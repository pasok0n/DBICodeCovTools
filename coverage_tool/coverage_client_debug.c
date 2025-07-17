/* client.c – TLS-based edge coverage tracer with AFL bitmap */

#include <stdatomic.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"

#define MAP_SIZE        65536             /* Total edge space and bitmap size in bytes */
#define FIFO_PATH       "/tmp/dr_cov_cmd"

/* State machine states */
typedef enum {
    STATE_WAITING_FOR_FUZZ,
    STATE_COLLECTING,
    STATE_DUMPING,
    STATE_EXITING
} tool_state_t;

static char        target_module[256]  = "";
static char        target_function[256]= "";
static uintptr_t   target_offset       = 0;

/* Global state variables */
static _Atomic tool_state_t current_state = STATE_WAITING_FOR_FUZZ;
static _Atomic uint32_t reset_generation = 0;  /* Incremented when reset is needed */
static void *fuzz_ready_event = NULL;          /* Signaled when STATE_COLLECTING */
static void *dump_complete_event = NULL;       /* Signaled when dump is complete */

typedef struct {
    uint8_t bitmap[MAP_SIZE];
} coverage_map_t;

typedef struct {
    uint32_t prev_offset;
    uint32_t reset_generation;  /* Last reset generation this thread saw */
} per_thread_data_t;

/* Global coverage bitmap */
static coverage_map_t cov;
/* TLS slot for per-thread prev_offset */
static int            tls_idx = -1;

/* Forward declarations */
static dr_emit_flags_t event_bb_instrumentation(void *drcontext,
                                                void *tag,
                                                instrlist_t *bb,
                                                instr_t *instr,
                                                bool for_trace,
                                                bool translating,
                                                void *user_data);
static void event_module_load(void *drcontext,
                              const module_data_t *info,
                              bool loaded);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static void cmd_listener(void *arg);
static void record_edge(app_pc pc);
static void clear_coverage_map(void);
static void reset_all_threads(void);
static void pre_fuzz_handler(void *wrapcxt, void **user_data);
static void post_fuzz_handler(void *wrapcxt, void *user_data);
static void make_output_filename(char *buf, size_t len);
static void dump_coverage(const coverage_map_t *map, const char *path);
static void event_exit(void);
static void wait_for_state(tool_state_t target_state);

/* Calculate edge ID using AFL's method */
static inline uint32_t
calculate_edge_id(uint32_t prev_offset, app_pc curr_pc)
{
    uint32_t curr_offset = (uint32_t)((uintptr_t)curr_pc) & (MAP_SIZE - 1);
    uint32_t edge_id = prev_offset ^ curr_offset;
    return edge_id & (MAP_SIZE - 1);
}

/* AFL-style bitmap edge marking with counter increment */
static inline void
mark_edge_afl(coverage_map_t *map, uint32_t edge_id)
{
    /* Atomically increment the counter */
    _Atomic uint8_t *byte_ptr = (_Atomic uint8_t *)&map->bitmap[edge_id];
    atomic_fetch_add(byte_ptr, 1);
}

/* Check if thread needs to reset its prev_offset */
static inline void
check_and_reset_if_needed(per_thread_data_t *t)
{
    uint32_t current_gen = atomic_load(&reset_generation);
    if (t->reset_generation != current_gen) {
        t->prev_offset = 0;
        t->reset_generation = current_gen;
    }
}

/* Basic-block instrumentation: invoke record_edge(bb_pc) */
static dr_emit_flags_t
event_bb_instrumentation(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                         bool for_trace, bool translating, void *user_data)
{
    if (!drmgr_is_first_instr(drcontext, instr))
        return DR_EMIT_DEFAULT;

    dr_insert_clean_call(drcontext, bb, instr, record_edge, false, 1, OPND_CREATE_INTPTR((app_pc)tag));
    return DR_EMIT_DEFAULT;
}

/* Called for each instrumented block when collecting */
void
record_edge(app_pc pc)
{
    tool_state_t state = atomic_load(&current_state);
    if (state != STATE_COLLECTING)
        return;

    void *ctx = dr_get_current_drcontext();
    per_thread_data_t *t = drmgr_get_tls_field(ctx, tls_idx);
    
    /* Check if we need to reset due to state change */
    check_and_reset_if_needed(t);
    
    uint32_t prev_offset = t->prev_offset;
    uint32_t curr_offset = (uint32_t)((uintptr_t)pc) & (MAP_SIZE - 1);
    
    /* Calculate edge ID and mark in bitmap */
    uint32_t edge_id = calculate_edge_id(prev_offset, pc);
    mark_edge_afl(&cov, edge_id);
    
    /* Store new offset for next edge calculation (shifted right by 1) */
    t->prev_offset = (curr_offset >> 1) & (MAP_SIZE - 1);
}

/* Zero the global coverage bitmap */
static void
clear_coverage_map(void)
{
    memset(cov.bitmap, 0, sizeof(cov.bitmap));
}

/* Reset all threads' prev_offset by incrementing reset generation */
static void
reset_all_threads(void)
{
    atomic_fetch_add(&reset_generation, 1);
}

/* Wait for a specific state */
static void
wait_for_state(tool_state_t target_state)
{
    while (atomic_load(&current_state) != target_state) {
        if (target_state == STATE_COLLECTING) {
            dr_event_wait(fuzz_ready_event);
        } else {
            /* For other states, we can add more events as needed */
            dr_thread_yield();
        }
    }
}

/* Allocate per-thread prev_offset = 0 */
static void
event_thread_init(void *drcontext)
{
    per_thread_data_t *t = dr_thread_alloc(drcontext, sizeof(*t));
    t->prev_offset = 0;
    t->reset_generation = atomic_load(&reset_generation);
    drmgr_set_tls_field(drcontext, tls_idx, t);
}

/* Free per-thread storage */
static void
event_thread_exit(void *drcontext)
{
    per_thread_data_t *t = drmgr_get_tls_field(drcontext, tls_idx);
    dr_thread_free(drcontext, t, sizeof(*t));
}

/* Generate a unique filename in /tmp */
static void
make_output_filename(char *buf, size_t len)
{
    static _Atomic uint32_t seq = 0;
    uint32_t id = atomic_fetch_add(&seq, 1u);
    snprintf(buf, len, "/tmp/dr_afl_bitmap_%u.bin", id);
}

/* Dedicated FIFO reader thread - centralized command processing */
static void
cmd_listener(void *arg)
{
    (void)arg;
    if (mkfifo(FIFO_PATH, 0666) < 0 && errno != EEXIST)
        return;
    
    int fd = open(FIFO_PATH, O_RDONLY);
    if (fd < 0)
        return;

    for (;;) {
        unsigned char cmd;
        if (read(fd, &cmd, 1) <= 0) {
            close(fd);
            fd = open(FIFO_PATH, O_RDONLY);
            if (fd < 0)
                break;
            continue;
        }
        
        switch (cmd) {
        case 'F':
            /* Start fuzzing */
            reset_all_threads();
            atomic_store(&current_state, STATE_COLLECTING);
            dr_event_signal(fuzz_ready_event);
            break;
            
        case 'D':
            /* Dump coverage */
            atomic_store(&current_state, STATE_DUMPING);
            char path[64];
            make_output_filename(path, sizeof(path));
            dump_coverage(&cov, path);
            /* Clear coverage map and reset state for next iteration */
            clear_coverage_map();
            reset_all_threads();
            atomic_store(&current_state, STATE_WAITING_FOR_FUZZ);
            dr_event_signal(dump_complete_event);
            break;
            
        case 'Q':
            /* Quit */
            atomic_store(&current_state, STATE_EXITING);
            dr_event_signal(fuzz_ready_event);
            dr_event_signal(dump_complete_event);
            close(fd);
            dr_exit_process(0);
            break;
            
        default:
            /* Ignore unknown commands */
            break;
        }
    }
    close(fd);
}

/* Pre-handler before target: signal 'P', wait for STATE_COLLECTING */
static void
pre_fuzz_handler(void *wrapcxt, void **user_data)
{
    (void)user_data;
    
    dr_fprintf(STDERR, "DEBUG: pre_fuzz_handler called\n");
    
    /* Signal that we're ready */
    int fd = open(FIFO_PATH, O_WRONLY | O_NONBLOCK);
    if (fd >= 0) {
        char c = 'P';
        ssize_t written = write(fd, &c, 1);
        close(fd);
        dr_fprintf(STDERR, "DEBUG: Sent 'P' signal, written=%d\n", (int)written);
    } else {
        dr_fprintf(STDERR, "DEBUG: Failed to open FIFO for 'P' signal, errno=%d\n", errno);
    }
    
    clear_coverage_map();
    dr_fprintf(STDERR, "DEBUG: Waiting for STATE_COLLECTING\n");
    wait_for_state(STATE_COLLECTING);
    dr_fprintf(STDERR, "DEBUG: STATE_COLLECTING received, proceeding\n");
    
    void *ctx = drwrap_get_drcontext(wrapcxt);
    per_thread_data_t *t = drmgr_get_tls_field(ctx, tls_idx);
    check_and_reset_if_needed(t);
}

static void
post_fuzz_handler(void *wrapcxt, void *user_data)
{
    (void)wrapcxt;
    (void)user_data;
    
    dr_fprintf(STDERR, "DEBUG: post_fuzz_handler called\n");
}

/* Wrap the user's target function when its module loads */
static void
event_module_load(void *drcontext,
                  const module_data_t *info,
                  bool loaded)
{
    (void)loaded;
    
    const char *name = dr_module_preferred_name(info);
    dr_fprintf(STDERR, "DEBUG: Module loaded: %s\n", name);
    
    if (!target_module[0]) {
        dr_fprintf(STDERR, "DEBUG: No target_module specified\n");
        return;
    }
    
    dr_fprintf(STDERR, "DEBUG: Looking for target module: %s\n", target_module);
    
    if (strcmp(name, target_module) != 0) {
        dr_fprintf(STDERR, "DEBUG: Module %s doesn't match target %s\n", name, target_module);
        return;
    }
    
    dr_fprintf(STDERR, "DEBUG: Found target module: %s\n", name);
    
    app_pc to_wrap = NULL;
    if (target_offset) {
        to_wrap = info->start + target_offset;
        dr_fprintf(STDERR, "DEBUG: Using offset 0x%lx, wrap address: %p\n", 
                   target_offset, to_wrap);
    } else if (target_function[0]) {
        to_wrap = (app_pc)dr_get_proc_address(info->handle, target_function);
        dr_fprintf(STDERR, "DEBUG: Looking for function %s, found: %p\n", 
                   target_function, to_wrap);
    } else {
        dr_fprintf(STDERR, "DEBUG: No target_function or target_offset specified\n");
    }

    if (to_wrap) {
        bool success = drwrap_wrap(to_wrap, pre_fuzz_handler, post_fuzz_handler);
        dr_fprintf(STDERR, "DEBUG: Wrapping %p: %s\n", to_wrap, 
                   success ? "SUCCESS" : "FAILED");
    } else {
        dr_fprintf(STDERR, "DEBUG: No address to wrap\n");
    }
}

/* Write the bitmap to disk */
static void
dump_coverage(const coverage_map_t *map, const char *path)
{
    file_t fd = dr_open_file(path, DR_FILE_WRITE_OVERWRITE);
    if (fd == INVALID_FILE)
        return;
    dr_write_file(fd, map->bitmap, sizeof(map->bitmap));
    dr_close_file(fd);
}

/* Cleanup on exit */
static void
event_exit(void)
{
    if (fuzz_ready_event)
        dr_event_destroy(fuzz_ready_event);
    if (dump_complete_event)
        dr_event_destroy(dump_complete_event);
    drwrap_exit();
    drmgr_exit();
}

/* Entry point */
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    (void)id;
    
    dr_fprintf(STDERR, "DEBUG: Client starting with %d args\n", argc);
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-target_module") && i+1 < argc) {
            strncpy(target_module, argv[++i], sizeof(target_module)-1);
            dr_fprintf(STDERR, "DEBUG: Set target_module to: %s\n", target_module);
        } else if (!strcmp(argv[i], "-target_function") && i+1 < argc) {
            strncpy(target_function, argv[++i], sizeof(target_function)-1);
            dr_fprintf(STDERR, "DEBUG: Set target_function to: %s\n", target_function);
        } else if (!strcmp(argv[i], "-target_offset") && i+1 < argc) {
            target_offset = strtoul(argv[++i], NULL, 0);
            dr_fprintf(STDERR, "DEBUG: Set target_offset to: 0x%lx\n", target_offset);
        }
    }

    dr_set_client_name("afl_bitmap_cov", "https://dynamorio.org");
    drmgr_init();
    drwrap_init();

    /* Initialize synchronization primitives */
    fuzz_ready_event = dr_event_create();
    dump_complete_event = dr_event_create();

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx >= 0);

    drmgr_register_bb_instrumentation_event(NULL, event_bb_instrumentation, NULL);
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    dr_register_exit_event(event_exit);

    dr_create_client_thread(cmd_listener, NULL);
}