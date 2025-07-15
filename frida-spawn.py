#!/usr/bin/env python

# This file, frida-spawn.py, is a modified version of yrp's frida-drcov.py.
# Original source: https://github.com/gaasedelen/lighthouse/tree/master/coverage/frida

from __future__ import print_function

import argparse
import json
import os
import signal
import sys
import time

import frida

"""
Frida BB tracer that outputs in DRcov format.

Frida script is responsible for:
- Getting and sending the process module map initially
- Getting the code execution events
- Converting from GumCompileEvent to DRcov block
- Sending a list of DRcov blocks to python

Python side is responsible for:
- Spawning and attaching to the target process
- Removing duplicate DRcov blocks
- Formatting module map and blocks
- Writing the output file
"""

# Our frida script, takes two string arguments to embed:
# 1. whitelist of modules, in the form "['module_a', 'module_b']" or "['all']"
# 2. threads to trace, in the form "[345, 765]" or "['all']"
js = """
"use strict";

var whitelist = %s;
var threadlist = %s;
var stalkedThreadIds = [];

function make_maps() {
    var raw_modules = Process.enumerateModulesSync();
    var new_module_list = [];
    for (var i = 0; i < raw_modules.length; i++) {
        var mod = raw_modules[i];
        new_module_list.push({
            name: mod.name,
            base: mod.base,
            size: mod.size,
            path: mod.path,
            id: i,
            end: mod.base.add(mod.size)
        });
    }
    return new_module_list;
}

var maps = make_maps();
send({'map': maps});

var module_ids = {};
maps.forEach(function (e) {
    module_ids[e.path] = {id: e.id, start: e.base};
});

var filtered_maps = new ModuleMap(function (m) {
    if (whitelist.indexOf('all') >= 0) { return true; }
    return whitelist.some(item => m.name.toLowerCase().includes(item.toLowerCase()));
});

function drcov_bbs(bbs_input, fmaps, path_ids) {
    var entry_sz = 8;
    var bb_out_buffer = new ArrayBuffer(entry_sz * bbs_input.length);
    var num_entries = 0;
    for (var i = 0; i < bbs_input.length; ++i) {
        var e = bbs_input[i];
        var start = e[0];
        var end   = e[1];
        var path = fmaps.findPath(start);
        if (path == null) continue;
        var mod_info = path_ids[path];
        if (mod_info === undefined) continue;
        var offset = start.sub(mod_info.start).toInt32();
        var size = end.sub(start).toInt32();
        var mod_id = mod_info.id;
        var x =  new Uint32Array(bb_out_buffer, num_entries * entry_sz, 1);
        x[0] = offset;
        var y = new Uint16Array(bb_out_buffer, num_entries * entry_sz + 4, 2);
        y[0] = size;
        y[1] = mod_id;
        ++num_entries;
    }
    return new Uint8Array(bb_out_buffer, 0, num_entries * entry_sz);
}

Stalker.trustThreshold = 0;

setImmediate(function() {
    Process.enumerateThreads({
        onMatch: function (thread) {
            if (threadlist.indexOf('all') < 0 && threadlist.indexOf(thread.id) < 0 && threadlist.length > 0) {
                return;
            }
            try {
                Stalker.follow(thread.id, {
                    events: { compile: true },
                    onReceive: function (event_data) {
                        if (!event_data || event_data.byteLength === 0) return;
                        var parsed_bbs;
                        try {
                            parsed_bbs = Stalker.parse(event_data, {stringify: false, annotate: false});
                        } catch (parseError) {
                            return;
                        }
                        if (parsed_bbs.length > 0) {
                            var drcov_data = drcov_bbs(parsed_bbs, filtered_maps, module_ids);
                            if (drcov_data.byteLength > 0) {
                                send({bbs: 1}, drcov_data);
                            }
                        }
                    }
                });
                if (stalkedThreadIds.indexOf(thread.id) === -1) {
                    stalkedThreadIds.push(thread.id);
                }
            } catch (e) {
                console.error('[JS] Error during Stalker.follow for thread ' + thread.id + ': ' + e.message);
            }
        },
        onComplete: function () {}
    });
});

recv('stop_stalking', function onStopStalking(value) {
    console.log('[JS] Received stop_stalking message from Python.');
    var status_message = "";
    try {
        console.log('[JS] Attempting Stalker.flush()...');
        Stalker.flush();
        console.log('[JS] Stalker.flush() completed.');
        status_message += "Flush OK. ";
    } catch (e) {
        console.warn('[JS] Error during Stalker.flush(): ' + e.message);
        status_message += "Flush Error: " + e.message + ". ";
    }

    var successfully_unfollowed = 0;
    var threads_to_unfollow_count = stalkedThreadIds.length;
    var unfollow_errors = "";

    var currentStalkedIds = stalkedThreadIds.slice();
    stalkedThreadIds = [];

    currentStalkedIds.forEach(function(tid) {
        try {
            Stalker.unfollow(tid);
            successfully_unfollowed++;
        } catch (e) {
            unfollow_errors += "TID " + tid + ": " + e.message + "; ";
        }
    });

    if (threads_to_unfollow_count > 0) {
        status_message += "Unfollowed " + successfully_unfollowed + "/" + threads_to_unfollow_count + ". ";
        if (unfollow_errors) {
            status_message += "Unfollow errors: " + unfollow_errors;
        }
    } else {
        status_message += "No threads in list to unfollow. ";
    }
    console.log('[JS] Stalking cleanup attempt finished. ' + status_message);
    send({type: 'stalking_stopped_ack', status: status_message});
});
"""

# Global variables
modules = []
bbs = set([])
outfile = "frida-spawn.log"
stalking_stopped_ack_received = False
session = None
script = None
device = None
pid_to_resume = -1

def populate_modules(image_list):
    global modules
    modules = []

    for image in image_list:
        try:
            idx = image['id']
            path = image['path']
            base = int(image['base'], 0)
            end = int(image['end'], 0)
            size = image['size']

            m = {
                'id': idx,
                'path': path,
                'base': base,
                'end': end,
                'size': size
            }
            modules.append(m)
        except KeyError as e:
            print(f"[Python Error] KeyError in populate_modules for image: {image}. Missing key: {e}")
            continue
        except Exception as e:
            print(f"[Python Error] Other error in populate_modules for image: {image}. Error: {e}")
            continue

    print(f'[+] Got module info. Count: {len(modules)}')

def populate_bbs(data):
    global bbs
    block_sz = 8
    for i in range(0, len(data), block_sz):
        bbs.add(data[i : i + block_sz])

def create_header(mods):
    header = ""
    header += "DRCOV VERSION: 2\n"
    header += "DRCOV FLAVOR: frida\n"
    header += "Module Table: version 2, count %d\n" % len(mods)
    header += "Columns: id, base, end, entry, checksum, timestamp, path\n"

    entries = []

    for m in mods:
        entry = "%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s" % (
            m["id"],
            m["base"],
            m["end"],
            0,
            0,
            0,
            m["path"],
        )
        entries.append(entry)

    header_modules = "\n".join(entries)
    return ("%s%s\n" % (header, header_modules)).encode("utf-8")

def create_coverage(data):
    bb_header = b"BB Table: %d bbs\n" % len(data)
    return bb_header + b"".join(data)

def on_message(msg, data):
    global modules, bbs, stalking_stopped_ack_received
    
    if msg.get("type") == "error":
        print(f"[Frida JS Error] Desc: {msg.get('description')}")
        print(f"[Frida JS Error] Stack: {msg.get('stack')}")
        if msg.get('fileName'): 
            print(f"[Frida JS Error] File: {msg.get('fileName')}:{msg.get('lineNumber')}")
        return

    payload = msg.get("payload", {})
    if "map" in payload:
        populate_modules(payload["map"])
    elif "bbs" in payload:
        if data:
            populate_bbs(data)
    elif payload.get('type') == 'stalking_stopped_ack':
        print("[Python on_message] Received 'stalking_stopped_ack' from Frida script.")
        print(f"    JS Status: {payload.get('status', 'No status message')}")
        stalking_stopped_ack_received = True

def perform_graceful_shutdown(signal_name="Signal"):
    global session, script, bbs, outfile, stalking_stopped_ack_received
    global device, pid_to_resume

    print(f"\n[{signal_name}] Received. Initiating graceful shutdown sequence.")
    stalking_stopped_ack_received = False

    if script:
        print(f"[{signal_name}] Script object exists. Attempting to stop stalking in JS.")
        try:
            script.post({'type': 'stop_stalking'})
            print(f"[{signal_name}] Waiting for 'stalking_stopped_ack' from JS (max 3 seconds)...")
            wait_start_time = time.time()
            while not stalking_stopped_ack_received and (time.time() - wait_start_time) < 3.0:
                time.sleep(0.1)
            if stalking_stopped_ack_received:
                print(f"[{signal_name}] 'stalking_stopped_ack' received.")
            else:
                print(f"[{signal_name}] Timed out/failed to receive 'stalking_stopped_ack'.")
        except Exception as e:
            print(f"[{signal_name}] Error during JS stop stalking: {e}")
    else:
        print(f"[{signal_name}] Script object None. Cannot send 'stop_stalking'.")

    print(f"[{signal_name}] Saving {len(bbs)} basic blocks to '{outfile}'.")
    save_coverage()

    if script:
        print(f"[{signal_name}] Attempting to unload script.")
        try:
            script.unload()
            print(f"[{signal_name}] Script unloaded.")
        except Exception as e:
            print(f"[{signal_name}] Error unloading script: {e}")

    if session and not session.is_detached:
        print(f"[{signal_name}] Attempting to detach session.")
        try:
            session.detach()
            print(f"[{signal_name}] Session detached.")
        except Exception as e:
            print(f"[{signal_name}] Error detaching session: {e}")

    if device and pid_to_resume != -1:
        print(f"[{signal_name}] Attempting to kill target process PID: {pid_to_resume}.")
        try:
            device.kill(pid_to_resume)
            print(f"[{signal_name}] Kill signal sent to target PID: {pid_to_resume}.")
            time.sleep(0.1)
        except Exception as e:
            print(f"[{signal_name}] Error killing target process: {e}")

    print(f"[{signal_name}] Graceful shutdown sequence complete. Exiting.")
    sys.exit(0)

def sigint_handler(signo, frame):
    print("[SIGINT specific message] Ctrl+C pressed!")
    perform_graceful_shutdown("SIGINT")

def sigterm_handler(signo, frame):
    print("[SIGTERM specific message] SIGTERM received!")
    perform_graceful_shutdown("SIGTERM")

def save_coverage():
    global modules, bbs, outfile
    header = create_header(modules)
    body = create_coverage(bbs)
    try:
        with open(outfile, "wb") as h:
            h.write(header)
            h.write(body)
    except Exception as e:
        print(f"[save_coverage] Error writing to {outfile}: {e}")

def main():
    global outfile, session, script, bbs
    global device, pid_to_resume

    parser = argparse.ArgumentParser(
        description="Frida-based basic block tracer outputting in DRcov format."
    )
    parser.add_argument("program", help="path to the program to launch")
    parser.add_argument(
        "program_args",
        nargs=argparse.REMAINDER,
        help="arguments for the program (optional)",
    )
    parser.add_argument(
        "-o",
        "--outfile",
        help="coverage file",
        default="frida-cov.log",
    )
    parser.add_argument(
        "-w",
        "--whitelist-modules",
        help="module to trace (name contains), may be specified multiple times [all]",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-t",
        "--thread-id",
        help="threads to trace, may be specified multiple times [all]",
        action="append",
        type=int,
        default=[],
    )
    parser.add_argument(
        "-D",
        "--device",
        help="select a device by id [local]",
        default="local",
    )

    args = parser.parse_args()
    outfile = args.outfile

    try:
        device = frida.get_device(args.device)
    except frida.InvalidArgumentError:
        print(f"[-] Error: Device '{args.device}' not found. Check device ID.")
        sys.exit(1)
    except frida.ServerNotRunningError:
        print(f"[-] Error: Frida server not running on device '{args.device}'.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error getting device '{args.device}': {e}")
        sys.exit(1)

    program_path = args.program
    program_argv = [program_path] + args.program_args

    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigterm_handler)

    whitelist_modules = ["all"]
    if len(args.whitelist_modules):
        whitelist_modules = args.whitelist_modules

    threadlist = ["all"]
    if len(args.thread_id):
        threadlist = args.thread_id

    json_whitelist_modules = json.dumps(whitelist_modules)
    json_threadlist = json.dumps(threadlist)

    pid_to_resume = -1

    try:
        print(f"[*] Spawning '{' '.join(program_argv)}' on device '{device.id}'...")
        pid_to_resume = device.spawn(program_argv)
        print(f"[+] Spawned process with PID: {pid_to_resume}")

        print(f"[*] Attaching to PID {pid_to_resume}...")
        session = device.attach(pid_to_resume)
        print("[+] Attached.")

        print("[*] Loading script...")
        script = session.create_script(
            js % (json_whitelist_modules, json_threadlist)
        )
        script.on("message", on_message)
        script.load()
        print("[+] Script loaded.")

        print(f"[*] Resuming PID {pid_to_resume}...")
        device.resume(pid_to_resume)
        print("[+] Process resumed.")

        print("[*] Now collecting info, press Control-C to terminate....")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Main] KeyboardInterrupt caught. SIGINT handler should take over.")
    except frida.ProcessNotFoundError as e:
        print(f"[-] Error: Process not found (PID: {pid_to_resume}): {e}")
        if session and not session.is_detached:
            session.detach()
        sys.exit(1)
    except frida.TransportError as e:
        print(f"[-] Frida transport error: {e}")
        if script:
            script.unload()
        if session and not session.is_detached:
            session.detach()
        sys.exit(1)
    except Exception as e:
        print(f"[Main] An unexpected error occurred: {e}")
        if script:
            try:
                script.unload()
            except:
                pass
        if session and not session.is_detached:
            try:
                session.detach()
            except:
                pass
        sys.exit(1)
    finally:
        print("[Main finally] Main block is exiting.")

if __name__ == "__main__":
    main()
