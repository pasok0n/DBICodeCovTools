#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <map>
#include <vector>
#include "pin.H"

// ============================================================================
// Global Data
// ============================================================================

struct InstructionInfo {
    std::string funcOffset;
    std::string disassembly;
};

static std::map<ADDRINT, InstructionInfo> instructionInfoMap;
static std::map<ADDRINT, std::vector<ADDRINT>> bblInstructions;
static std::set<ADDRINT> coverageAddresses;
static std::set<ADDRINT> coveredBasicBlocks; // Track unique basic blocks covered

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "coverage_with_asm.out", "Coverage output file name");

static PIN_LOCK pinLock;

// ============================================================================
// Utility Routines
// ============================================================================

// This function will be called when the application starts executing
VOID ApplicationStart(VOID *v)
{
    std::cout << "PIN: Target application is instrumented and now running." << std::endl;
}

// ============================================================================
// Analysis Routines
// ============================================================================

VOID RecordBlockCoverage(ADDRINT bblAddr)
{
    PIN_GetLock(&pinLock, 1);
    PIN_LockClient();

    coveredBasicBlocks.insert(bblAddr); // Record that this basic block was executed

    auto it = bblInstructions.find(bblAddr);
    if (it != bblInstructions.end()) {
        for (ADDRINT insAddr : it->second) {
            coverageAddresses.insert(insAddr);
        }
    }

    PIN_UnlockClient();
    PIN_ReleaseLock(&pinLock);
}

// ============================================================================
// Instrumentation Callbacks
// ============================================================================

VOID TraceCallback(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT bblAddr = BBL_Address(bbl);
        std::vector<ADDRINT> insAddrs;

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            ADDRINT insAddr = INS_Address(ins);
            insAddrs.push_back(insAddr);

            RTN rtn = RTN_FindByAddress(insAddr);
            std::string funcOffset;

            if (RTN_Valid(rtn)) {
                ADDRINT offset = insAddr - RTN_Address(rtn);
                std::ostringstream oss;
                oss << RTN_Name(rtn) << "+0x" << std::hex << offset;
                funcOffset = oss.str();
            } else {
                std::ostringstream oss;
                oss << "UNKNOWN_0x" << std::hex << insAddr;
                funcOffset = oss.str();
            }

            instructionInfoMap[insAddr] = {
                funcOffset,
                INS_Disassemble(ins)
            };
        }

        bblInstructions[bblAddr] = insAddrs;

        BBL_InsertCall(bbl, IPOINT_ANYWHERE,
                      (AFUNPTR)RecordBlockCoverage,
                      IARG_ADDRINT, bblAddr,
                      IARG_END);
    }
}

// ============================================================================
// Finalization
// ============================================================================

VOID FiniCallback(INT32 code, VOID *v)
{
    std::ofstream outFile(KnobOutputFile.Value().c_str());
    if (!outFile.is_open()) {
        std::cerr << "Error: Could not open output file.\n";
        return;
    }

    for (ADDRINT insAddr : coverageAddresses) {
        auto it = instructionInfoMap.find(insAddr);
        if (it != instructionInfoMap.end()) {
            outFile << it->second.funcOffset << " : "
                    << it->second.disassembly << "\n";
        } else {
            outFile << "UNKNOWN_0x" << std::hex << insAddr
                    << " : [Disassembly not found]\n";
        }
    }

    outFile << "\nTotal covered instructions: " << coverageAddresses.size() << "\n";
    outFile << "Total covered basic blocks: " << coveredBasicBlocks.size() << "\n";
    outFile.close();
    std::cout << "PIN: Coverage data written to " << KnobOutputFile.Value() << std::endl;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        std::cerr << "PIN_Init failed.\n";
        return 1;
    }

    PIN_InitLock(&pinLock);

    // Register the function to be called when the application starts
    PIN_AddApplicationStartFunction(ApplicationStart, 0);
    
    TRACE_AddInstrumentFunction(TraceCallback, 0);
    PIN_AddFiniFunction(FiniCallback, 0);

    std::cout << "PIN: Starting instrumentation..." << std::endl;
    PIN_StartProgram();

    return 0;
}
