# CoreReveal - Qiling based program flow emulation and visualization.
"""CoreReveal - Jython Ghidra script that executes and analyzes a Qiling emulation.

CoreReveal performs emulation via Qiling and analyzes the program flow.
The results are plotted to give a top level overview of the program
structure and general pathways.

The default python builtin methods are supplemented by JEP with wrappers around
core Ghidra Java functions (e.g. monitor, popup, currentProgram, etc.). To see
them all run `dir(builtins)`.

@category: Emulation
"""

# STL
import sys
import subprocess

# sanity check we're using Python3 (via Ghidrathon)
assert sys.version_info < (3,0), "Incorrect Python version; expected Jython (2.7)."
sys.path.append("/usr/local/lib/python3.8/dist-packages/corereveal/")

# CoreReveal
from corereveal_types import EmulationResults

# Ghidra
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from ghidra.app.util import CodeUnitInfo
from java.awt import Color

# Hardcoded global variables
BACKGROUND_COLOR = Color.PINK
OUTPUT = "/tmp/corereveal_results.pkl"

# mapping from Ghidra metadata to our architecture rootfs naming convention
GHIDRA_ARCH_MAP = {
    ("x86", "64"): "x8664",
    ("arm", "32"): "arm",
    ("arm", "64"): "arm64",
    ("mips", "32"): "mips",
    ("mips", "64"): "mips64",
    # !! Unverified !! #
    ("ppc", "64"): "ppc64",
}

def get_code_unit(program, addr, offset):
    """ Convenience function to return the code unit at a given address. """
    address = program.getMinAddress().getAddress(hex(int(addr, 16) + offset))
    if address:
        code_unit = program.getListing().getCodeUnitAt(address)
        if code_unit:
            return code_unit
    return None

def annotate_bss(program, variables, offset):
    """ Add annotations to the current program detailing BSS values. """
    # iterate through results
    for addr,values in variables.items():
        code_unit = get_code_unit(program, addr, offset)
        if code_unit:
            # location found - set comment
            code_unit.setComment(code_unit.POST_COMMENT,
                                 "CoreReveal: This symbol had values {}".format(values))

def annotate_posix_calls(program, posix_calls):
    """ Add annotations to the current program detailing POSIX call arguments. """
    # @TODO!

def color_function_graph(program, blocks, offset):
    """ Highlight the blocks encountered and display the Function Graph. """
    # iterate through traversed addresses
    for addr in blocks:
        code_unit = get_code_unit(program, addr, offset)
        if code_unit:
            code_unit.setComment(code_unit.PLATE_COMMENT, "CoreReveal: Execution path taken in last emulation.")

def communicate(process):
    """ Interact with the given subprocess until it closes. """
    # continually read newlines and prompt the user
    while process.poll() is not None:
        print("Before msg")
        msg = process.stdout.readline().rstrip()
        print("msg: " + msg)
        response = askString(msg)
        print("response: " + response)
        process.stdin.write(response)
        process.stdin.flush()

    # get any final communication
    stdout, stderr = process.communicate()
    print(stdout)
    print(stderr)
    return process.returncode

if __name__ == "__main__":
    # sanity check
    if not getState().getCurrentProgram():
        popup("No program selected; unable to emulate.")
        sys.exit(1)
    
    # construct basic ghidra program objects
    program = getState().getCurrentProgram()
    monitor = ConsoleTaskMonitor()

    # determine current program fullpath
    binary = program.getExecutablePath()

    # determine current program architecture configuration (processor and address size)
    arch_config = (program.getMetadata().get("Processor").lower(), program.getMetadata().get("Address Size"))
    assert arch_config in GHIDRA_ARCH_MAP, "Unsupported architecture configuration: {}".format(arch_config)
    architecture = GHIDRA_ARCH_MAP[arch_config]

    # determine the memory address used as the Ghidra starting point
    mem_offset = int(program.getMetadata().get("Minimum Address"), 16)

    # determine BSS section location and size
    bss_start = program.symbolTable.getGlobalSymbols("__bss_start")[0].getAddress()
    bss_memory = program.getMemory().getBlock(bss_start)
    assert bss_start == bss_memory.start, "Error in determination of BSS start!"

    # prompt for user input
    print("Emulating {} with Qiling...".format(binary))
    cli_args = askString("Executing {}".format(binary), "Command Line Arguments")

    # set up subprocess call arguments
    cmd = "corereveal {} --arch {} --bss-offset {} --bss-size {} --output {}".format(
        binary, architecture, bss_start.offset - mem_offset, bss_memory.size, OUTPUT)
    if len(cli_args.strip()) != 0:
        cmd += " --args {}".format(cli_args)

    print("Running command: \n  {}".format(cmd))
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

    # wait for completion and handle failure conditions
    retcode = communicate(proc)
    if retcode != 0:
       popup("Emulation failed!")
       sys.exit(retcode)

    # otherwise parse output
    print("Emulation succeeded; post-processing...")
    results = EmulationResults()
    results.from_file(OUTPUT)

    # format output and visualize
    annotate_bss(program, results.static_variables, mem_offset)
    annotate_posix_calls(program, results.posix_calls)
    color_function_graph(program, results.block_addresses, mem_offset)
    print("Success!")
