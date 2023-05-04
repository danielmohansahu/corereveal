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
OUTPUT = "/tmp/results.pickel"

def annotate_bss(program, variables):
    """ Add annotations to the current program detailing BSS values. """
    # @TODO!

def annotate_posix_calls(program, posix_calls):
    """ Add annotations to the current program detailing POSIX call arguments. """
    # @TODO!

def color_function_graph(program, blocks, offset):
    """ Highlight the blocks encountered and display the Function Graph. """
    # get program listing for commenting
    listing = program.getListing()

    # convert list of address strings to address objects
    start = program.getMinAddress()
    for hex_str in blocks:
        # offset string by ghidra's "entry point"
        address = start.getAddress(hex(int(hex_str, 16) + offset))
        if address:
            # address found; set background
            setBackgroundColor(address, BACKGROUND_COLOR)
            # add a comment too, if this is a valid CodeUnit
            code_unit = listing.getCodeUnitAt(address)
            if code_unit:
                code_unit.setComment(code_unit.PLATE_COMMENT, "Background color set by CoreReveal")
            print("Colored {}".format(hex_str))
        else:
            popup("Skipping invalid address {}!".format(hex_str))

if __name__ == "__main__":
    # sanity check
    if not getState().getCurrentProgram():
        popup("No program selected; unable to emulate.")
        sys.exit(1)
    
    # construct basic ghidra program objects
    program = getState().getCurrentProgram()
    monitor = ConsoleTaskMonitor()

    # extract current program metadata
    binary = program.getExecutablePath()
    mem_offset = int(program.getMetadata().get("Minimum Address"), 16)

    # prompt for user input
    print("Emulating {} with Qiling...".format(binary))
    cli_args = askString("Executing {}".format(binary), "Command Line Arguments")

    # set up subprocess call arguments
    cmd = "corereveal {} --args {} --arch {} --bss-size {} --bss-offset {} --output {}".format(binary, cli_args, "UNKNOWN", 0, 0, OUTPUT)
    print("Running command: \n  {}".format(cmd))
    code = subprocess.call(cmd, shell=True)

    # handle failure conditions
    if code != 0:
       popup("Emulation failed!")
       sys.exit(code)

    # otherwise parse output
    print("Emulation succeeded; post-processing...")
    results = EmulationResults()
    results.from_file(OUTPUT)

    # format output and visualize
    annotate_bss(program, res.static_variables)
    annotate_posix_calls(program, res.posix_calls)
    color_function_graph(program, res.block_addresses, mem_offset)
    print("Success!")
