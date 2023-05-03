# CoreReveal - Qiling based program flow emulation and visualization.
"""CoreReveal - Ghidrathon based Ghidra script that executes and analyzes a Qiling emulation.

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

# sanity check we're using Python3 (via Ghidrathon)
assert sys.version_info > (3,0), "Incorrect Python version; do you have Ghidrathon installed?"

# Ghidra
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from ghidra.app.util import CodeUnitInfo
from java.awt import Color

# CoreReveal
from corereveal.qiling_interface import QilingInterface

# Hardcoded global variables
BACKGROUND_COLOR = Color.PINK

def annotate_bss(api, program, variables: dict):
    """ Add annotations to the current program detailing BSS values. """
    # @TODO!

def annotate_posix_calls(api, program, posix_calls: dict):
    """ Add annotations to the current program detailing POSIX call arguments. """
    # @TODO!

def color_function_graph(api, program, blocks: set):
    """ Highlight the blocks encountered and display the Function Graph. """
    # get program listing for commenting
    listing = program.getListing()

    # convert list of address strings to address objects
    start = program.getMinAddress()
    for hex_str in blocks:
        if address := start.getAddress(hex_str):
            # address found; set background
            setBackgroundColor(address, BACKGROUND_COLOR)
            # add a comment too, if this is a valid CodeUnit
            if code_unit := listing.getCodeUnitAt(address):
                code_unit.setComment(code_unit.PLATE_COMMENT, f"Background color set by CoreReveal")
            print(f"Colored {hex_str}")
        else:
            popup(f"Skipping invalid address {hex_str}!")

if __name__ == "__main__":
    # sanity check
    if not getState().getCurrentProgram():
        popup("No program selected; unable to emulate.")
        sys.exit(1)
    
    # construct basic ghidra program objects
    program = getState().getCurrentProgram()
    ghidra_api = FlatProgramAPI(program)
    monitor = ConsoleTaskMonitor()
    print(f"Emulating {program.getExecutablePath()} with Qiling...")

    # construct core interface class
    interface = QilingInterface(
        program.getExecutablePath(),
        0,
        0,
        int(program.getMetadata().get("Minimum Address"), 16),
        lambda prompt: askString("STDIN", prompt),
        lambda output: popup(output)
    )

    # set root filesystem (provided by Qiling)
    interface.set_default_rootfs(
        program.getMetadata().get("Processor"),
        program.getMetadata().get("Address Size")
    )

    # prompt for user input
    cli_args = askString(f"Executing {program.getExecutablePath()}", "Command Line Arguments")

    # perform emulation
    # @TODO update system monitor with progress bar
    print(f"Running emulation...")
    res = interface.emulate(cli_args)

    # handle failure conditions
    if not res:
       popup("Emulation failed!")
       sys.exit(2)
    print(f"Emulation succeeded; post-processing...")

    # format output and visualize
    annotate_bss(ghidra_api, program, res.static_variables)
    annotate_posix_calls(ghidra_api, program, res.posix_calls)
    color_function_graph(ghidra_api, program, res.block_addresses)

    print(f"Success!")
