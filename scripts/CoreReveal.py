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
from java.awt import Color

# CoreReveal
from corereveal.qiling_interface import QilingInterface

########## TEMPORARY TESTING - @TODO REMOVE ##########
from corereveal.mock_qiling_interface import MockQilingInterface
######################################################

# Hardcoded global variables
BACKGROUND_COLOR = Color.PINK

def annotate_bss(api, variables: dict):
    """ Add annotations to the current program detailing BSS values. """
    # @TODO!

def annotate_posix_calls(api, posix_calls: dict):
    """ Add annotations to the current program detailing POSIX call arguments. """
    # @TODO!

def color_function_graph(api, program, blocks: list):
    """ Highlight the blocks encountered and display the Function Graph. """
    # convert list of address strings to address objects
    start = program.getMinAddress()
    for string in blocks:
        if address := start.getAddress(string):
            # address found; set background
            setBackgroundColor(address, BACKGROUND_COLOR)
        else:
            popup(f"Skipping invalid address {string}!")

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
    # @TODO determine which program details (e.g. endianess) we need to / should send
    # interface = QilingInterface(program.getExecutablePath(), program.getLanguage().toString())

    ########## TEMPORARY TESTING - @TODO REMOVE ##########
    interface = MockQilingInterface(
        program.getExecutablePath(),
        program.getLanguage().toString(),
        program.getMinAddress().toString(),
        None
    )
    ######################################################

    # prompt for user input
    cli_args = askString(f"Executing {program.getExecutablePath()}", "Command Line Arguments")

    # perform emulation
    # @TODO update system monitor with progress bar
    print(f"Running emulation...")
    res = interface.emulate(
        cli_args,
        lambda prompt: askString("STDIN", prompt),
        lambda output: popup(output)
    )

    # handle failure conditions
    if not res:
       popup("Emulation failed!")
       sys.exit(2)
    print(f"Emulation succeeded; post-processing...")

    # format output and visualize
    annotate_bss(ghidra_api, res.static_variables)
    annotate_posix_calls(ghidra_api, res.posix_calls)
    color_function_graph(ghidra_api, program, res.block_addresses)

    print(f"Success!")
