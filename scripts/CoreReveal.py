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

# CoreReveal
from corereveal.qiling_interface import QilingInterface

def annotate_bss(api, variables: dict):
    """ Add annotations to the current program detailing BSS values. """
    # @TODO!

def annotate_posix_calls(api, posix_calls: dict):
    """ Add annotations to the current program detailing POSIX call arguments. """
    # @TODO!

def color_function_graph(api, blocks: list):
    """ Highlight the blocks encountered and display the Function Graph. """
    # @TODO!

if __name__ == "__main__":
    # sanity check
    if not getState().getCurrentProgram():
        popup("No program selected; unable to emulate.")
        sys.exit(1)
    
    # construct basic ghidra program objects
    program = getState().getCurrentProgram()
    ghidra_api = FlatProgramAPI(program)

    # construct core interface class
    # @TODO determine which program details (e.g. endianess) we need to / should send
    interface = QilingInterface(program.getExecutablePath(), program.getLanguage().toString())

    # prompt for user input
    cli_args = askString(f"Executing {program.toString()}", "Command Line Arguments")

    # perform emulation
    # @TODO update system monitor with progress bar
    res = interface.emulate(
        cli_args,
        lambda prompt: askString("STDIN", prompt),
        lambda output: popup(output)
    )

    # handle failure conditions
    if not res:
       popup("Emulation failed!")
       sys.exit(2)

    # format output and visualize
    annotate_bss(ghidra_api, res.static_variables)
    annotate_posix_calls(ghidra_api, res.posix_calls)
    color_function_graph(ghidra_api, res.blocks)