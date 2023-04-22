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

# CoreReveal
from corereveal.qiling_interface import QilingInterface

# sanity check we're using Python3 (via Ghidrathon)
assert sys.version_info > (3,0), "Incorrect Python version; do you have Ghidrathon installed?"

if __name__ == "__main__":
    popup("Hello, World!")
