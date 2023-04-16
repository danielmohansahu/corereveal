"""CoreReveal - Ghidrathon based Ghidra script that executes and analyzes a Qiling emulation.

CoreReveal performs emulation via Qiling and analyzes the program flow.
The results are plotted to give a top level overview of the program
structure and general pathways.

@category: Emulation
"""

# STL
import sys

# sanity check we're using Python3 (via Ghidrathon)
assert sys.version_info > (3,0), "Incorrect Python version; do you have Ghidrathon installed?"

# Qiling
from qiling import Qiling

if __name__ == "__main__":
    popup(dir())
