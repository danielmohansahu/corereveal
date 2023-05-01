""" QilingInterface - Backend class wrapping Qiling emulator.

This file contains the implementation of the QilingInterface class
which accomplishes the following functions:
 - binary / executable emulation,
 - STDIN / STDOUT / CLI argument passthrough,
 - packaging of emulation results, including:
   - addresses of basic blocks encountered during emulation,
   - values of static (.bss) variables,
   - arguments to POSIX calls (read, write, ...?)
"""

# STL
from typing import Callable
import dataclasses

# Qiling
from qiling import Qiling

# data structure of results from Qiling
@dataclasses.dataclass
class EmulationResults:
  # basic blocks encountered [(address, name)]
  block_addresses:  list = dataclasses.field(default_factory=list)
  # static variable values {variable : [values]}
  static_variables: dict = dataclasses.field(default_factory=dict)
  # arguments to posix calls {call : [(arg1, arg2, ..., argN)] }
  posix_calls:      dict = dataclasses.field(default_factory=dict)

class QilingInterface:
  """ Core Qiling Interface Class """
  
  def __init__(self, program: str, metadata: str):
    """ Setup and initialization of underlying Qiling environment.

    Args:
      filename:   Full path to the program to execute.
      metadata:   Executable metadata (architecture, endianness, etc.).
    """
    # I am a stub.
  
  def emulate(self, args: str, stdin_cb: Callable, stdout_cb: Callable) -> EmulationResults:
    """ Perform emulation and return the top-level execution trace / metadata.

    Args:
      args:       Command line arguments in string format to pass to program.
      stdin_cb:   Callback executed when STDIN is requested.
      stdout_cb:  Callback executed when STDOUT is produced.
    """
    # I am a stub.
    return EmulationResults()
