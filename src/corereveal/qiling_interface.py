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
from pathlib import Path
from typing import Callable
import dataclasses

# Unicorn
from unicorn import UcError

# Qiling
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_ARCH, QL_OS
from qiling.extensions import pipe

# hardcoded path to qiling rootfs - assuming x8664 linux for now
ROOTFS_ROOT = Path("/opt/qiling/examples/rootfs")

# data structure of results from Qiling
@dataclasses.dataclass
class EmulationResults:
  # all addresses encountered
  addresses:        set  = dataclasses.field(default_factory=set)
  # basic block addresses encountered
  block_addresses:  set  = dataclasses.field(default_factory=set)
  # static variable values {variable : [values]}
  static_variables: dict = dataclasses.field(default_factory=dict)
  # arguments to posix calls {call : [(arg1, arg2, ..., argN)] }
  posix_calls:      dict = dataclasses.field(default_factory=dict)

class QilingInterface:
  """ Core Qiling Interface Class """

  def __init__(self, program: str, args: str, arch: str, address_size : str, os: str, stdin_cb: Callable, stdout_cb: Callable):
    """ Setup and initialization of underlying Qiling environment.

    Args:
      program:      Full path to the program to execute.
      args:         Command line arguments to provide.
      arch:         Architecture of program to emulate.
      address_size: Number of bits in addresses.
      os:           Operating system of program to emulate.
      stdin_cb:     Callback executed when STDIN is requested.
      stdout_cb:    Callback executed when STDOUT is produced.
    """
    # verify input operating system / arch
    assert hasattr(QL_OS, os.upper()), f"Unsupported operating system '{os}'; options are {QL_OS}"
    assert hasattr(QL_ARCH, arch.upper()), f"Unsupported architecture '{arch}'; options are {QL_ARCH}"

    # access base rootfs - note the convention differences between Ghidra and Qiling
    if int(address_size) == 64:
      rootfs = ROOTFS_ROOT / f"{arch.lower()}{address_size.lower()}_{os.lower()}"
    else:
      rootfs = ROOTFS_ROOT / f"{arch.lower()}_{os.lower()}"
    assert rootfs.is_dir(), f"Failed to locate required root filesystem '{rootfs.as_posix()}'"

    # combine program + input args into format expected by qiling
    argv = [program] + args.split()
    self.ql = Qiling(argv, rootfs=rootfs.as_posix(), verbose=QL_VERBOSE.DEBUG)

    # @TODO take over STDIN / STDOUT
    # self.ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())  # take over the input to the program using a fake stdin
    # self.ql.os.stdout = pipe.NullOutStream(sys.stdout.fileno()) # disregard program output

  def emulate(self) -> EmulationResults:
    """ Perform emulation and return the top-level execution trace / metadata.
    """
    # initialize results
    results = EmulationResults()

    # hook to record all addresses encountered
    address_callback = lambda ql,address,size : results.addresses.add(address)
    address_handle = self.ql.hook_code(address_callback)

    # hook in a callback to record the addresses at the start of basic blocks
    block_callback = lambda ql,address,size : results.block_addresses.add(address)
    block_handle = self.ql.hook_block(block_callback)

    # hook in a callback to record all writes
    write_callback = lambda ql,access,address,size,value : print(f'intercepted a memory write to {address:#x} (value = {value:#x})')
    write_handle = self.ql.hook_mem_write(write_callback)

    # perform emulation
    try:
      self.ql.run()
    except UcError as e:
      print(f"Error encountered during emulation: \n{e}")

    # delete hooks
    address_handle.remove()
    block_handle.remove()
    write_handle.remove()

    return results
