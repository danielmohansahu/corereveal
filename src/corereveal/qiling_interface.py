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
from qiling.const import QL_VERBOSE, QL_INTERCEPT, QL_ARCH
from qiling.extensions import pipe

# hardcoded path to qiling rootfs - assuming x8664 linux for now
ROOTFS_ROOT = Path("/opt/qiling/examples/rootfs")

class BasicBlock:
  def __init__(self, addr:int, size:int):
    """
    :param addr: the runtime address that this basic block is loaded at
    :param size: the size of the basic block in number of bytes
    """
    self.addr = addr
    self.size = size

  def rebase(self, offset:int):
    pass

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

  def __init__(self, program: str, bss_offset:int, bss_size:int, stdin_cb: Callable[[], bytes]=None, stdout_cb: Callable[[bytes], None]=None):
    """ Setup and initialization of underlying Qiling environment.

    :param program:     Full path to the program to execute.
    :param bss_offset:  The offset (i.e. base address == 0) where the .bss section is located at
    :param bss_size:    The size of the .bss section in bytes
    :param stdin_cb:    Callback executed when STDIN is requested.
    :param stdout_cb:   Callback executed when STDOUT is produced.
    """

    # save class variables
    self.binary    = program
    self.bss_addr  = bss_offset
    self.bss_size  = bss_size
    self.stdin_cb  = stdin_cb
    self.stdout_cb = stdout_cb

    # initialize other class variables
    self.rootfs  = None
    self.results = None

  def set_rootfs(self, rootfs: str):
    """ Manually set a rootfs for emulation.
    
    :param: rootfs:   Full path to the root file system the binary expects to execute in
    """
    self.rootfs = Path(rootfs)
    assert self.rootfs.is_dir(), f"Failed to locate required root filesystem '{self.rootfs.as_posix()}'"

  def set_default_rootfs(self, arch: str, address_size: str, os: str):
    """ Use a pre-installed rootfs (provided by qiling).
    
    :param arch:         Architecture of program to emulate.
    :param address_size: Number of bits in addresses.
    :param os:           Operating system of program to emulate.
    """
    # verify input operating system / arch
    assert hasattr(QL_OS, os.upper()), f"Unsupported operating system '{os}'; options are {QL_OS}"
    assert hasattr(QL_ARCH, arch.upper()), f"Unsupported architecture '{arch}'; options are {QL_ARCH}"
  
    # access base rootfs - note the convention differences between Ghidra and Qiling
    if int(address_size) == 64:
      self.rootfs = ROOTFS_ROOT / f"{arch.lower()}{address_size.lower()}_{os.lower()}"
    else:
      self.rootfs = ROOTFS_ROOT / f"{arch.lower()}_{os.lower()}"
    assert self.rootfs.is_dir(), f"Failed to locate required root filesystem '{self.rootfs.as_posix()}'"
  
  def emulate(self, args:str="") -> EmulationResults:
    """
    Perform emulation and return the top-level execution trace / metadata.

    :param args: Command line arguments in string format to pass to program. (Exclude the program itself i.e. argv[0])
    
    :returns: an EmulationResults containing dynamically gather information
    """
    # sanity check initialization
    assert (self.rootfs is not None), "QilingInterface not initialized properly. Must set rootfs."
  
    # initialize results
    self.results = EmulationResults()

    # construct core qiling object
    argv = [self.binary] + args.split()
    self.ql = Qiling(argv, self.rootfs.as_posix(), verbose=QL_VERBOSE.DEBUG)

    # @TODO take over STDIN / STDOUT
    # self.ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())  # take over the input to the program using a fake stdin
    # self.ql.os.stdout = pipe.NullOutStream(sys.stdout.fileno()) # disregard program output
    
    # Determine Base Address and an Upper Bound address for the binary's text section    
    bits = self.ql.arch.bits
    self.base_address = int(self.ql.profile[f'OS{bits}']['load_address'], 16)
    self.addr_uppr_bnd = int(self.ql.profile[f'OS{bits}']['mmap_address'], 16)

    ####################
    # Basic Block Hook #
    ####################
    self.ql.hook_block(self._ql_hook_block_disasm)

    ####################
    #  BSS Write Hook  #
    ####################
    bss_start = self.base_address + self.bss_addr
    bss_end = bss_start = self.bss_size
    self.ql.hook_mem_write(self._ql_hook_bss, begin=bss_start, end=bss_end)

    ####################
    # POSIX Call Hooks #
    ####################
    # open/openat
    self.ql.os.set_syscall('openat', self._ql_syscall_openat, QL_INTERCEPT.EXIT)
    # read

    # write
    self.ql.run()

    return self.results
  
  def _ql_hook_block_disasm(self, ql, address, size):
    ''' Basic Block entry callback.

    Note: We constrain functionality based on whether or not the basic block's
          address is in the loaded program's address space. Otherwise we'd get
          basic blocks from libc or ld.
    '''
    assert (self.results is not None), "Emulation setup failed."

    if self.base_address <= address <= self.addr_uppr_bnd:
      # print("\n[+] Tracing basic block at 0x%x" % (address))
      self.results.block_addresses.add(address)
      
  def _ql_hook_bss(self, ql, access, address, size, value):
    """ Memory writes in BSS section callback.
    """
    assert (self.results is not None), "Emulation setup failed."
    # TODO
    pass

  def _ql_syscall_openat(self, ql, dirfd:int, pathname:str, flags:int, mode:int, ret):
    """ POSIX syscall callback.
    """
    assert (self.results is not None), "Emulation setup failed."
    # IPython.embed()
    # TODO
    pass
