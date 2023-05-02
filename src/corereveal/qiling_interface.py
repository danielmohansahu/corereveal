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
from qiling.const import QL_INTERCEPT

try:
  import IPython
except:
  pass

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
  # basic blocks encountered [(address, name)]
  block_addresses:  list = dataclasses.field(default_factory=list)
  # static variable values {variable : [values]}
  static_variables: dict = dataclasses.field(default_factory=dict)
  # arguments to posix calls {call : [(arg1, arg2, ..., argN)] }
  posix_calls:      dict = dataclasses.field(default_factory=dict)

class QilingInterface:
  """ Core Qiling Interface Class """
  
  def __init__(self, program: str, rootfs:str, bss_offset:int, bss_size:int):
    """
    Setup and initialization of underlying Qiling environment.
    
    :param filename:   Full path to the program to execute.
    :param rootfs:     Full path to the root file system the binary expects to execute in
    :param bss_offset: The offset (i.e. base address == 0) where the .bss section is located at
    :param bss_size:   The size of the .bss section in bytes

    """
    self.binary = program
    self.rootfs = rootfs

    self.bss_addr = bss_offset
    self.bss_size = bss_size

    self.results = EmulationResults()
  
  def emulate(self, args:str="", stdin_cb: Callable[[], bytes]=None, stdout_cb: Callable[[bytes], None]=None) -> EmulationResults:
    """
    Perform emulation and return the top-level execution trace / metadata.

    :param args: Command line arguments in string format to pass to program. (Exclude the program itself i.e. argv[0])
    :param stdin_cb:   Callback executed when STDIN is requested. Should return bytes
    :param stdout_cb:  Callback executed when STDOUT is produced. First parameter should be bytes
    
    :returns: an EmulationResults containing dynamically gather information
    """
    self.argv = [self.binary] + args.split()
    self.ql = Qiling(self.argv, self.rootfs)
    
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
    '''
    Constraint functionality based on whether or not the basic blocks' address is in the loaded program's address space. Otherwise we'd get basic blocks from libc or ld
    '''
    if address > self.base_address and address < self.addr_uppr_bnd:
      # print("\n[+] Tracing basic block at 0x%x" % (address))
      self.results.block_addresses.append(address)
      
  def _ql_hook_bss(self, ql, access, address, size, value):
    # TODO
    pass

  def _ql_syscall_openat(self, ql, dirfd:int, pathname:str, flags:int, mode:int, ret):
    # IPython.embed()
    pass


q=QilingInterface("../../test/bin/ini_reader", "../../test/bin/", 0x4010, 0x7)
q.emulate(args='test_config.ini')