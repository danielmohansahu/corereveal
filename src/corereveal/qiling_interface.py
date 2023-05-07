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

# Qiling
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from qiling.extensions import pipe
from qiling.os.const import *

# CoreReveal
from .corereveal_types import EmulationResults, FunctionCall

MAX_RECORD_SIZE = 32

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

class QilingInterface:
  """ Core Qiling Interface Class """

  def __init__(self, program: str, rootfs: str, bss_offset:int, bss_size:int, stdin_cb: Callable[[], bytes]=None, stdout_cb: Callable[[bytes], None]=None):
    """ Setup and initialization of underlying Qiling environment.

    :param program:     Full path to the program to execute.
    :param rootfs:     Full path to the root file system the binary expects to execute in
    :param bss_offset:  The offset (i.e. base address == 0) where the .bss section is located at
    :param bss_size:    The size of the .bss section in bytes
    :param stdin_cb:    Callback executed when STDIN is requested.
    :param stdout_cb:   Callback executed when STDOUT is produced.
    """

    # save class variables
    self.binary      = program
    self.bss_addr    = bss_offset
    self.bss_size    = bss_size
    self.stdin_cb    = stdin_cb
    self.stdout_cb   = stdout_cb
    self.rootfs = Path(rootfs)
    assert self.rootfs.is_dir(), f"Failed to locate required root filesystem '{self.rootfs.as_posix()}'"

    
    # initialize other class variables
    self.results       = None
    self.ql            = None
    self.base_address  = None
    self.addr_uppr_bnd = None
    self.current_func_call = None 

  def emulate(self, args:str="", stdin:bytes=b"") -> EmulationResults:
    """
    Perform emulation and return the top-level execution trace / metadata.

    :param args: Command line arguments in string format to pass to program. (Exclude the program itself i.e. argv[0])
    
    :returns: an EmulationResults containing dynamically gather information
    """
    # initialize results
    self.results = EmulationResults()

    # construct core qiling object
    argv = [self.binary] + args.split()
    print(f"Executing `{' '.join(argv)}` with rootfs {self.rootfs.as_posix()}")
    self.ql = Qiling(argv, self.rootfs.as_posix(), console=False, log_plain=True)

    self.ql.os.stdin = pipe.SimpleInStream(0)  # take over the input to the program using a fake stdin
    self.ql.os.stdin.write(stdin)
    # self.ql.os.stdout = pipe.NullOutStream(sys.stdout.fileno()) # disregard program output
    
    # Determine Base Address and an Upper Bound address for the binary's text section    
    bits = self.ql.arch.bits
    self.base_address = int(self.ql.profile[f'OS{bits}']['load_address'], 16)
    self.addr_uppr_bnd = int(self.ql.profile[f'OS{bits}']['mmap_address'], 16)

    ####################
    # Basic Block Hook #
    ####################
    self.ql.hook_block(self._ql_hook_block)

    ####################
    #  BSS Write Hook  #
    ####################
    bss_start = self.base_address + self.bss_addr
    bss_end = bss_start + self.bss_size
    self.ql.hook_mem_write(self._ql_hook_bss, begin=bss_start, end=bss_end)

    ####################
    # POSIX Call Hooks #
    ####################
    # open/openat
    
    self.ql.os.set_api('open', self._ql_syscall_open_ENTER, QL_INTERCEPT.ENTER)
    self.ql.os.set_api('open', self._ql_syscall_get_ret, QL_INTERCEPT.EXIT)
    # read
    self.ql.os.set_api('read', self._ql_syscall_read_ENTER, QL_INTERCEPT.ENTER)
    self.ql.os.set_api('read', self._ql_syscall_get_ret, QL_INTERCEPT.EXIT)
    # write 
    self.ql.os.set_api('write', self._ql_syscall_write_ENTER, QL_INTERCEPT.ENTER)
    self.ql.os.set_api('write', self._ql_syscall_get_ret, QL_INTERCEPT.EXIT)

    self.ql.run()

    return self.results
  
  def _ql_hook_block(self, ql, address, size):
    ''' Basic Block entry callback.

    Note: We constrain functionality based on whether or not the basic block's
          address is in the loaded program's address space. Otherwise we'd get
          basic blocks from libc or ld.
    '''
    assert (self.results is not None), "Emulation setup failed."
    if self.base_address <= address <= self.addr_uppr_bnd:
      self.results.block_addresses.add(hex(address - self.base_address))

  def _ql_hook_bss(self, ql, access, address, size, value):
    """ Memory writes in BSS section callback.
    """
    assert (self.results is not None), "Emulation setup failed."
    self.results.static_variables[hex(address - self.base_address)].append(value)

  def _ql_syscall_get_ret(self, ql):
    """ POSIX syscall callback.
    """
    assert (self.results is not None), "Emulation setup failed."
    self.current_func_call.ret = ql.os.fcall.cc.getReturnValue()
    self.results.posix_calls.append(self.current_func_call)

  def _ql_syscall_open_ENTER(self, ql):
    assert (self.results is not None), "Emulation setup failed."
    print("[+] Recording open()")
    address = ql.arch.regs.arch_pc - self.base_address
    params = ql.os.resolve_fcall_params({"pathname": STRING, "flags":INT, "mode":INT})
    self.current_func_call = FunctionCall("open", address, None, **params)

  def _ql_syscall_read_ENTER(self, ql):
    assert (self.results is not None), "Emulation setup failed."
    print("[+] Recording read()")
    address = ql.arch.regs.arch_pc - self.base_address

    # Since buf is just a pointer it is more useful to see the data at the pointer
    params = ql.os.resolve_fcall_params({"fd": INT, "buf":POINTER, "size_t": SIZE_T})

    # Get the file descriptor; save off the current position, read some data off, seek back to the original position
    fd = ql.os.fd[params['fd']]
    pos = fd.tell()
    buffer_data = fd.read(min(params['size_t'], MAX_RECORD_SIZE))
    fd.seek(pos)

    params['buf'] = buffer_data
    self.current_func_call = FunctionCall("read", address, None, **params)

  def _ql_syscall_write_ENTER(self, ql):
    assert (self.results is not None), "Emulation setup failed."
    print("[+] Recording write()")
    address = ql.arch.regs.arch_pc - self.base_address
    params = ql.os.resolve_fcall_params({"fd": INT, "buf":POINTER, "size_t": SIZE_T})
    self.current_func_call = FunctionCall("write", address, None, **params)
