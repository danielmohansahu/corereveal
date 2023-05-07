""" Core datatypes used in the CoreReveal project.

N.B. This file is intended to work across both Python2 and Python3
to support Ghidra's native Jython interpreter and modern Python3.
"""

# STL
import pickle
from collections import namedtuple, defaultdict

class FunctionCall:
  def __init__(self, name:str, address:int, return_value:int, **func_args):
    """
    Represents a call to a function that has executed
    :param address: The address the function was called at (i.e. address of the CALL op code)
    :param return_value: The value of the function's return value
    :param args: The list of arguments passed into the function in the positional order expected in the call
    """
    self.name = name
    self.address = address
    self.ret = return_value
    self.args = func_args

  def __str__(self):
    args = ", ".join([f"{param}={value}" for param, value in self.args.items()])
    return f"{hex(self.address)}: {self.name}({args}) = {self.ret}"

# data structure of results from emulation
class EmulationResults:
  def __init__(self):
    # basic block addresses encountered
    self.block_addresses = set()
    # static variable values
    self.static_variables = defaultdict(list)
    # arguments to posix calls
    self.posix_calls = list()

  def to_file(self, filename):
    """ Serialize to a pickle file. """
    with open(filename, "wb") as picklefile:
      data = {"block_addresses" : self.block_addresses,
              "static_variables" : self.static_variables,
              "posix_calls" : self.posix_calls}
      pickle.dump(data, picklefile, 0)

  def from_file(self, filename):
    """ Deserialize from a pickle file. """
    with open(filename, "rb") as picklefile:
      data = pickle.load(picklefile)
      self.block_addresses = data["block_addresses"]
      self.static_variables = data["static_variables"]
      self.posix_calls = data["posix_calls"]
