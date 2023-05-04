""" Core datatypes used in the CoreReveal project.

N.B. This file is intended to work across both Python2 and Python3
to support Ghidra's native Jython interpreter and modern Python3.
"""

# STL
import pickle
from collections import namedtuple

# data structure of results from emulation
class EmulationResults:
  def __init__(self):
    # basic block addresses encountered
    self.block_addresses = set()
    # static variable values
    self.static_variables = dict()
    # arguments to posix calls
    self.posix_calls = dict()

  def to_file(self, filename):
    """ Serialize to a pickle file. """
    with open(filename, "wb") as picklefile:
      data = {"block_addresses" : self.block_addresses,
              "static_variables" : self.static_variables,
              "posix_calls" : self.posix_calls}
      pickle.dump(data, picklefile, pickle.HIGHEST_PROTOCOL)

  def from_file(self, filename):
    """ Deserialize from a pickle file. """
    with open(filename, "rb") as picklefile:
      data = pickle.load(picklefile)
      self.block_addresses = data["block_addresses"]
      self.static_variables = data["static_variables"]
      self.posix_calls = data["posix_calls"]
