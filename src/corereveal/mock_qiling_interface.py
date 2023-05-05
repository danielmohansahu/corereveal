""" Mock implementation of QilingInterface.

This class is a dummy implementation of the QilingInterface
class for testing and development.
"""

# STL
import time
import random
from typing import Callable

# CoreReveal
from .qiling_interface import EmulationResults

def generate_random_addresses(start: str, end_offset: int = 2048, count: int = 150):
    """ Generate 'count' random addresses in the range ['start', 'start' + 'end_offset'] """
    begin = int(start, 16)
    end = begin + end_offset
    return [hex(address) for address in random.choices(range(begin, end), k=count)]

class MockQilingInterface:
    """ Mock QilingInterface class, for testing and development. """
    def __init__(self, program, metadata, start_address, static_variables):
        """ Mock initialization takes the same arguments as the core class
            as well as some Ghidra-supplied program info.
        """
        self.program  = program
        self.metadata = metadata
        self.start_address = start_address
        self.static_variables = static_variables

    def emulate(self, args: str, stdin_cb: Callable, stdout_cb: Callable) -> EmulationResults:
        """ Simulate emulation. """

        # determine duration
        duration = random.random() * 10

        # 50/50 chance of prompting for user input right off the bat
        if random.random() > 0.5:
            stdin_cb("How are you feeling?")
        stdout_cb("I understand.")

        # loop until desired time is up
        st = time.time()
        while time.time() - st < duration:
            # maybe we need more user input
            if random.random() > 0.9:
                stdin_cb("Please provide additional input")

            # it's more likely that we just spam
            if random.random() > 0.75:
                stdout_cb("SPAM!")

            # sleep
            time.sleep(random.random())

        # there's a small chance emulation failed
        if random.random() < 0.05:
            stdout_cb("SEGFAULT")
            return None

        # otherwise, populate random results
        results = EmulationResults()

        # get random address after our start address
        results.block_addresses = generate_random_addresses(self.start_address)

        # @TODO populate syscall information and comments
        return results
