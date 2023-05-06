#!/usr/bin/env python3
""" Command line interface to call QilingInterface emulator.
"""

# STL
import sys
import argparse
from pathlib import Path

# CoreReveal
from corereveal.qiling_interface import QilingInterface

ROOTFS_ROOT = Path("/mnt/rootfs/")

def parse_args():
    """ Parse input arguments. """
    parser = argparse.ArgumentParser("Qiling-based binary emulation wrapper.")
    parser.add_argument("program", type=Path, help="Binary program to execute.")
    parser.add_argument("-o", "--output", type=Path, default=Path("/tmp/emulation.pickle"),
                        help="Results output file.")
    parser.add_argument("-a", "--args", type=str, default="",
                        help="Space separated string of args to pass.")
    parser.add_argument("-r", "--rootfs", type=Path, default=None,
                        help="ROOTFS to use in emulation; can be specified manually or through ARCH options.")
    parser.add_argument("-A", "--arch", type=str, default=None,
                        help="Architecture to emulate.")
    parser.add_argument("-bo", "--bss-offset", type=int, default=0, help="Relative location of BSS memory block.")
    parser.add_argument("-bs", "--bss-size", type=int, default=0, help="Size of BSS memory block.")
    args,_ = parser.parse_known_args()

    # sanity check inputs
    assert args.program.is_file(), f"Provided binary {args.program} doesn't exist."
    if args.rootfs is not None:
        assert args.rootfs.is_dir(), f"Provided rootfs '{args.rootfs.as_posix()}' is not a directory."
        assert args.arch is None, "Provided both architecture and ROOTFS - just provide one."
    elif args.arch is not None:
        # use one of our pre-built rootfs
        args.rootfs = ROOTFS_ROOT / args.arch.lower()
        assert args.rootfs.is_dir(), f"Unsupported architecture {args.arch}"
    else:
        raise RuntimeError("Must provide ROOTFS or architecure!")
    return args

def main() -> int:
    # parse inputs
    args = parse_args()

    # construct core interface class
    print("Constructing interface...")
    interface = QilingInterface(args.program.as_posix(), args.rootfs.as_posix(), args.bss_offset, args.bss_size)

    # perform emulation
    print("Running emulation...")
    if results := interface.emulate(args.args):
        print(f"Emulation succeeded - saving results to {args.output.as_posix()}.")
        results.to_file(args.output.as_posix())
    else:
        print("Emulation failed.")
        return 1

    # indicate success
    return 0
