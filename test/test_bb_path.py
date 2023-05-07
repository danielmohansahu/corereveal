from elftools.elf.elffile import ELFFile
from conftest import EMULATION_RESULTS

def _get_info(prog_name):
    with open(f"./src/{prog_name}.c", 'r') as f:
        src = f.read().split('\n')

    debug_info = []
    with open(f"./bin/{prog_name}", 'rb') as f:
        elf = ELFFile(f)
        dwarf = elf.get_dwarf_info()
        # only 1 CU in these test cases
        cu = next(dwarf.iter_CUs())

        line_prog = dwarf.line_program_for_CU(cu)
        for entry in line_prog.get_entries():
            if not (entry.state is None):
                debug_info.append((entry.state.address, entry.state.line, src[entry.state.line-1]))
    return debug_info

# def test_rng_bb():
#     res = EMULATION_RESULTS['rng_guesser'].block_addresses
#     debug_info = _get_info("rng_guesser")

#     lines = [10,12,13,14,15,21,22] + list(range(27, 60))
#     expected_addrs = set()
#     for line in lines:
