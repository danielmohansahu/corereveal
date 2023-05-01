from elftools.elf.elffile import ELFFile

def _get_info(prog_name):
    with open(f"./src/{prog_name}.c", 'r') as f:
        src = f.read().split('\n')

    debug_info = []
    with open("./bin/{prog_name}", 'rb') as f:
        elf = ELFFile(f)
        dwarf = elf.get_dwarf_info()
        # only 1 CU in these test cases
        cu = next(dwarf.iter_CUs())

        line_prog = dwarf.line_program_for_CU(cu)
        for entry in line_prog.get_entries():
            if not (entry.state is None):
                debug_info.append((entry.state.address, entry.state.line, src[entry.state.line-1]))

def rng_bb_test():
    base_addr = 0
    basic_blocks = []
    debug_info = _get_info("rng_guesser")

    for bb in basic_blocks:
        pass
    