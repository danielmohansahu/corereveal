def rng_bss_test():
    # TODO run script
    seed = None
    max_retries = None
    max_value = None

    assert seed == (0xdead << 16) | 0xbeef
    assert max_retries == 5
    assert max_value == 1000

def ini_bss_test():
    num_bss_vars = None

    assert num_bss_vars == 0

def sus_bss_test():
    num_bss_vars = None

    assert num_bss_vars == 0


