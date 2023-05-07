from conftest import EMULATION_RESULTS

def test_rng_bss():
    res = EMULATION_RESULTS['rng_guesser'].static_variables

    # TODO run script
    seed = res['0x4014'][0]
    max_retries = res['0x401c'][0]
    max_value = res['0x4018'][0]

    assert seed == (0xdead << 16) | 0xbeef
    assert max_retries == 5
    assert max_value == 1000

def test_ini_bss():
    res = EMULATION_RESULTS['ini_reader'].static_variables
    assert len(res.keys()) == 1

def test_sus_bss():
    res = EMULATION_RESULTS['sus'].static_variables
    assert len(res.keys()) == 1


