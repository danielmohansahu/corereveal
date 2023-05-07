from conftest import EMULATION_RESULTS

def test_rng_posix():
    res = EMULATION_RESULTS['rng_guesser'].posix_calls
    
    assert len(res) == 0

def test_ini_posix():
    with open("src/test_config.ini", 'rb') as f:
        read_data = f.read()

    res = EMULATION_RESULTS['ini_reader'].posix_calls

    assert res[0].name == 'open'
    pathname = res[0].args['pathname']
    flags = res[0].args['flags']
    fd = res[0].ret

    assert pathname == "./test_config.ini"
    assert flags == 0 # O_RDONLY

    assert res[1].args['fd'] == fd
    assert res[1].args['buf'] == read_data
    assert res[1].ret == len(read_data)


def test_sus_posix():
    res=EMULATION_RESULTS['sus']
    
    expected_results = [
        ("/etc/passwd", 0),
        (b"FAKE PASSWD\n", 12),
        (b"FAKE PASSWD\n", 12),
        ("/etc/shadow", 0),
        (b"FAKE SHADOW\n", 12),
        (b"FAKE SHADOW\n", 12),
        ('/etc/crontab', 0),
        (b"# /etc/crontab: system-wide crontab\n", 36),
        (b"# /etc/crontab: system-wide crontab\n", 36),
        ('/etc/hosts', 0),
        (b"127.0.0.1 localhost\n", 20),
        (b"127.0.0.1 localhost\n", 20)
    ]

    fd = -1
    for posix, expected in zip(res.posix_calls, expected_results):
        if posix.name == "open":
            assert expected[0] == posix.args['pathname']
            assert expected[1] == posix.args['flags']
            fd = posix.ret
        elif posix.name == "read":
            assert posix.args['fd'] == fd
            assert expected[0] == posix.args['buf']
            assert 4096 == posix.args['size_t']
            assert expected[1] == posix.ret
        elif posix.name == "write":
            assert 1 == posix.args['fd']
            assert expected[0] == posix.args['buf']
            assert expected[1] == posix.args['size_t']
        else:
            assert False, "Unexpected Function Name"