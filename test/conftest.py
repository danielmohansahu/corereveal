import os
from corereveal.qiling_interface import QilingInterface

EMULATION_RESULTS = dict()

def pytest_sessionstart(session):
    print("[+] Compiling Test Binaries...")
    
    cmd = "(cd src/ && make clean)"
    print(f"[+] $ {cmd}")
    os.system(cmd)
    
    cmd = "(cd src/ && make all)"
    print(f"[+] $ {cmd}")
    os.system(cmd)
    
    interface = QilingInterface("./bin/rng_guesser", "./bin", 0x4010, 0xc)
    stdin_data = b"".join([b"100\n", b"500\n", b"200\n", b"150\n"])
    EMULATION_RESULTS['rng_guesser'] = interface.emulate(stdin=stdin_data)

    interface = QilingInterface("./bin/ini_reader", "./bin", 0x4010, 0x7)
    EMULATION_RESULTS['ini_reader'] = interface.emulate(args="./test_config.ini")
    
    interface = QilingInterface("./bin/sus", "./bin", 0x4058, 0x8)
    EMULATION_RESULTS['sus'] = interface.emulate()  