import os

EMULATION_RESULTS = None

def pytest_sessionstart(session):
    print("[+] Compiling Test Binaries...")
    
    cmd = "(cd src/ && make clean)"
    print(f"[+] $ {cmd}")
    os.system(cmd)
    
    cmd = "(cd src/ && make all)"
    print(f"[+] $ {cmd}")
    os.system(cmd)
    
    # TODO call Qiling emulation for all test bins here

    # Insert results here as a dict so tests can check the results
    # EMULATION_RESULTS = 