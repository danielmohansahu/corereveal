import os

def pytest_sessionstart(session):
    print("[+] Compiling Test Binaries...")
    
    cmd = "(cd src/ && make clean)"
    print(f"[+] $ {cmd}")
    os.system(cmd)
    
    cmd = "(cd src/ && make all)"
    print(f"[+] $ {cmd}")
    os.system(cmd)
    