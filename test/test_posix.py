def rng_posix_test():
    # read(0, __, 1024)
    stdin_data = [b"100\n", b"500\n", b"200\n", b"150\n"]

    # write(1, "A little too high.\n", 19) = 19
    expected_writes = [
        b"I'm thinking of a number between 0 and 1000\n",
        b"Can you guess it?\n",
        b"Too Low.\n", 
        b"A little too high.\n", 
        b"A little too high.\n", 
        b"A little too high.\n", 
        b"Too Low.\n"
    ]

def ini_posix_test():
    with open("src/test_config.ini", 'rb') as f:
        read_data = f.read()

    open_file = "./bin/test_config.ini" 
    open_mode = "O_RDONLY"
    open_fd = None # TODO dynamically get

    close_fd = False

    expected_writes = [
        b"Comment:  last modified 1 April 2001 by John Doe\n",
        b"Comment:  use IP address in case network name resolution is not working\n",
        b"[owner]\n",
        b"name = John Doe\n",
        b"organization = Acme Widgets Inc.\n",
        b"[database]\n",
        b"port = 143\n",
        b"server = 192.0.2.62\n",
        b"file = \"payroll.dat\"\n"
    ]

    assert open_fd == close_fd

def sus_posix_test():
    expected_opens = ["/etc/passwd", "/etc/shadow", "/etc/crontab", "/etc/groups", "/etc/hosts", "/proc/version", "/proc/mounts"]
