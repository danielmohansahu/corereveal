# corereveal
Leveraging [Qiling](https://qiling.io/) and [Ghidra](https://ghidra-sre.org/) for binary analysis.

## Development Environment

A [Docker](https://www.docker.com/) development environment is provided for those who wish to use it. Users should carefully weight the benefits of isolation vs. the pains of containerization before using it. Note that this assumes an existing Docker installation on a modern version of Ubuntu with common system tools installed.

Docker installation verification:

```bash
# note this should work without root privileges (sudo)
docker run hello-world
```

Additional dependencies:

```bash
python3 -m pip install rocker
```

**Instructions:**
1. Build Docker image and drop into an interactive container via `./build_and_run.sh`
2. Run Ghidra via `ghidraRun` and install Ghidrathon extension. Restart.
3. (optional, per-project): Run Ghidra via `ghidraRun` and disable native (Jython) Python support. Restart.
4. (optional): `docker commit` the modified container so you don't need to repeat these steps on every restart.

Initial Configuration | Script Execution
--- | ---
![example startup](docs/container-startup.gif) | ![example execute](docs/running-corereveal.gif)

