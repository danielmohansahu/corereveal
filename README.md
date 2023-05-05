REPOSITORY UNDER DEVELOPMENT!

# corereveal
Leveraging [Qiling](https://qiling.io/) and [Ghidra](https://ghidra-sre.org/) for binary analysis.

## Development Environment

A [Docker](https://www.docker.com/) development environment is provided for demonstration purposes.

Note that this assumes an existing Docker installation on a modern version of Ubuntu with common system tools installed. Make sure `docker run hello-world` succeeds on your machine before continuing.

Additional dependencies:

```bash
python3 -m pip install rocker
```

**Instructions:**
1. Build Docker image and drop into an interactive container via `./build_and_run.sh`
2. Start Ghidra via `ghidraRun` abd perform Ghidra initialization (new project, etc.) - see [the docs](https://ghidra-sre.org/) for more information.
3. Execute the CoreReveal Ghidra script on a loaded binary.

Initial Configuration | Script Execution
--- | ---
![example startup](docs/container-startup.gif) | ![example execute](docs/running-corereveal.gif)


## Execution Examples

The following gifs demonstrate the usage of `CoreReveal` against a variety of different binary targets. To build the test binaries first run the following:

```bash
cd test
pytest
```

`ini_reader` | `rng_guesser` | `sus`
--- | --- | ---
![ini_reader example](docs/example-ini-reader.gif) | ![rng_guesser example](docs/example-rng-guesser.gif) | ![sus example](docs/example-sus.gif)

