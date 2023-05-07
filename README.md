# corereveal

<img src="docs/CoreReveal.svg" alt="logo" width="750" height="500">

CoreReveal allows users to directly employ [Qiling](https://qiling.io/) emulation within the [Ghidra](https://ghidra-sre.org/) reverse engineering framework for binary analysis and introspection. During emulation the following data are collected:

Information | Description
--- | ---
Basic Block Addresses | Addresses of Basic Blocks executed during emulation - the executed control flow.
BSS Symbol Values | The value(s) assigned to global variables present in the binary's `.bss` section.
POSIX Call Arguments | Arguments passed to supported POSIX calls like `read` / `write`.

This information is displayed directly in Ghidra via code unit coloring and comments to supplement static analysis with dynamically executed emulation results.

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

The following gifs demonstrate the usage of `CoreReveal` against a variety of different binary targets. Before reproducing make sure to build the test binaries via `cd test && pytest`.

Example | Recording
--- | ---
`ini_reader` | ![ini_reader example](docs/example-ini-reader.gif)
`rng_guesser` | ![rng_guesser example](docs/example-rng-guesser.gif)
`sus` | ![sus example](docs/example-sus.gif)

## Sequence Diagram

The following sequence diagram illustrates the typical workflow's fine-grained execution path:

![sequence diagram](docs/uml/sequence.png)