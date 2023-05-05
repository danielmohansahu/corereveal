# GHIDRA development environment base image
FROM ubuntu:20.04 AS base

# install common utilities and ghidra dependencies
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      vim \
      byobu \
      wget \
      zip \
      git \
      tree \
      python3-dev \
      python3-pip \
      openjdk-17-jdk \
      debootstrap \
      qemu-user-static

# construct a set of supported rootfs for emulation
WORKDIR /mnt/rootfs
RUN mkdir arm && debootstrap --foreign --arch armhf --variant=buildd stable arm
RUN mkdir arm64 && debootstrap --foreign --arch arm64 --variant=buildd stable arm64
RUN mkdir mips && debootstrap --foreign --arch mipsel --variant=buildd stable mips
RUN mkdir mips64 && debootstrap --foreign --arch mips64el --variant=buildd stable mips64
RUN mkdir ppc64 && debootstrap --foreign --arch ppc64el --variant=buildd stable ppc64
RUN mkdir x8664 && debootstrap stable x8664

# change working dir for installation of downloadable packages
WORKDIR /opt

# install gradle (Java development)
RUN wget -nv https://services.gradle.org/distributions/gradle-8.0.2-bin.zip --output-document gradle-8.0.2-bin.zip
RUN unzip gradle-8.0.2-bin.zip && rm gradle-8.0.2-bin.zip
RUN ln -s /opt/gradle-8.0.2/bin/gradle /usr/local/bin/gradle

# install ghidra (Reverse Engineering tool)
RUN wget -nv https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.3_build/ghidra_10.2.3_PUBLIC_20230208.zip --output-document ghidra_10.2.3_PUBLIC_20230208.zip
RUN unzip ghidra_10.2.3_PUBLIC_20230208.zip && rm ghidra_10.2.3_PUBLIC_20230208.zip
RUN ln -s /opt/ghidra_10.2.3_PUBLIC/ghidraRun /usr/local/bin/ghidraRun
ENV GHIDRA_INSTALL_DIR /opt/ghidra_10.2.3_PUBLIC

# install Qiling (Python Emulation Framework)
RUN git clone -b 1.4.5 https://github.com/qilingframework/qiling.git
RUN cd qiling && git submodule update --init --recursive && python3 -m pip install .

# install CoreReveal
WORKDIR /tmp/corereveal
RUN python3 -m pip install --upgrade pip pylint pytest
COPY . .
RUN python3 -m pip install .
# RUN python3 -m pylint corereveal

# move Ghidrathon extensions and our custom scripts into Ghidra installation (for easy access)
COPY scripts/CoreReveal.py $GHIDRA_INSTALL_DIR/Ghidra/Features/Python/ghidra_scripts/
COPY src/corereveal/corereveal_types.py $GHIDRA_INSTALL_DIR/Ghidra/Features/Python/ghidra_scripts/

# drop into an interactive shell
WORKDIR /root/workspace
CMD bash

