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
      openjdk-17-jdk

# change working dir for installation of downloadable packages
WORKDIR /opt

# install gradle
COPY downloads/gradle-8.0.2-bin.zip .
RUN unzip gradle-8.0.2-bin.zip
RUN ln -s /opt/gradle-8.0.2/bin/gradle /usr/local/bin/gradle

# install eclipse
COPY downloads/eclipse-java-2023-03-R-linux-gtk-x86_64.tar.gz .
RUN tar -xzf eclipse-java-2023-03-R-linux-gtk-x86_64.tar.gz
RUN ln -s /opt/eclipse/eclipse /usr/local/bin/eclipse

# install ghidra
COPY downloads/ghidra_10.2.3_PUBLIC_20230208.zip .
RUN unzip ghidra_10.2.3_PUBLIC_20230208.zip
RUN ln -s /opt/ghidra_10.2.3_PUBLIC/ghidraRun /usr/local/bin/ghidraRun
ENV GHIDRA_INSTALL_DIR /opt/ghidra_10.2.3_PUBLIC

# drop into an interactive shell
WORKDIR /workspace
CMD bash

