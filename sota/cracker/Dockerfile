FROM rust:1.83-bookworm AS crackers_builder
WORKDIR /crackers_build
COPY crackers ./crackers
RUN apt update && apt install -y libclang-dev libz3-dev
RUN rustup default stable
RUN cargo install crackers --version 0.1.1 --features="bin"

FROM debian:trixie
WORKDIR /tmp
ENV VERSION=11.2.1_PUBLIC
ENV GHIDRA_SHA=ce4db5117da0fbaf8f33863fec4f40902f754f06b68945a59fb1c0f9b1bc461c
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip

RUN apt update && apt install -y libz3-4 libssl3 ca-certificates unzip
ADD $GHIDRA_URL /tmp/ghidra.zip
RUN unzip /tmp/ghidra.zip
RUN mv /tmp/ghidra_11.2.1_PUBLIC /opt/ghidra
COPY --from=crackers_builder /usr/local/cargo/bin/crackers /usr/bin/crackers

RUN mkdir /expriment
WORKDIR /experiment
RUN apt-get install -y python3 python3-pip python-is-python3
RUN pip3 install --break-system-packages jinja2
RUN pip3 install --break-system-packages pwntools angrop
RUN apt-get install -y build-essential
COPY funcall4.s funcall4.s
RUN gcc -c funcall4.s -o funcall4.o
COPY templates templates
COPY run_funcall4.py run_funcall4.py
COPY run_execve.py run_execve.py
COPY utils.py utils.py
COPY run_execve run_execve
COPY run_funcall4 run_funcall4

