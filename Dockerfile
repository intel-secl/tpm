# ATTENTION: DO NOT RUN DOCKER BUILD FROM THIS CONTEXT
# Run docker build from the go repository root, and docker build -f ./docker/Dockerfile .

FROM ubuntu:17.10

ARG http_proxy
ARG https_proxy

RUN apt-get update &&\
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ca-certificates \
        libssl-dev \
        curl \
        vim \
        build-essential \
        libtool \
        autotools-dev \
        automake \
        git \
        libtspi-dev \
        libgcrypt11-dev \
        pkg-config \
        libglib2.0-dev \
        libcurl4-openssl-dev \
        autoconf-archive \
        libglib2.0-dev \
        libdbus-1-dev \
        autoconf \
        automake \
        libtool \
        curl \
        man \
        gnulib \
        doxygen



# Create TPM 1.2 sim dir
RUN mkdir -p /root/tpm12/sim
WORKDIR /root/tpm12/sim
# Build TPM 1.2 simulator
RUN curl -L https://sourceforge.net/projects/ibmswtpm/files/tpm4769tar.gz > /root/tpm12/sim/tpm-sim.tar.gz &&\
    tar -xzvf tpm-sim.tar.gz && cd libtpm && chmod +x comp-sockets.sh && ./comp-sockets.sh && make install &&\
    cd ../tpm && cp makefile-en-ac makefile && make && cp ./tpm_server /usr/local/bin/tpm_server

# Create TPM 1.2 TSS dir
RUN mkdir -p /root/tpm12/tss
WORKDIR /root/tpm12/tss
# Build TPM 1.2 TSS
RUN curl -L https://sourceforge.net/projects/trousers/files/trousers/0.3.14/trousers-0.3.14.tar.gz > tss.tar.gz &&\
    tar -xzvf tss.tar.gz && chmod +x ./bootstrap.sh && ./bootstrap.sh && ./configure --enable-debug && make && make install
# Set TPM 1.2 Environment Variables
ENV TCSD_TCP_DEVICE_HOSTNAME localhost
ENV TPM_PORT 6545
ENV TPM_SERVER_PORT 6545
ENV TPM_SERVER_NAME localhost
ENV TSS_USER_PS_FILE /tmp/tss.ps

# Create TPM 1.2 NIARL Tools
RUN mkdir -p  /root/tpm12/niarl
COPY docker/niarl_tpm /root/tpm12/niarl
RUN cd /root/tpm12/niarl && make && make install


# Create TPM 2.0 dir
RUN mkdir -p /root/tpm20/sim
# Build TPM 2.0 sim
WORKDIR /root/tpm20/sim
RUN curl -L https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm1332.tar.gz |\
    tar -xz &&\
    make -j4 -C src && cp ./src/tpm_server /usr/local/bin/tpm2_server

RUN mkdir -p /root/tpm20/tss2
WORKDIR /root/tpm20/tss2

RUN git clone https://github.com/intel/tpm2-tss.git &&\
    cd tpm2-tss &&\
    ./bootstrap -I /usr/share/gnulib/m4 &&\
    ./configure --prefix=/usr &&\
    make -j4 &&\
    make install

RUN mkdir -p /root/tpm20/tools
WORKDIR /root/tpm20/tools
RUN git clone https://github.com/intel/tpm2-tools.git &&\
    cd tpm2-tools &&\
    ./bootstrap -I /usr/share/gnulib/m4 &&\
    ./configure --prefix=/usr &&\
    make -j4 &&\
    make install

ENV TPM2TOOLS_TCTI=mssim
ENV USE_TPM_SIM true

WORKDIR /root
RUN curl -L https://dl.google.com/go/go1.11.2.linux-amd64.tar.gz > go.tar.gz && tar -C /usr/local -xzf go.tar.gz
ENV PATH ${PATH}:/usr/local/go/bin

COPY . /root/go/tpm
WORKDIR /root/go/tpm
RUN go build cmd/go-tpm/main.go && mv ./main /usr/local/bin/go-tpm

COPY docker/start_tpm1.sh /usr/local/bin/start_tpm1
COPY docker/start_tpm2.sh /usr/local/bin/start_tpm2 
RUN chmod +x /usr/local/bin/start_tpm*
COPY docker/tcsd.conf /etc/tcsd.conf

ENV TPM_PATH /tmp
ENTRYPOINT "bash"
