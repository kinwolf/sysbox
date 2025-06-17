FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies required for Sysbox development
RUN apt-get update && apt-get install -y \
    acl \
    build-essential \
    gcc-x86-64-linux-gnu \
    libc6-dev-amd64-cross \
    linux-libc-dev-amd64-cross \
    gcc-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    linux-libc-dev-arm64-cross \
    automake \
    autoconf \
    libtool \
    procps \
    psmisc \
    nano \
    less \
    curl \
    sudo \
    gawk \
    git \
    iptables \
    jq \
    pkg-config \
    libaio-dev \
    libcap-dev \
    libprotobuf-dev \
    libnl-3-dev \
    libnet-dev \
    libseccomp2 \
    libseccomp-dev \
    protobuf-c-compiler \
    protobuf-compiler \
    python3 \
    uidmap \
    kmod \
    unzip \
    time \
    net-tools \
    lsb-release \
    wget \
    lsof \
    iproute2 \
    iputils-ping \
    ca-certificates \
    bc \
    ssh-client \
    shellcheck \
    gperf \
    fuse \
    rsync \
    bash-completion \
    attr \
    tree \
    strace \
    make \
    --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22.6
ARG TARGETARCH=amd64
RUN wget https://go.dev/dl/go1.22.6.linux-${TARGETARCH}.tar.gz && \
    tar -C /usr/local -xzf go1.22.6.linux-${TARGETARCH}.tar.gz && \
    rm go1.22.6.linux-${TARGETARCH}.tar.gz

# Set up Go environment
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && \
    chmod -R 777 "$GOPATH"

# Install protoc compiler for gRPC
RUN if [ "$TARGETARCH" = "amd64" ] ; then arch_str="x86_64"; \
    elif [ "$TARGETARCH" = "arm64" ]; then arch_str="aarch_64"; \
    else echo "Unsupported platform: ${TARGETARCH}"; exit; fi \
    && curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v3.15.8/protoc-3.15.8-linux-${arch_str}.zip \
    && unzip protoc-3.15.8-linux-${arch_str}.zip -d /usr/local \
    && rm protoc-3.15.8-linux-${arch_str}.zip

# Install Go tools
RUN go install github.com/golang/protobuf/protoc-gen-go@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest

# Install Docker
RUN curl -fsSL https://get.docker.com -o get-docker.sh && \
    sh get-docker.sh && \
    rm get-docker.sh

# Install bats for testing
RUN cd /tmp && \
    git clone https://github.com/sstephenson/bats.git && \
    cd bats && \
    git reset --hard 03608115df2071fff4eaaff1605768c275e5f81f && \
    ./install.sh /usr/local && \
    rm -rf /tmp/bats

# Create a non-root user for development
RUN useradd -m -d /home/ubuntu -s /bin/bash ubuntu && \
    echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up bash completion
RUN echo ". /etc/bash_completion" >> /etc/bash.bashrc

USER ubuntu
WORKDIR /home/ubuntu

# Configure git to avoid issues with safe.directory
RUN git config --global --add safe.directory '*'

# Reset DEBIAN_FRONTEND
ENV DEBIAN_FRONTEND=
