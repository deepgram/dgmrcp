From centos:7

# These are used to access the UniMRCP package repository.
ARG UNIMRCP_USERNAME
ARG UNIMRCP_PASSWORD

RUN echo -e "\
[unimrcp]\n\
name=UniMRCP Packages for Red Hat / Cent OS-$releasever $basearch\n\
baseurl=https://$UNIMRCP_USERNAME:$UNIMRCP_PASSWORD@unimrcp.org/repo/yum/main/rhel\$releasever/\$basearch\n\
enabled=1\n\
sslverify=1\n\
gpgcheck=1\n\
gpgkey=https://unimrcp.org/keys/unimrcp-gpg-key.public" > /etc/yum.repos.d/unimrcp.repo

RUN yum install -y unimrcp-server-devel

# Paths to find mrcp objects
ENV C_INCLUDE_PATH="/opt/unimrcp/include/apr-1:/opt/unimrcp/include"
ENV LD_LIBRARY_PATH="/opt/unimrcp/lib"


# # Install Rust
# COPY rust-toolchain /rust-toolchain
# RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain $(cat /rust-toolchain) --target x86_64-unknown-linux-musl

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable

RUN yum install -y pkg-config clang gcc llvm-devel

# Build the Deepgram MRCP plugin
WORKDIR /dgmrcp
COPY Cargo.toml Cargo.lock ./
COPY native native
COPY build.rs ./
COPY src src
RUN . $HOME/.cargo/env && cargo build --release
RUN strip ./target/release/libdgmrcp.so
