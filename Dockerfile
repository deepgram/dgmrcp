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


# # Install Rust
# COPY rust-toolchain /rust-toolchain
# RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain $(cat /rust-toolchain) --target x86_64-unknown-linux-musl

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable

RUN yum install -y pkg-config clang gcc llvm-devel # libssl-dev openssl-devel


# Install OpenSSL
ARG OPENSSL_VERSION=1.1.1g

RUN yum install -y perl
RUN curl -sSfL https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz | tar -xz && \
    cd openssl-* && \
    # Configure and build.
    ./config \
        no-shared \
        no-zlib \
        -fPIC \
        -DOPENSSL_NO_SECURE_MEMORY \
        --prefix=/usr/local && \
    make install && \
    rm -rf $(pwd)

# Build the Deepgram MRCP plugin
WORKDIR /dgmrcp
COPY Cargo.toml Cargo.lock ./
COPY native native
COPY build.rs ./
COPY src src
ENV MRCP_INCLUDE_PATH=/opt/unimrcp/include:/opt/unimrcp/include/apr-1
ENV OPENSSL_INCLUDE_DIR=/usr/local/include/openssl
ENV OPENSSL_LIB_DIR=/usr/local/lib64
RUN . $HOME/.cargo/env && cargo build --release
RUN strip ./target/release/libdgmrcp.so
