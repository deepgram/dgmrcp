FROM rust:1.45.2

RUN apt-get update && apt-get install -y \
        automake \
        clang \
        curl \
        gcc \
        git \
        libsofia-sip-ua-dev \
        libsofia-sip-ua-glib-dev \
        libsofia-sip-ua-glib3 \
        libsofia-sip-ua0 \
        libssl-dev \
        libtool \
        pkg-config \
        sofia-sip-bin \
        sudo \
        wget

# Download and install UniMRPC dependencies
WORKDIR /
RUN wget http://www.unimrcp.org/project/component-view/unimrcp-deps-1-6-0-tar-gz/download -O unimrcp-deps-1.6.0.tar.gz
RUN tar xzf unimrcp-deps-1.6.0.tar.gz
WORKDIR /unimrcp-deps-1.6.0
RUN ./build-dep-libs.sh --silent
RUN ls

# Download and install UniMRCP
WORKDIR /
RUN git clone https://github.com/unispeech/unimrcp
WORKDIR /unimrcp
RUN git checkout unimrcp-1.6.0
RUN ./bootstrap
RUN ./configure
RUN make -j
RUN make install

# # Install Rust
# WORKDIR /
# RUN curl -sSf https://sh.rustup.rs | sh -s -- -y
# # This initializes the crates.io registry
# RUN . $HOME/.cargo/env && cargo search

# Build the Deepgram MRCP plugin
WORKDIR /dgmrcp
RUN USER=root cargo init --lib --name dummy-project
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release
RUN rm src/*.rs
RUN rm ./target/release/deps/dgmrcp*
COPY native native
COPY build.rs ./
COPY src src
RUN cargo build --release

CMD ["/usr/local/unimrcp/bin/unimrcpserver"] #  -r /usr/local/unimrcp -o 2 -w"]
