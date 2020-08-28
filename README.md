![Deepgram Logo](dg-black-logo.png)

This is a server plugin for [UniMRCP](https://unimrcp.org/) to allow
[Deepgram Brain](https://deepgram.com) to be used as a
[`speechrecog`](https://tools.ietf.org/html/rfc6787#section-9)
resource in an MRCP server.

## Building

A Dockerfile is provided that will download and build UniMRCP and its
dependencies, as well as build the server plugin.

```bash
$ docker build -t dgmrcp .
```

The server plugin can be copied out of the container by mounting a
directory on your host and running the image to copy the binary:

```bash
$ mkdir out
$ docker run --rm -v $PWD/out:/out dgmrcp cp /dgmrcp/target/release/libdgmrcp.so /out/
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
