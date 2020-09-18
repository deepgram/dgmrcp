![Deepgram Logo](dg-black-logo.png)

This is a server plugin for [UniMRCP](https://unimrcp.org/) to allow
[Deepgram Brain](https://deepgram.com) to be used as a
[`speechrecog`](https://tools.ietf.org/html/rfc6787#section-9)
resource in an MRCP server.

## Installation

Place the library file `libdgmrcp.so` in the UniMRCP plugins directory
(for example, `/opt/unimrcp/plugin/`).

Then edit the `<plugin-factory>` section of the UniMRCP server
configuration file (for example,
`/opt/unimrcp/conf/unimrcpserver.xml`). General information about
configuring the UniMRCP server can be found in the Server
Configuration Manual on [this
page](http://unimrcp.org/solutions/server).

A minimum configuration is as follows:

```xml
<plugin-factory>
  <engine id="Deepgram" name="libdgmrcp" enable="true">
    <param name="brain_url" value="wss://brain.deepgram.com/v2/"/>
    <param name="brain_username" value="USERNAME"/>
    <param name="brain_password" value="PASSWORD"/>
  </engine>
</plugin-factory>
```

### Configuration

The following options can be specified:

| name | value | description |
| ---  | ---   | ---
| brain_url | string (required) | The URL of the Deepgram ASR API. Try `wss://brain.deepgram.com/v2/` to use Deepgram's hosted API. Note the trailing slash, which is significant. |
| brain_username | string (required) | API username or [API key](https://docs.deepgram.com/#api-keys). |
| brain_password | string (required) | API password or secret. |
| model | string | The default ASR model to use. |
| language | string | The default ASR language to use. |
| plaintext_results | boolean | If `true`, then results in a `RECOGNITION-COMPLETE` message will be in plain text instead of the standard [NLSML](https://tools.ietf.org/html/rfc6787#section-6.3.1). Note that this does not conform to the MRCP specification, but it can be convenient for testing and development. |


## Building

A Dockerfile is provided that will download and build UniMRCP and its
dependencies, as well as build the server plugin.

```bash
$ docker build -t dgmrcp .
```

In order to extract the plugin, we need to create a container from the
image, and then copy the shared object out:

```bash
CONTAINER=$(docker create dgmrcp) \
  && docker cp $CONTAINER:/dgmrcp/target/release/libdgmrcp.so ./ \
  && docker rm $CONTAINER
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
