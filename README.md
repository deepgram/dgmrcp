![Deepgram Logo](dg-black-logo.png)

This is a server plugin for [UniMRCP](https://unimrcp.org/) to allow
[Deepgram Brain](https://deepgram.com) to be used as a
[`speechrecog`](https://tools.ietf.org/html/rfc6787#section-9)
resource in an MRCP server.

## Installation

Download the `libdgmrcp.so` library from the
[releases](https://github.com/deepgram/dgmrcp/releases) page.

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
    <param name="brain_url" value="wss://api.deepgram.com/v1/"/>
    <param name="brain_username" value="YOUR_USER_EMAIL"/>
    <param name="brain_password" value="YOUR_API_KEY"/>
  </engine>
</plugin-factory>
```

### Configuration

The following options can be specified:

| name | value | description |
| ---  | ---   | ---
| brain_url | string (required) | The URL of the Deepgram ASR API. You can set this to `wss://api.deepgram.com/v1/` to use Deepgram's hosted API, or set it to the URL of your on-prem deployment. Note the trailing slash, which is significant. |
| brain_username | string | Your email. |
| brain_password | string | Your [API key](https://developers.deepgram.com/documentation/getting-started/authentication/#create-an-api-key). |
| model | string | The default ASR model to use. |
| language | string | The default ASR language to use. |
| sensitivity_level | float | The default VAD sensitivity level, between 0.0 and 1.0. |
| plaintext_results | boolean | If `true`, then results in a `RECOGNITION-COMPLETE` message will be in plain text instead of the standard [NLSML](https://tools.ietf.org/html/rfc6787#section-6.3.1). Note that this does not conform to the MRCP specification, but it can be convenient for testing and development. |

The following [vendor-specific
parameters](https://tools.ietf.org/html/rfc6787#section-6.2.16) are
supported in a `RECOGNIZE` or `SET-PARAMS` message. In cases where a
parameter can specified both here and in the plugin config, the
parameters here take precedence.

| name | value | description |
| ---  | ---   | ---
| com.deepgram.model | string | The ASR model to use. |
| com.deepgram.ner | bool | Enable/disable named entity recognition. |
| com.deepgram.numerals | bool | Enable/disable the numerals feature. |
| com.deepgram.no_delay | bool | Enable/disable the `no_delay` flag. |
| com.deepgram.plugin | string | Configure a plugin. Multiple plugins can be given, separated by commas. |
| com.deepgram.keywords | string | Boost keywords. Multiple keywords can be given, separated by commas. |
| com.deepgram.keyword_boost | string | Specify either `standard` or `legacy` keyword boosting strategy. |

## Building

A Dockerfile is provided that will download and build UniMRCP and its
dependencies, as well as build the server plugin. This is used by
GitHub Actions to build the plugin for releases.

The build environment itself downloads UniMRCP from its package
repo. In order to access the package repo, you need credentials, which
can be acquired from the [UniMRCP website]. These credentials must be
passed to the Docker build environment:

[UniMRCP website]: https://unimrcp.org/profile-registration

```bash
$ docker build \
    --build-arg UNIMRCP_USERNAME=your_unimrcp_username \
    --build-arg UNIMRCP_PASSWORD=your_unimrcp_password \
    -t dgmrcp \
    .
```

In order to extract the plugin, we need to create a container from the
image, and then copy the shared object out:

```bash
CONTAINER=$(docker create dgmrcp) \
  && docker cp $CONTAINER:/dgmrcp/target/release/libdgmrcp.so ./ \
  && docker rm $CONTAINER
```

> If there is a better way to extract a file from a Docker image
> without creating an intermediate container, please let us know!

## Development

While the Docker image can be used for local development, it may be
more convenient to work in a VM. A [Vagrantfile](./Vagrantfile) is
provided along with some Ansible roles to get you up and running. As
with the Docker image, you'll need credentials for the UniMRCP RPM
repository.

```bash
vagrant up

# If you edit the Ansible roles or if something fails during the initial setup:
vagrant provision

vagrant ssh
```

To get started with development, follow these steps:

1. Build the `dgmrcp` plugin in the shared folder that is mounted in
   the VM, and copy or symlink it into the UniMRCP plugin directory.

```bash
cd /vagrant
cargo build

sudo mkdir /opt/unimrcp/plugin
ln -s /vagrant/target/debug/libdgmrcp.so /opt/unimrcp/plugin/
```

2. Edit the UniMRCP server config file at
   `/opt/unimrcp/conf/unimrcpserver.xml`, and add the `dgmrcp` plugin
   to the `<plugin-factory>` section as described above.

3. Run the UniMRCP server.

```bash
cd /opt/unimrcp/bin
./unimrcpserver
```

4. Run the UniMRCP client CLI and send a test request. UniMRCP
   includes two clients, `unimrcpclient` and `umc`, which have similar
   but maybe slightly different features. Their source code is found
   [here](https://github.com/unispeech/unimrcp/tree/master/platforms).

```bash
cd /opt/unimrcp/bin
./unimrcpclient
> run recog
```

If all goes well, both the client and the server should show logs
that, among other messages, include a `RECOGNIZE` and
`RECOGNITION-COMPLETE` message. If this doesn't work or if these
instructions are unclear, please [open an issue] or a PR!

[open an issue]: https://github.com/deepgram/dgmrcp/issues

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
