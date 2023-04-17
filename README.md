# TPM plugin for age clients

`age-plugin-tpm` is a plugin for [age](https://age-encryption.org/v1) clients
like [`age`](https://age-encryption.org) and [`rage`](https://str4d.xyz/rage),
which enables files to be encrypted to age identities stored on YubiKeys.

# Experimental

The identity format and technical details might change between iterations.
Consider this plugin experimental.

Insteal of utilizing the TPM directly, you can use `--swtpm` or `export
AGE_PLUGIN_TPM_SWTPM=1` to create a identity backed by
[swtpm](https://github.com/stefanberger/swtpm) which will be stored under
`/var/tmp/age-plugin-tpm`.

Note that `swtpm` provides no security properties and should only be used for
testing.

## Installation

The simplest, and currently only way, of installing this plugin is by running
the follow go command.

`go install github.com/Foxboron/age-plugin-tpm@latest`

## Usage

An age identity can be created with:

```
$ age-plugin-tpm --generate
# Handle: 0x81000004
# Created: 2023-04-17 21:33:27.875945823 +0200 CEST m=+0.962292740
# Recipient: age1tpm1syqqqpqqqqqqqqqpqqqm84d7lunxz4thkj4vmmx28j4qnpznkl0rp6q7p2v8d7v9nae4347jr56ehr6xax4qs8xfk93al4zy4nxvx0hdqgucs2l392h6a5wfrqz9kwkxm5ycey8je0mzt5arv4m3xv2uwxdtvhvq3uz6pfxcexe6udjc5c5nxq6as57reqfz5vqunjjln3js6hapqjg459tqulxggwj3z2rfjz3udrkpec9ycvwv6q8tu2648huktq07c5pan84rsrtc689gac82lhw5cn9uzf92u8wq30w4ws8h3srmla5vrlf7f7h6k66f2ypjunff7xggns993225s9gdagrr6sa2qk5vp5ksrqz5td5ceer7705ajxc8pfdc4kdwufcp6qlkzm2mqcuqfwtmze2j7ewdg25rfapg7l0jh8v

AGE-PLUGIN-TPM-1QXQSQQQY2HCVDY
```

Recipients can be listed with:

```
$ age-plugin-tpm --list
# Handle: 0x81000004
# Created: 2023-04-17 21:33:27.875945823 +0200 CEST

age1tpm1syqqqpqqqqqqqqqpqqqm84d7lunxz4thkj4vmmx28j4qnpznkl0rp6q7p2v8d7v9nae4347jr56ehr6xax4qs8xfk93al4zy4nxvx0hdqgucs2l392h6a5wfrqz9kwkxm5ycey8je0mzt5arv4m3xv2uwxdtvhvq3uz6pfxcexe6udjc5c5nxq6as57reqfz5vqunjjln3js6hapqjg459tqulxggwj3z2rfjz3udrkpec9ycvwv6q8tu2648huktq07c5pan84rsrtc689gac82lhw5cn9uzf92u8wq30w4ws8h3srmla5vrlf7f7h6k66f2ypjunff7xggns993225s9gdagrr6sa2qk5vp5ksrqz5td5ceer7705ajxc8pfdc4kdwufcp6qlkzm2mqcuqfwtmze2j7ewdg25rfapg7l0jh8v
```

Identities can be listed with:

```
$ age-plugin-tpm --identity
# Handle: 0x81000004
# Created: 2023-04-17 21:33:27.875945823 +0200 CEST
# Recipient: age1tpm1syqqqpqqqqqqqqqpqqqm84d7lunxz4thkj4vmmx28j4qnpznkl0rp6q7p2v8d7v9nae4347jr56ehr6xax4qs8xfk93al4zy4nxvx0hdqgucs2l392h6a5wfrqz9kwkxm5ycey8je0mzt5arv4m3xv2uwxdtvhvq3uz6pfxcexe6udjc5c5nxq6as57reqfz5vqunjjln3js6hapqjg459tqulxggwj3z2rfjz3udrkpec9ycvwv6q8tu2648huktq07c5pan84rsrtc689gac82lhw5cn9uzf92u8wq30w4ws8h3srmla5vrlf7f7h6k66f2ypjunff7xggns993225s9gdagrr6sa2qk5vp5ksrqz5td5ceer7705ajxc8pfdc4kdwufcp6qlkzm2mqcuqfwtmze2j7ewdg25rfapg7l0jh8v

AGE-PLUGIN-TPM-1QXQSQQQY2HCVDY
```

To delete the key:

```
$ age-plugin-tpm --handle "0x81000004" --delete
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or http://opensource.org/licenses/MIT

