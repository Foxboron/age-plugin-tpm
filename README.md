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


# Usage

```bash
# Create indetity
$ age-plugin-tpm --generate
$ age-plugin-tpm --identity > age-identity.txt
$ age-plugin-tpm --list > age-recipient.txt

# Encrypt / Decrypt something
$ echo "Hack The Planet!" | age -R ./age-recipient.txt -o test-decrypt.txt
$ age --decrypt -i ./age-identity.txt -o - test-decrypt.txt
Hack The Planet!
```

## Commands

An age identity can be created with:

```
$ age-plugin-tpm --generate
# Handle: 0x81000004
# Created: 2023-04-29 14:14:37.191273186 +0200 CEST m=+0.326659927
# Recipient: age1tpm1syqqqpqrtxsnkkqlmu505zzrq439hetls4qwwmyhsv8dgjhksvtewvx29lxs7s68qy

AGE-PLUGIN-TPM-1QXQSQQQY2HCVDY

```

Recipients can be listed with:

```
$ age-plugin-tpm --list
# Handle: 0x81000004
# Created: 2023-04-29 14:14:37.191273186 +0200 CEST
age1tpm1syqqqpqrtxsnkkqlmu505zzrq439hetls4qwwmyhsv8dgjhksvtewvx29lxs7s68qy
```

Identities can be listed with:

```
$ age-plugin-tpm --identity
# Handle: 0x81000004
# Created: 2023-04-29 14:14:37.191273186 +0200 CEST
# Recipient: age1tpm1syqqqpqrtxsnkkqlmu505zzrq439hetls4qwwmyhsv8dgjhksvtewvx29lxs7s68qy

AGE-PLUGIN-TPM-1QXQSQQQY2HCVDY
```

To delete the key:

```
$ age-plugin-tpm --handle "0x81000004" --delete
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or http://opensource.org/licenses/MIT

