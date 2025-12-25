TPM plugin for age clients
==========================

`age-plugin-tpm` is a plugin for [age](https://age-encryption.org/v1) clients
like [`age`](https://age-encryption.org) and [`rage`](https://str4d.xyz/rage),
which enables files to be encrypted to age identities sealed by the TPM.

# Features

* Keys created on the TPM, sealed outside of it
* PIN support
* TPM session encryption

## Installation

The simplest way of installing this plugin is by running the follow go command.

`go install github.com/foxboron/age-plugin-tpm/cmd/age-plugin-tpm@latest`

Alternatively download the [pre-built binaries](https://github.com/foxboron/age-plugin-tpm/releases).

# Usage

```bash
# Create identity
$ age-plugin-tpm --generate -o age-identity.txt
$ age-plugin-tpm -y age-identity.txt > age-recipient.txt

# Encrypt / Decrypt something
$ echo 'Hack The Planet!' | age -R age-recipient.txt -o test-decrypt.txt
$ age --decrypt -i age-identity.txt -o - test-decrypt.txt
Hack The Planet!
```

You can add `--pin` when calling `--generate` to require a PIN when encrypting or decrypting.

### When used non-interactively

If you want to use a `--pin` non-interactively, you can use the `AGE_TPM_PIN` environment variable.
Please be aware that environment variables are not secure, and can be read from `/proc/$PID/environ`.

```bash
# Create identity
$ AGE_TPM_PIN=1234 age-plugin-tpm --generate --pin -o age-identity.txt
$ age-plugin-tpm -y age-identity.txt > age-recipient.txt

# Encrypt / Decrypt something
$ echo 'Hack The Planet!' | age -R age-recipient.txt -o test-decrypt.txt
$ AGE_TPM_PIN=1234 age --decrypt -i age-identity.txt -o - test-decrypt.txt
Hack The Planet!
```

## Commands

An age identity can be created with:

```
$ age-plugin-tpm --generate -o - | tee age-identity.txt
# Created: 2025-12-25 01:54:45.690315451 +0100 CET m=+0.011592629
# Recipient: age1tag1q096edfp3ty6n36fj5kyq0yuesp7rdcmm7sjswzdcrekh6ash8n3uys987t

AGE-PLUGIN-TPM-1QGQQQKQQYVQQKQQZQPEQQQQQZQQPJQQTQQPSQYQQYR96EDFP3TY6N36FJ5KYQ0YUESP7RDCMM7SJSWZDCREKH6ASH8N3UQPQYE4FZAPQXA3HRLELET3KX2EDSWDRF2ET4DWMTN0AWMKHUPQ8EK8SQLSQYQYMY5ZVWQYDY5D7WZ0W6KEXDWNUAP00DEVQ76AJ7HVV85TWU0DFCQQS0DA7N7E8GN55U6E4G8ECFFNRTP7XJTHD440N3CZW6STXNWQGA89WF3NF3PEDPUAPC8AW5XNZW68E4QG7X85G2CM5TZDKAP2UZ9EEAAC5LQ0R9PJEX5280SG0U47HA09EAFQ6VSVX65HCGRGNQQ3QQZL5H2W3M34CMSTWMRXLR90YRDZPZKWGZK7H7E079KLCCSSVRLFMQYEY547R
```

To display the recipient of a given identity:

```
$ age-plugin-tpm -y age-identity.txt
age1tag1q096edfp3ty6n36fj5kyq0yuesp7rdcmm7sjswzdcrekh6ash8n3uys987t
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or http://opensource.org/licenses/MIT
