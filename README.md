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
$ age-plugin-tpm --generate -o age-identity.txt
# Created: 2023-07-05 22:38:36.362043774 +0200 CEST m=+0.110154231
# Recipient: age1tpm1qg86fn5esp30u9h6jy6zvu9gcsvnac09vn8jzjxt8s3qtlcv5h2x287wm36

AGE-PLUGIN-TPM-1QYQSQLSQYZJN56KJ4WHGP676AW248W7Z3KE7JRP8HWGGTW98CX955U9NCV4G2QQS828ZMZNQLLC57QU037ELMLA0RR56SM35HLJAFHKY0EH7J62SYJLX3YFULEE7AQJR0DJX7D33HRKWRYHNXFN0TRS45MKUHZGRU3K3EPRUSGSWWV07K2PKTFF79YVACDZSVEKAYY4GEAM6DRNQQPTQQGCQPVQQYQRJQQQQQYQQZQQQXQQSQQSQLFXWNXQX9LSKL2GNGFNS4RZPJ0HPU4JV7G2GEV7ZYP0LPJJAGEGQYQE8GSEC0GWWDVKAFT04QTJWCU3T2KYVXGER35FVMHEY0ZDGEHC4C0EXJ8Y
```

To display the recipient of a given identity:

```
$ age-plugin-tpm -y age-identity.txt
age1tpm1qg86fn5esp30u9h6jy6zvu9gcsvnac09vn8jzjxt8s3qtlcv5h2x287wm36
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or http://opensource.org/licenses/MIT
