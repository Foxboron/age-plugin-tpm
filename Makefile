
all: build

build: age-plugin-tpm

age-plugin-tpm:
	go build -o age-plugin-tpm ./cmd/age-plugin-tpm

.PHONY: age-plugin-tpm

test:
	go test ./...

integ:
	go build ./cmd/age-plugin-tpm
	./age-plugin-tpm --swtpm --delete --handle 0x81000004 || true
	./age-plugin-tpm --swtpm -g
	./age-plugin-tpm --swtpm --identity > age-identity.txt
	./age-plugin-tpm --swtpm --list > age-recipient.txt
	echo "itworksitworksitworksitworksitworks" | AGE_PLUGIN_TPM_SWTPM=1 AGEDEBUG=plugin PATH="${PWD}:${PATH}" ../age/age -R ./age-recipient.txt -o test-decrypt.txt
	AGE_PLUGIN_TPM_SWTPM=1 AGEDEBUG=plugin PATH="${PWD}:${PATH}" ../age/age --decrypt -i ./age-identity.txt -o decrypted-output.txt test-decrypt.txt
	./age-plugin-tpm --swtpm --delete --handle 0x81000004


check:
	staticcheck ./...

.PHONY: test
