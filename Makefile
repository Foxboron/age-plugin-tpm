
all: build

build: age-plugin-tpm

age-plugin-tpm:
	go build -o age-plugin-tpm ./cmd/age-plugin-tpm

.PHONY: age-plugin-tpm

test:
	go test ./...

integ:
	go build ./cmd/age-plugin-tpm
	./age-plugin-tpm --swtpm -g -o age-identity.txt || true
	./age-plugin-tpm --swtpm -y age-identity.txt > age-recipient.txt
	echo "itworksitworksitworksitworksitworks" | AGE_PLUGIN_TPM_SWTPM=1 AGEDEBUG=plugin PATH="${PWD}:${PATH}" ../age/age -R ./age-recipient.txt -o test-decrypt.txt
	AGE_PLUGIN_TPM_SWTPM=1 AGEDEBUG=plugin PATH="${PWD}:${PATH}" ../age/age --decrypt -i ./age-identity.txt -o - test-decrypt.txt
	rm age-*.txt


check:
	staticcheck ./...

.PHONY: test
