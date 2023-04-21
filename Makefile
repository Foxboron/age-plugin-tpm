test:
	go build ./cmd/age-plugin-tpm
	./age-plugin-tpm --swtpm -g
	./age-plugin-tpm --swtpm --identity > age-identity.txt
	./age-plugin-tpm --swtpm --list > age-recipient.txt
	echo "itworksitworksitworksitworksitworks" | AGE_PLUGIN_TPM_SWTPM=1 AGEDEBUG=plugin PATH="${PWD}:${PATH}" ../age/age -R ./age-recipient.txt -o test-decrypt.txt
	AGE_PLUGIN_TPM_SWTPM=1 AGEDEBUG=plugin PATH="${PWD}:${PATH}" ../age/age --decrypt -i ./age-identity.txt -o decrypted-output.txt test-decrypt.txt
	./age-plugin-tpm --swtpm --delete --handle 0x81000004
