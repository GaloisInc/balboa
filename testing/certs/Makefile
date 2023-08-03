all:

clean:
	rm -f *.key *.pem *.crt *.csr *.srl *.der

%.key:
	openssl genrsa -out $@ 2048

rootCA.crt: rootCA.key
	openssl req -x509 -new -nodes -key $< -sha256 -days 3650 -subj "/C=US/ST=VA/O=Rocky Testing Cert DO NOT USE IN PRODUCTION" -out $@

%.csr: %.key
	openssl req -new -sha256 -key $< -subj "/C=US/ST=VA/O=Rocky Testing Cert DO NOT USE IN PRODUCTION/CN=$(patsubst %.key,%,$<)" -out $@

%.crt: %.csr rootCA.crt rootCA.key
	openssl x509 -req -in $< -CA rootCA.crt -CAcreateserial -CAkey rootCA.key -out $@ -days 3650 -sha256 || (rm -f $@ ; exit 1)

%.der: %.key
	openssl rsa -in $< -inform PEM -RSAPublicKey_out -outform DER -out $@

%.pem: %.key %.crt
	cat $^ > $@

.PRECIOUS: %.key %.crt %.der
.PHONY: all clean
