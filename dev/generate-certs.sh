#!/bin/bash
# generate-certs.sh

# Create certs directory
mkdir -p ../certs

# Install local CA
mkcert -install

# Copy root CA certificate
cp "$(mkcert -CAROOT)/rootCA.pem" certs/

# Generate certificate for mailpit
mkcert -cert-file ../certs/mailpit.pem -key-file ../certs/mailpit-key.pem \
    "mailpit" \
    "*.mailpit" \
    "localhost" \
    "172.20.0.3" \
    "smtp_test"

# Set permissions
chmod 644 ../certs/*.pem
