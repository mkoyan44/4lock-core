#!/bin/sh
# Generate CA certificate if it doesn't exist
# Runs in alpine utility container with openssl

# Since container stdout/stderr are redirected to /dev/null, write directly to mounted output files
OUTPUT_DIR="/tmp/utility-output"
STDOUT_FILE="$OUTPUT_DIR/stdout.log"
STDERR_FILE="$OUTPUT_DIR/stderr.log"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR" 2>/dev/null || true

# Function to log to file (since stdout/stderr go to /dev/null)
log() {
    echo "$1" >> "$STDOUT_FILE" 2>/dev/null || true
}

log_error() {
    echo "$1" >> "$STDERR_FILE" 2>/dev/null || true
}

# Test if we can write to output files
log "=== CA Generation Script Started ==="
log "Script path: $0"
log "Working directory: $(pwd 2>&1)"
log "User: $(id 2>&1)"
log "Output dir exists: $(test -d \"$OUTPUT_DIR\" && echo 'yes' || echo 'no')"
log "Can write to stdout: $(echo 'test' >> \"$STDOUT_FILE\" 2>&1 && echo 'yes' || echo 'no')"

CA_DIR="/output/ca"
log "CA directory: $CA_DIR"
mkdir -p "$CA_DIR" || {
    log_error "ERROR: Failed to create CA directory"
    exit 1
}

if [ -f "$CA_DIR/ca.pem" ] && [ -f "$CA_DIR/ca.key" ]; then
    log "CA already exists, skipping generation"
    exit 0
fi

log "Checking for openssl..."
if ! command -v openssl >/dev/null 2>&1; then
    log "openssl not found, installing via apt..."
    # Update package index and install openssl (non-interactive, no cache)
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get update -qq >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
        log_error "ERROR: Failed to update apt package index"
        exit 1
    fi
    if ! apt-get install -y -qq openssl >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
        log_error "ERROR: Failed to install openssl"
        exit 1
    fi
    log "openssl installed successfully"
else
    log "openssl found: $(command -v openssl)"
fi

log "Generating CA private key..."
if ! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$CA_DIR/ca.key" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
    log_error "ERROR: openssl genpkey failed"
    exit 1
fi
if [ ! -f "$CA_DIR/ca.key" ]; then
    log_error "ERROR: Failed to create CA key file"
    ls -la "$CA_DIR" >> "$STDERR_FILE" 2>&1 || true
    exit 1
fi
log "CA key created: $CA_DIR/ca.key"

log "Generating CA certificate..."
# Create a minimal OpenSSL config to avoid relying on system openssl.cnf
CONF_FILE="$OUTPUT_DIR/openssl.cnf"
cat > "$CONF_FILE" <<'EOF'
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = 4lock-kubernetes-ca
O = 4lock

[ v3_req ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

if ! openssl req -x509 -new -nodes -sha256 \
    -key "$CA_DIR/ca.key" \
    -days 3650 \
    -out "$CA_DIR/ca.pem" \
    -config "$CONF_FILE" \
    -extensions v3_req \
    -subj "/CN=4lock-kubernetes-ca/O=4lock" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
    log_error "ERROR: openssl req failed"
    exit 1
fi
if [ ! -f "$CA_DIR/ca.pem" ]; then
    log_error "ERROR: Failed to create CA certificate file"
    ls -la "$CA_DIR" >> "$STDERR_FILE" 2>&1 || true
    exit 1
fi
log "CA certificate created: $CA_DIR/ca.pem"

chmod 600 "$CA_DIR/ca.key" 2>> "$STDERR_FILE" || true
chmod 644 "$CA_DIR/ca.pem" 2>> "$STDERR_FILE" || true

# Verify files exist and are readable
if [ ! -f "$CA_DIR/ca.pem" ] || [ ! -f "$CA_DIR/ca.key" ]; then
    log_error "ERROR: CA files not found after generation"
    ls -la "$CA_DIR" >> "$STDERR_FILE" 2>&1 || true
    exit 1
fi

log "CA certificate generated successfully"
ls -la "$CA_DIR" >> "$STDOUT_FILE" 2>&1 || true
log "=== CA Generation Script Completed ==="

