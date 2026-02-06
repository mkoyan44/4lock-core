#!/bin/sh
# Generate Kubernetes API server and component certificates
# Runs in alpine utility container with openssl
# Template variables: {{ instance_id }}, {{ service_cidr }}

set -e

# Logging setup - output to utility-output directory for capture by utility runner
UTILITY_OUTPUT_DIR="/tmp/utility-output"
STDOUT_FILE="$UTILITY_OUTPUT_DIR/stdout.log"
STDERR_FILE="$UTILITY_OUTPUT_DIR/stderr.log"

# Create output directory if it doesn't exist
mkdir -p "$UTILITY_OUTPUT_DIR" 2>/dev/null || true

# Function to log to file (since stdout/stderr are redirected by utility runner)
log() {
    echo "$1" >> "$STDOUT_FILE" 2>/dev/null || true
}

log_error() {
    echo "$1" >> "$STDERR_FILE" 2>/dev/null || true
}

log "=== Certificate Generation Script Started ==="
log "Script path: $0"
log "Working directory: $(pwd 2>&1)"
log "User: $(id 2>&1)"

INSTANCE_ID="{{ instance_id }}"
SERVICE_CIDR="{{ service_cidr }}"
CERT_LIFETIME_DAYS=3650
RSA_KEY_SIZE=2048

CA_DIR="/input/ca"
OUTPUT_DIR="/output/kubernetes"
ETCD_DIR="/output/etcd"

log "CA directory: $CA_DIR"
log "Kubernetes certificates directory: $OUTPUT_DIR"
log "etcd certificates directory: $ETCD_DIR"

mkdir -p "$OUTPUT_DIR" "$ETCD_DIR" || {
    log_error "ERROR: Failed to create output directories"
    exit 1
}

# Calculate K8s service IP (first IP in service CIDR + 1)
K8S_SERVICE_IP=$(echo "$SERVICE_CIDR" | awk -F'[./]' '{print $1"."$2"."$3"."($4+1)}')
log "K8s service IP: $K8S_SERVICE_IP"

# Function to create server certificate with SANs
create_server_cert() {
    local cert_name="$1"
    local cert_subject="$2"
    local sans="$3"
    local output_dir="$4"

    local key_file="$output_dir/${cert_name}.key"
    local cert_file="$output_dir/${cert_name}.crt"
    local config_file="$output_dir/${cert_name}.cnf"
    local csr_file="$output_dir/${cert_name}.csr"

    log "Creating server certificate: $cert_name"

    if [ ! -f "$key_file" ]; then
        log "Generating private key for $cert_name..."
        if ! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$RSA_KEY_SIZE -out "$key_file" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
            log_error "ERROR: Failed to generate private key for $cert_name"
            return 1
        fi
        chmod 640 "$key_file" 2>> "$STDERR_FILE" || true
    else
        log "Private key already exists for $cert_name, skipping generation"
    fi

    cat > "$config_file" <<EOF
[req]
req_extensions = v3_req
distinguished_name = dn
[dn]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
$sans
EOF

    log "Creating CSR for $cert_name..."
    if ! openssl req -new -key "$key_file" -subj "$cert_subject" \
        -out "$csr_file" -config "$config_file" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
        log_error "ERROR: Failed to create CSR for $cert_name"
        rm -f "$csr_file" "$config_file"
        return 1
    fi

    log "Signing certificate for $cert_name..."
    if openssl x509 -req -in "$csr_file" \
        -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$cert_file" -days $CERT_LIFETIME_DAYS \
        -extensions v3_req -extfile "$config_file" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
        chmod 644 "$cert_file" 2>> "$STDERR_FILE" || true
        log "Generated $cert_name server cert"
        echo "Generated $cert_name server cert"
    else
        log_error "ERROR: Failed to generate $cert_name server cert"
        echo "ERROR: Failed to generate $cert_name server cert"
        rm -f "$csr_file" "$config_file"
        return 1
    fi

    rm -f "$csr_file" "$config_file"
}

# Function to create client certificate
create_client_cert() {
    local cert_name="$1"
    local cert_subject="$2"
    local output_dir="$3"

    local key_file="$output_dir/${cert_name}.key"
    local cert_file="$output_dir/${cert_name}.crt"
    local csr_file="$output_dir/${cert_name}.csr"
    local config_file="$output_dir/${cert_name}.cnf"

    log "Creating client certificate: $cert_name"

    if [ ! -f "$key_file" ]; then
        log "Generating private key for $cert_name..."
        if ! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$RSA_KEY_SIZE -out "$key_file" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
            log_error "ERROR: Failed to generate private key for $cert_name"
            return 1
        fi
        chmod 640 "$key_file" 2>> "$STDERR_FILE" || true
    else
        log "Private key already exists for $cert_name, skipping generation"
    fi

    # Create OpenSSL config file with v3 extensions to ensure X.509 v3 format
    cat > "$config_file" <<EOF
[req]
req_extensions = v3_req
distinguished_name = dn
prompt = no
[dn]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

    log "Creating CSR for $cert_name..."
    if ! openssl req -new -key "$key_file" -subj "$cert_subject" \
        -out "$csr_file" -config "$config_file" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
        log_error "ERROR: Failed to create CSR for $cert_name"
        rm -f "$csr_file" "$config_file"
        return 1
    fi

    local ca_cert_file ca_key_file
    if [ -f "$CA_DIR/ca.pem" ] && [ -f "$CA_DIR/ca.key" ]; then
        ca_cert_file="$CA_DIR/ca.pem"
        ca_key_file="$CA_DIR/ca.key"
        log "Using CA certificate: $ca_cert_file"
    else
        log_error "ERROR: CA certificate files not found in $CA_DIR"
        echo "ERROR: CA certificate files not found in $CA_DIR"
        rm -f "$csr_file"
        return 1
    fi

    log "Signing certificate for $cert_name..."
    if openssl x509 -req -in "$csr_file" \
        -CA "$ca_cert_file" -CAkey "$ca_key_file" -CAcreateserial \
        -out "$cert_file" -days $CERT_LIFETIME_DAYS \
        -extensions v3_req -extfile "$config_file" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
        chmod 644 "$cert_file" 2>> "$STDERR_FILE" || true
        log "Generated $cert_name client cert"
        echo "Generated $cert_name client cert"
    else
        log_error "ERROR: Failed to generate $cert_name client cert"
        echo "ERROR: Failed to generate $cert_name client cert"
        rm -f "$csr_file" "$config_file"
        return 1
    fi

    rm -f "$csr_file" "$config_file"
}

# Generate Kubernetes certificates
log "=== Generating Kubernetes certificates ==="
apiserver_sans="DNS.1 = kubernetes
DNS.2 = kubernetes.default
DNS.3 = kubernetes.default.svc
DNS.4 = kubernetes.default.svc.cluster.local
DNS.5 = localhost
DNS.6 = $INSTANCE_ID
IP.1 = $K8S_SERVICE_IP
IP.2 = 127.0.0.1
IP.3 = 10.0.2.2"

create_server_cert "kube-apiserver" "/CN=kube-apiserver/O=Kubernetes" "$apiserver_sans" "$OUTPUT_DIR" || {
    log_error "ERROR: Failed to generate kube-apiserver certificate"
    exit 1
}
create_client_cert "apiserver-kubelet-client" "/CN=kube-apiserver-kubelet-client/O=system:masters" "$OUTPUT_DIR" || {
    log_error "ERROR: Failed to generate apiserver-kubelet-client certificate"
    exit 1
}

kubelet_sans="DNS.1 = $INSTANCE_ID
DNS.2 = localhost
IP.1 = $K8S_SERVICE_IP
IP.2 = 127.0.0.1
IP.3 = 10.0.2.2"

create_server_cert "kubelet" "/CN=system:node:$INSTANCE_ID/O=system:nodes" "$kubelet_sans" "$OUTPUT_DIR" || {
    log_error "ERROR: Failed to generate kubelet certificate"
    exit 1
}
create_client_cert "admin" "/CN=admin/O=system:masters" "$OUTPUT_DIR" || {
    log_error "ERROR: Failed to generate admin certificate"
    exit 1
}
create_client_cert "controller-manager" "/CN=system:kube-controller-manager/O=system:kube-controller-manager" "$OUTPUT_DIR" || {
    log_error "ERROR: Failed to generate controller-manager certificate"
    exit 1
}
create_client_cert "scheduler" "/CN=system:kube-scheduler/O=system:kube-scheduler" "$OUTPUT_DIR" || {
    log_error "ERROR: Failed to generate scheduler certificate"
    exit 1
}
create_client_cert "front-proxy-client" "/CN=front-proxy-client/O=Kubernetes" "$OUTPUT_DIR" || {
    log_error "ERROR: Failed to generate front-proxy-client certificate"
    exit 1
}
create_client_cert "kube-proxy" "/CN=system:kube-proxy/O=system:node-proxier" "$OUTPUT_DIR" || {
    log_error "ERROR: Failed to generate kube-proxy certificate"
    exit 1
}

# Generate service account keypair
log "Generating service account keypair..."
if ! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$RSA_KEY_SIZE -out "$OUTPUT_DIR/service-account.key" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
    log_error "ERROR: Failed to generate service account private key"
    exit 1
fi
if ! openssl rsa -in "$OUTPUT_DIR/service-account.key" -pubout -out "$OUTPUT_DIR/service-account.pub" >> "$STDOUT_FILE" 2>> "$STDERR_FILE"; then
    log_error "ERROR: Failed to generate service account public key"
    exit 1
fi
chmod 640 "$OUTPUT_DIR/service-account.key" 2>> "$STDERR_FILE" || true
chmod 644 "$OUTPUT_DIR/service-account.pub" 2>> "$STDERR_FILE" || true
log "Generated service-account keypair"
echo "Generated service-account keypair"

# ======================
# ETCD CERTIFICATES
# ======================
log "=== Generating etcd certificates ==="
echo "=== Generating etcd certificates ==="

etcd_sans="DNS.1 = localhost
DNS.2 = $INSTANCE_ID
IP.1 = $K8S_SERVICE_IP
IP.2 = 127.0.0.1
IP.3 = 10.0.2.2"

create_server_cert "etcd-server" "/CN=etcd/O=etcd" "$etcd_sans" "$ETCD_DIR" || {
    log_error "ERROR: Failed to generate etcd-server certificate"
    exit 1
}
create_client_cert "etcd-peer" "/CN=etcd/O=etcd" "$ETCD_DIR" || {
    log_error "ERROR: Failed to generate etcd-peer certificate"
    exit 1
}
create_client_cert "etcd-healthcheck-client" "/CN=kube-etcd-healthcheck-client/O=system:masters" "$ETCD_DIR" || {
    log_error "ERROR: Failed to generate etcd-healthcheck-client certificate"
    exit 1
}
create_client_cert "apiserver-etcd-client" "/CN=kube-apiserver-etcd-client/O=system:masters" "$ETCD_DIR" || {
    log_error "ERROR: Failed to generate apiserver-etcd-client certificate"
    exit 1
}

log "Certificate generation completed!"
log "CA certificates location: $CA_DIR"
log "Kubernetes certificates: $OUTPUT_DIR"
log "etcd certificates: $ETCD_DIR"
echo "Certificate generation completed!"
echo "CA certificates location: $CA_DIR"
echo "Kubernetes certificates: $OUTPUT_DIR"
echo "etcd certificates: $ETCD_DIR"

