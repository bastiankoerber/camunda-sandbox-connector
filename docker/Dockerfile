# Camunda Sandbox CLI Connector - Multi-stage Dockerfile
# Builds a secure container with nsjail for CLI command sandboxing

# =============================================================================
# Stage 1: Build the application
# =============================================================================
FROM maven:3.9-eclipse-temurin-21-alpine AS builder

WORKDIR /build

# Copy POM files first for dependency caching
COPY pom.xml ./
COPY connector-core/pom.xml ./connector-core/

# Download dependencies (cached layer)
RUN mvn dependency:go-offline -B

# Copy source code
COPY connector-core/src ./connector-core/src

# Build the application
RUN mvn clean package -DskipTests -B

# =============================================================================
# Stage 2: Build nsjail from source
# =============================================================================
# Use Ubuntu jammy to match runtime's protobuf version (libprotobuf23 = 3.12.x)
FROM ubuntu:jammy AS nsjail-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    pkg-config \
    libprotobuf-dev \
    protobuf-compiler \
    libnl-3-dev \
    libnl-route-3-dev \
    libcap-dev \
    libseccomp-dev \
    flex \
    bison \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone and build nsjail
RUN git clone --depth 1 --branch 3.4 https://github.com/google/nsjail.git /nsjail \
    && cd /nsjail \
    && make -j$(nproc) \
    && strip nsjail

# =============================================================================
# Stage 3: Create minimal rootfs for sandbox
# =============================================================================
# Use Ubuntu jammy for consistency with nsjail-builder
FROM ubuntu:jammy AS rootfs-builder

# Install tools that will be available inside the sandbox
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    coreutils \
    bash \
    # Text processing
    grep \
    sed \
    gawk \
    # JSON/YAML processing
    jq \
    # Networking (optional)
    curl \
    ca-certificates \
    # Python (optional)
    python3 \
    python3-pip \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# Create a minimal rootfs structure that preserves FHS paths for Python
# Python looks for libraries at /usr/lib/python3.10 inside the chroot
# /workspace is the mount point for script files inside the sandbox
RUN mkdir -p /rootfs/bin /rootfs/lib /rootfs/lib64 /rootfs/usr/lib /rootfs/usr/bin \
    /rootfs/etc /rootfs/tmp /rootfs/dev /rootfs/proc /rootfs/workspace \
    && cp -a /bin/* /rootfs/bin/ || true \
    && cp -a /usr/bin/* /rootfs/usr/bin/ || true \
    && ln -sf /usr/bin/python3.10 /rootfs/bin/python3.10 \
    && ln -sf /usr/bin/python3 /rootfs/bin/python3 \
    && cp -a /lib/* /rootfs/lib/ || true \
    && cp -a /lib64/* /rootfs/lib64/ || true \
    && cp -a /usr/lib/* /rootfs/usr/lib/ || true \
    && cp /etc/passwd /rootfs/etc/ \
    && cp /etc/group /rootfs/etc/ \
    && cp -a /etc/ssl /rootfs/etc/ || true \
    && touch /rootfs/etc/resolv.conf \
    && chmod 1777 /rootfs/tmp

# Copy security wrapper scripts for interpreters
COPY docker/wrappers/safe-python3 /rootfs/bin/safe-python3
RUN chmod 755 /rootfs/bin/safe-python3

# =============================================================================
# Stage 4: Runtime image
# =============================================================================
# CRITICAL: Must use Ubuntu jammy to match nsjail-builder's protobuf version
# nsjail is linked against libprotobuf.so.23 (protobuf 3.12.x from jammy)
FROM eclipse-temurin:21-jre-jammy AS runtime

# Security hardening labels
LABEL org.opencontainers.image.title="Camunda Sandbox CLI Connector" \
      org.opencontainers.image.description="Secure CLI command execution in sandboxed environments" \
      org.opencontainers.image.vendor="Camunda" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="Apache-2.0"

# Install runtime dependencies for nsjail (must match Ubuntu jammy build environment)
# libprotobuf23 is the correct version for Ubuntu 22.04 (jammy)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libprotobuf23 \
    libnl-3-200 \
    libnl-route-3-200 \
    libcap2 \
    libseccomp2 \
    tini \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 sandbox \
    && useradd -u 1000 -g sandbox -m sandbox

# Create directory structure
RUN mkdir -p /app /sandbox/workspaces /sandbox/tools /sandbox/rootfs \
    /sandbox/seccomp /sandbox/nsjail /config \
    /var/log/sandbox-connector \
    && chown -R sandbox:sandbox /sandbox /var/log/sandbox-connector

# Copy nsjail binary
COPY --from=nsjail-builder /nsjail/nsjail /usr/bin/nsjail
RUN chmod 755 /usr/bin/nsjail

# Copy minimal rootfs
COPY --from=rootfs-builder /rootfs /sandbox/rootfs

# Copy the application JAR
COPY --from=builder /build/connector-core/target/*.jar /app/connector.jar

# Copy configuration files
COPY connector-core/src/main/resources/seccomp/* /sandbox/seccomp/
COPY connector-core/src/main/resources/nsjail/* /sandbox/nsjail/
COPY connector-core/src/main/resources/tools/registry.yaml /config/tools-registry.yaml
COPY connector-core/src/main/resources/tenant/policies.yaml /config/tenant-policies.yaml

# Set proper permissions
RUN chown -R sandbox:sandbox /app /config \
    && chmod 644 /sandbox/seccomp/* /sandbox/nsjail/* /config/*

# Security hardening
# - Drop all capabilities except what's needed for nsjail
# - Run as non-root user
ENV JAVA_OPTS="-XX:+UseContainerSupport \
    -XX:MaxRAMPercentage=75.0 \
    -Djava.security.egd=file:/dev/./urandom \
    -Dspring.profiles.active=production"

# Application configuration
ENV SANDBOX_NSJAIL_PATH=/usr/bin/nsjail \
    SANDBOX_WORKSPACE_BASE=/sandbox/workspaces \
    SANDBOX_TOOLS_DIRECTORY=/sandbox/tools \
    SANDBOX_SECCOMP_PROFILES_DIRECTORY=/sandbox/seccomp \
    SANDBOX_ROOTFS=/sandbox/rootfs \
    SANDBOX_TENANT_POLICIES_PATH=/config/tenant-policies.yaml \
    SANDBOX_TOOL_REGISTRY_PATH=/config/tools-registry.yaml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget -q --spider http://localhost:8081/actuator/health || exit 1

# Use tini as init system (installed via apt on Debian)
ENTRYPOINT ["/usr/bin/tini", "--"]

# Run as non-root user
USER sandbox

# Expose connector port
EXPOSE 8080

# Start the application
CMD ["sh", "-c", "java $JAVA_OPTS -jar /app/connector.jar"]
