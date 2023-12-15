FROM golang:1.21 as builder

# Docker BuildX Target Architecture
ARG TARGETARCH

ENV CGO_ENABLED=0
WORKDIR /baseca
COPY . /baseca

# Build ARM64 or AMD64 Binary
RUN apt update && apt clean && \
    if [ "$TARGETARCH" = "amd64" ]; then \
        make build_amd64; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        make build_arm64; \
    else \
        echo "Unsupported Architecture [$TARGETARCH]"; \
        exit 1; \
    fi

# Deploy Image
FROM alpine:3.17

# Non-Root User
RUN adduser --home /home/baseca baseca --gecos "baseca" --disabled-password && \
    apk --no-cache add ca-certificates && \
    rm -rf /var/cache/apk/*

# Copy Binary and Configuration from Build Image
COPY --from=builder /baseca/target/bin/linux/baseca /home/baseca/baseca
COPY --from=builder /baseca/config /home/baseca/config

# Permissions for Non-Root User
RUN chown -R baseca:baseca /home/baseca

# Switch to Non-Root User
USER baseca
WORKDIR /home/baseca

# Execute coinbase/baseca
CMD ["/home/baseca/baseca"]
