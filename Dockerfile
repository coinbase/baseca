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

# Deploy Image using Alpine Linux
FROM alpine:3.19

# Add a Non-Root User
RUN addgroup -S baseca && adduser -S baseca -G baseca && \
    mkdir -p /home/baseca/config && \
    chown -R baseca:baseca /home/baseca

# Install Required Dependencies
RUN apk --no-cache add ca-certificates && \
    rm -rf /var/cache/apk/*

# Copy Binary and Configuration from Build Image
COPY --from=builder /baseca/target/bin/linux/baseca /home/baseca/baseca
COPY --from=builder /baseca/config /home/baseca/config

# Set permissions for copied files
RUN chown -R baseca:baseca /home/baseca

# Switch to Non-Root User
USER baseca
WORKDIR /home/baseca

# Execute coinbase/baseca
CMD ["/home/baseca/baseca"]