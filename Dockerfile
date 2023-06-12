# Build Image
FROM golang:1.20 as builder

ENV CGO_ENABLED=0
WORKDIR /baseca
COPY . /baseca
RUN apt update && apt clean && make build

# Deploy Image
FROM alpine:3.17

RUN adduser --home /home/baseca baseca --gecos "baseca" --disabled-password && \
    apk --no-cache add ca-certificates && \
    rm -rf /var/cache/apk/*

COPY --from=builder /baseca/target/bin/linux/baseca /home/baseca/baseca
COPY --from=builder /baseca/internal/authorization/casbin /home/baseca/internal/authorization/casbin
COPY --from=builder /baseca/internal/attestor/aws_iid/certificate /home/baseca/internal/attestor/aws_iid/certificate

RUN chown -R baseca:baseca /home/baseca

USER baseca
WORKDIR /home/baseca

CMD ["/home/baseca/baseca"]