# hive simulator image: builds the beacon-p2p simulator binary.
FROM golang:1.25-alpine AS builder
RUN apk --no-cache add gcc musl-dev linux-headers git
ADD . /source
WORKDIR /source
RUN go build -o /hive-sim .

FROM alpine:latest
COPY --from=builder /hive-sim /hive-sim
ENTRYPOINT ["/hive-sim"]
