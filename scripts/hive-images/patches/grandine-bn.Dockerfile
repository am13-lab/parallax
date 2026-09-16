# grandine-bn: the BN needs xxd and chokes on the --features LogHttp* flags.
ARG BASE=hive/clients/grandine-bn:local
FROM ${BASE}
RUN apk add --no-cache xxd || true; sed -i "/--features /d" /grandine.sh
