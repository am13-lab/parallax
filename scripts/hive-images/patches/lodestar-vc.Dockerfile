# lodestar-vc: same shebang fix as the BN image.
ARG BASE=hive/clients/lodestar-vc:local
FROM ${BASE}
RUN sed -i "1s|.*|#!/bin/bash|" /lodestar_vc.sh
