# lodestar-bn: upstream ships the launcher with a broken shebang.
ARG BASE=hive/clients/lodestar-bn:local
FROM ${BASE}
RUN sed -i "1s|.*|#!/bin/bash|" /lodestar_bn.sh
