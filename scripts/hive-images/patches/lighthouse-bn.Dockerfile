# lighthouse-bn: the enr-auto-update flag rejects `=true`; the BN entry
# expects deposit_contract_block.txt which upstream never writes; and the
# default inbound rate limiter blackholes the probe after the hostile
# (length bomb / exhaustion) cases, so disable it for differential runs.
ARG BASE=hive/clients/lighthouse-bn:local
FROM ${BASE}
RUN sed -i "s/--disable-enr-auto-update=true/--disable-enr-auto-update/" /lighthouse_bn.sh && \
    sed -i 's|--disable-enr-auto-update  \\|--disable-enr-auto-update \\\n    --disable-inbound-rate-limiter \\|' /lighthouse_bn.sh && \
    sed -i 's|echo "${HIVE_ETH2_DEPOSIT_DEPLOY_BLOCK_NUMBER:-0}" > /data/testnet_setup/deploy_block.txt|echo "${HIVE_ETH2_DEPOSIT_DEPLOY_BLOCK_NUMBER:-0}" > /data/testnet_setup/deploy_block.txt \&\& cp /data/testnet_setup/deploy_block.txt /data/testnet_setup/deposit_contract_block.txt|' /lighthouse_bn.sh
