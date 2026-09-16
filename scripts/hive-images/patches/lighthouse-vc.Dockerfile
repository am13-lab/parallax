# lighthouse-vc: upstream /lighthouse_vc.sh never copies the beacon genesis
# state into the testnet dir, so `lighthouse validator` aborts with
# "Genesis state bytes missing from Eth2NetworkConfig". Also normalize the
# deposit-contract block filename the BN side expects.
ARG BASE=hive/clients/lighthouse-vc:local
FROM ${BASE}
RUN sed -i 's|cp /hive/input/config.yaml /data/testnet_setup|cp /hive/input/config.yaml /data/testnet_setup \&\& cp /hive/input/genesis.ssz /data/testnet_setup/|' /lighthouse_vc.sh && \
    sed -i 's|echo "${HIVE_ETH2_DEPOSIT_DEPLOY_BLOCK_NUMBER:-0}" > /data/testnet_setup/deploy_block.txt|echo "${HIVE_ETH2_DEPOSIT_DEPLOY_BLOCK_NUMBER:-0}" > /data/testnet_setup/deploy_block.txt \&\& cp /data/testnet_setup/deploy_block.txt /data/testnet_setup/deposit_contract_block.txt|' /lighthouse_vc.sh
