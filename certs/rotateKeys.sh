#!/bin/bash
set -e

source ./config.sh
source ./utils.sh

# Cleanup
rm -rf ./server ./client
mkdir -p server client


CDIR=$(pwd)

# Rotate server cert and key
cd ${CDIR}/server
rotateCert server $SERVER_CERT_OCID
uploadKeyToVault server $SERVER_KEY_OCID

# Rotate client cert and key
cd ${CDIR}/client
rotateCert client $CLIENT_CERT_OCID
uploadKeyToVault client $CLIENT_KEY_OCID

echo "ALL done!"