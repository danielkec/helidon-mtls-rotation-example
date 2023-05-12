#!/bin/bash
set -e

source ./config.sh
source ./generated-config.sh
source ./utils.sh

# Cleanup
rm -rf ./server ./client
mkdir -p server client


CDIR=$(pwd)

# Rotate server cert and key
cd ${CDIR}/server
genCertAndCSR server
rotateCert server $SERVER_CERT_OCID
prepareKeyToUpload server
rotateKeyInVault server $SERVER_KEY_OCID

# Rotate client cert and key
cd ${CDIR}/client
genCertAndCSR client
rotateCert client $CLIENT_CERT_OCID
prepareKeyToUpload client
rotateKeyInVault client $CLIENT_KEY_OCID

echo "ALL done!"