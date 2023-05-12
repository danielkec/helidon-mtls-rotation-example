#!/bin/bash
set -e

source ./config.sh
source ./utils.sh

# Cleanup
rm -rf ./server ./client
mkdir -p server client

DISPLAY_NAME_PREFIX="mtls-test-6"

CDIR=$(pwd)

# Rotate server cert and key
cd ${CDIR}/server
genCertAndCSR server
NEW_SERVER_CERT_OCID=$(uploadNewCert server $DISPLAY_NAME_PREFIX)
prepareKeyToUpload server
NEW_SERVER_KEY_OCID=$(createKeyInVault server $DISPLAY_NAME_PREFIX)

# Rotate client cert and key
cd ${CDIR}/client
genCertAndCSR client
NEW_CLIENT_CERT_OCID=$(uploadNewCert client $DISPLAY_NAME_PREFIX)
prepareKeyToUpload client
NEW_CLIENT_KEY_OCID=$(createKeyInVault client $DISPLAY_NAME_PREFIX)

echo "======= ALL done! ======="
echo "Newly created OCI resources:"
echo "Server certificate OCID: $NEW_SERVER_CERT_OCID"
echo "Server private key OCID: $NEW_SERVER_KEY_OCID"
echo "Client certificate OCID: $NEW_CLIENT_CERT_OCID"
echo "Client private key OCID: $NEW_CLIENT_KEY_OCID"
echo "Saving to gen-config.sh"
tee ${CDIR}/generated-config.sh << EOF
#!/bin/bash
## Content of this file gets rewritten by createKeys.sh
export SERVER_CERT_OCID=$NEW_SERVER_CERT_OCID
export SERVER_KEY_OCID=$NEW_SERVER_KEY_OCID

export CLIENT_CERT_OCID=$NEW_CLIENT_CERT_OCID
export CLIENT_KEY_OCID=$NEW_CLIENT_KEY_OCID
EOF