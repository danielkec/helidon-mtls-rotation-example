#!/bin/bash
set -e

COMPARTMENT_OCID=ocid1.tenancy.oc1..aaaaaaaaonou3anbsghdg723hfoodyj3y6gmx3kqma5dcou4n2fh2setk6ta
VAULT_MANAGEMENT_ENDPOINT=https://bjqkhfbuaaaao-management.kms.eu-frankfurt-1.oraclecloud.com
CA_OCID=ocid1.certificateauthority.oc1.eu-frankfurt-1.amaaaaaarxor3daapterg4ao3r5xdsovhe6tcwxoo5rmukkzcjdupk52rq5a

SERVER_KEY_OCID=ocid1.key.oc1.eu-frankfurt-1.bjqkhfbuaaaao.abtheljt2wamixp4xbk7mhxvf2mq4us7bhdu7fm6dy4sfkh6w52kdzg6ltma
SERVER_CERT_OCID=ocid1.certificate.oc1.eu-frankfurt-1.amaaaaaarxor3daa4onn6cc72zfs72cpwy2ixtsfcfu6ect6hyi65yigo7ca;

CLIENT_KEY_OCID=ocid1.key.oc1.eu-frankfurt-1.bjqkhfbuaaaao.abtheljsnmfad52ttrxtpu35ac5foje7ddlzq7wbyv7ke23rhoqkfnza5epq
CLIENT_CERT_OCID=ocid1.certificate.oc1.eu-frankfurt-1.amaaaaaarxor3daa65nneicancdjusua4vet43hkhnsntp74womxre3td4uq;

# Cleanup
rm -rf ./server ./client
mkdir -p server client

source ./utils.sh

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