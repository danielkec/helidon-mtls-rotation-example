# Helidon mTLS context rotation OCI example
Helidon mTLS context rotation with [OCI](https://www.oracle.com/cloud) [KMS](https://www.oracle.com/security/cloud-security/key-management) and [Certificates](https://www.oracle.com/security/cloud-security/ssl-tls-certificates) services

1. [Prerequisites](#prerequisites)  
2. [Setting up OCI](#setting-up-oci)
   1. [Configuration](#configuration) 
   2. [Prepare CA(Certification Authority)](#prepare-cacertification-authority)
   3. [Prepare keys and certificates](#prepare-keys-and-certificates)
3. [Configuration](#configuration)
4. [Rotating mTLS certificates](#rotating-mtls-certificates)
5. [Build and run example](#build-and-run-example)
   1. [Build & Run](#build--run)
   2. [Test with WebClient](#test-with-webclient)
   3. [Test with cURL](#test-with-curl)


## Prerequisites
- JDK 17 or higher
- Maven 3.6.1 or higher
- OCI Tenancy with Vault [KMS](https://www.oracle.com/security/cloud-security/key-management) and [Certificate service](https://www.oracle.com/security/cloud-security/ssl-tls-certificates) (all features used in the example are free of charge)
- [OCI CLI](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm#Quickstart) 3.2.1 or later with properly configured `~/.oci/config` to access your tenancy
- OpenSSL (on deb based distros `apt install openssl`) 
- [Keytool](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html) (comes with JDK installation)

## Setting up OCI
### Prepare CA(Certification Authority)
Follow [OCI documentation](https://docs.oracle.com/en-us/iaas/Content/certificates/managing-certificate-authorities.htm):
1. Create group `CertificateAuthorityAdmins` and add your user in it
2. Create dynamic group `CertificateAuthority-DG` with single rule `resource.type='certificateauthority'`
3. Create policy `CertificateAuthority-PL` with following statements:
    ```
    Allow dynamic-group CertificateAuthority-DG to use keys in tenancy
    Allow dynamic-group CertificateAuthority-DG to manage objects in tenancy
    Allow group CertificateAuthorityAdmins to manage certificate-authority-family in tenancy
    Allow group CertificateAuthorityAdmins to read keys in tenancy
    Allow group CertificateAuthorityAdmins to use key-delegate in tenancy
    Allow group CertificateAuthorityAdmins to read buckets in tenancy
    Allow group CertificateAuthorityAdmins to read vaults in tenancy
    ```
4. Create policy `Vaults-PL` with following statements:
    ```
    Allow group CertificateAuthorityAdmins to manage vaults in tenancy
    Allow group CertificateAuthorityAdmins to manage keys in tenancy
    Allow group CertificateAuthorityAdmins to manage secret-family in tenancy
    ```
5. Create or reuse OCI Vault and notice there are cryptographic and management endpoints in the vault general info, 
   we will need them later.
6. Create new key in the vault with following properties:
   - Name: `mySuperCAKey`
   - Protection Mode: **HSM** (requirement for CA keys, those can't be downloaded)
   - Algorithm: **RSA**
7. Create CA:
   1. In OCI menu select `Identity & Security>Certificates>Certificate Authorities`
   2. Select button `Create Certificate Authority`
   3. Choose `Root Certificate Authority` and choose the name, for example `MySuperCA`
   4. Enter CN(Common Name), for example `my.super.authority`
   5. Select your vault and the key `mySuperCAKey`
   6. Select max validity for signed certs(or leave the default 90 days)
   7. Check `Skip Revocation` to keep it simple
   8. Select `Create Certificate Authority` button on the summary page
   9. Notice OCID of the newly created CA, we will need it later

### Configuration
Following env variables to be configured in [config.sh](certs%2Fconfig.sh)
for both [rotating](#rotating-mtls-certificates) certificates and [running](#build--run) the examples.
- **COMPARTMENT_OCID** - OCID of compartment the services are in
- **VAULT_CRYPTO_ENDPOINT** - Each OCI Vault has public crypto and management endpoints, we need to specify crypto endpoint of the vault we are rotating the private keys in (example expects both client and server to store private key in the same vault)
- **VAULT_MANAGEMENT_ENDPOINT** - crypto endpoint of the vault we are rotating the private keys in
- **CA_OCID** - OCID of the CA authority we have created in [Prepare CA](#prepare-cacertification-authority) step

Following env variables are generated automatically by [createKeys.sh](certs%2FcreateKeys.sh) or needs to be configured manually for [rotateKeys.sh](certs%2FrotateKeys.sh) in [generated-config.sh](certs%2Fgenerated-config.sh)
- **SERVER_CERT_OCID** - OCID of the server certificate(not the specific version!)
- **SERVER_KEY_OCID** - OCID of the server private key in vault(not the specific version!)

- **CLIENT_CERT_OCID** - OCID of the client certificate(not the specific version!)
- **CLIENT_KEY_OCID** - OCID of the client private key in vault(not the specific version!)

### Prepare keys and certificates
Make sure you are in the directory [./certs](certs).
```shell
bash createKeys.sh
```

## Rotating mTLS certificates
Make sure you are in the directory [./certs](certs).
```shell
bash rotateKeys.sh
```
⚠️ Keep in mind that rotation creates new [versions](https://docs.oracle.com/en-us/iaas/Content/certificates/rotation-states.htm), OCIDs of the keys and certificates stays the same, and you don't need to change your configuration.

## Build and run example

### Build & Run

```shell
mvn clean package
```

Run mTLS secured web server:
```shell
source ./certs/config.sh && \
source ./certs/generated-config.sh && \
java -jar ./target/mtls-rotation.jar
```
Reload interval can be overridden with:
```shell
source ./certs/config.sh && \
source ./certs/generated-config.sh && \
java -Dsecurity.mtls-reload.reload-cron="0/20 * * * * ? *" \
-jar ./target/mtls-rotation.jar
```
### Test with WebClient
```shell
source ./certs/config.sh && \
source ./certs/generated-config.sh && \
java -cp ./target/mtls-rotation.jar io.helidon.example.mtls.Client
```

### Test with cURL
```shell
curl --key key-pair.pem --cert cert-chain.cer --cacert ca.cer -v https://localhost:8443
```