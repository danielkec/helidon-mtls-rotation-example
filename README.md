# Helidon mTLS context rotation OCI example
Helidon mTLS context rotation with [OCI](https://www.oracle.com/cloud) [KMS](https://www.oracle.com/security/cloud-security/key-management) and [Certificates](https://www.oracle.com/security/cloud-security/ssl-tls-certificates) services

1. [Setting up OCI](#setting-up-oci)  
   1.1. [Prepare CA(Certification Authority)](#prepare-cacertification-authority)

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