package io.helidon.example.mtls;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import io.helidon.config.Config;

import com.oracle.bmc.ConfigFileReader;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
import com.oracle.bmc.certificates.CertificatesClient;
import com.oracle.bmc.certificates.requests.GetCertificateAuthorityBundleRequest;
import com.oracle.bmc.certificates.requests.GetCertificateBundleRequest;
import com.oracle.bmc.certificates.responses.GetCertificateAuthorityBundleResponse;
import com.oracle.bmc.certificates.responses.GetCertificateBundleResponse;
import com.oracle.bmc.keymanagement.KmsCryptoClient;
import com.oracle.bmc.keymanagement.model.ExportKeyDetails;
import com.oracle.bmc.keymanagement.requests.ExportKeyRequest;
import com.oracle.bmc.keymanagement.responses.ExportKeyResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class OCImTLSManager {

    private final String caOcid;
    private final String keyOcid;
    private final String certOcid;
    private final char[] password;
    private final Type type;
    private final ConfigFileAuthenticationDetailsProvider ociConfigProvider;
    private final PrivateKeyDownloader privateKeyDownloader;

    private OCImTLSManager(String vaultCryptoEndpoint,
                           String caOcid,
                           String keyOcid,
                           String certOcid,
                           char[] password,
                           Type type) {
        this.caOcid = caOcid;
        this.keyOcid = keyOcid;
        this.certOcid = certOcid;
        this.password = password;
        this.type = type;
        try {
            ociConfigProvider = new ConfigFileAuthenticationDetailsProvider(ConfigFileReader.parseDefault());
            privateKeyDownloader = new PrivateKeyDownloader(ociConfigProvider, vaultCryptoEndpoint);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static OCImTLSManager create(Type type, Config config) {
        String cryptoEndpoint = config.get("vault-crypto-endpoint").asString().get();
        String caOcid = config.get("ca-ocid").asString().get();
        String certOcid = config.get(type + ".cert-ocid").asString().get();
        String keyOcid = config.get(type + ".key-ocid").asString().get();
        char[] password = config.get(type + ".key-pass").asString().get().toCharArray();
        return new OCImTLSManager(cryptoEndpoint, caOcid, keyOcid, certOcid, password, type);
    }

    public SSLContext loadSSLContext() {
        try {
            Certificate[] certificates = loadCert(certOcid);
            Certificate ca = loadCACert();
            PrivateKey key = privateKeyDownloader.loadKey(keyOcid);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);

            keyStore.setKeyEntry(type + "-cert-chain", key, password, certificates);
            keyStore.setCertificateEntry("trust-ca", ca);

            SSLContext context = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

            kmf.init(keyStore, password);
            tmf.init(keyStore);

            // Uncomment to debug downloaded context
            //saveToFile(keyStore, type + ".jks");

            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstance("DEFAULT"));
            return context;
        } catch (Exception e) {
            throw new RuntimeException("Error when loading mTls context from OCI", e);
        }
    }

    private Certificate[] loadCert(String certOcid) throws Exception {
        try (CertificatesClient client = CertificatesClient.builder()
                .build(ociConfigProvider)) {

            GetCertificateBundleResponse res =
                    client.getCertificateBundle(GetCertificateBundleRequest.builder()
                                                        .certificateId(certOcid)
                                                        .build());

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream chainIs = new ByteArrayInputStream(res.getCertificateBundle().getCertChainPem().getBytes());
            ByteArrayInputStream certIs = new ByteArrayInputStream(res.getCertificateBundle().getCertificatePem().getBytes());
            Certificate cert = cf.generateCertificate(certIs);
            ArrayList<Certificate> chain = new ArrayList<>();
            chain.add(cert);
            chain.addAll(cf.generateCertificates(chainIs));
            return chain.toArray(new Certificate[0]);
        }
    }

    private Certificate loadCACert() throws Exception {
        GetCertificateAuthorityBundleResponse res;
        try (CertificatesClient client = CertificatesClient.builder()
                .build(ociConfigProvider)) {

            res = client.getCertificateAuthorityBundle(GetCertificateAuthorityBundleRequest.builder()
                                                               .certificateAuthorityId(caOcid)
                                                               .build());

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] pemBytes = res.getCertificateAuthorityBundle().getCertificatePem().getBytes();
            try (ByteArrayInputStream pemStream = new ByteArrayInputStream(pemBytes)) {
                return cf.generateCertificate(pemStream);
            }
        }

    }

    public enum Type {
        SERVER, CLIENT;

        public String toString() {
            return this.name()
                    .toLowerCase();
        }
    }

    private void saveToFile(KeyStore ks, String fileName) {
        try {
            FileOutputStream fos = new FileOutputStream(fileName);
            ks.store(fos, new char[0]);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static class PrivateKeyDownloader {

        private final PrivateKey wrappingPrivateKey;
        private final String wrappingPublicKeyPem;
        private final String vaultCryptoEndpoint;
        private final ConfigFileAuthenticationDetailsProvider ociConfigProvider;

        PrivateKeyDownloader(ConfigFileAuthenticationDetailsProvider ociConfigProvider, String vaultCryptoEndpoint) {
            // OCI uses BC, we need it for decryptAesKey
            // https://stackoverflow.com/a/23859386/626826
            // https://bugs.openjdk.org/browse/JDK-7038158
            Security.addProvider(new BouncyCastleProvider());
            this.ociConfigProvider = ociConfigProvider;
            this.vaultCryptoEndpoint = vaultCryptoEndpoint;

            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair wrappingKeyPair = generator.generateKeyPair();
                wrappingPrivateKey = wrappingKeyPair.getPrivate();
                PublicKey wrappingPublicKey = wrappingKeyPair.getPublic();
                String pubBase64 = Base64.getEncoder().encodeToString(wrappingPublicKey.getEncoded());
                wrappingPublicKeyPem = "-----BEGIN PUBLIC KEY-----" + pubBase64 + "-----END PUBLIC KEY-----";
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        PrivateKey loadKey(String keyOcid) throws Exception {
            try (KmsCryptoClient client = KmsCryptoClient.builder()
                    .endpoint(vaultCryptoEndpoint)
                    .build(ociConfigProvider)) {

                ExportKeyResponse exportKeyResponse =
                        client.exportKey(ExportKeyRequest.builder()
                                                 .exportKeyDetails(ExportKeyDetails.builder()
                                                                           .keyId(keyOcid)
                                                                           .publicKey(
                                                                                   wrappingPublicKeyPem)
                                                                           .algorithm(ExportKeyDetails.Algorithm.RsaOaepAesSha256)
                                                                           .build())
                                                 .build());

                String encryptedKey = exportKeyResponse.getExportedKeyData().getEncryptedKey();

                byte[] encryptedMaterial = Base64.getDecoder().decode(encryptedKey);

                //rfc3394 - first 256 bytes is tmp AES key encrypted by our temp wrapping RSA
                byte[] tmpAes = decryptAesKey(Arrays.copyOf(encryptedMaterial, 256));

                //rfc3394 - rest of the bytes is secret key wrapped by tmp AES
                byte[] wrappedSecretKey = Arrays.copyOfRange(encryptedMaterial, 256, encryptedMaterial.length);

                // Unwrap with decrypted tmp AES
                return (PrivateKey) unwrapRSA(wrappedSecretKey, tmpAes);
            }
        }

        private Key unwrapRSA(byte[] in, byte[] keyBytes) throws Exception {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher c = Cipher.getInstance("AESWrapPad");
            c.init(Cipher.UNWRAP_MODE, key);
            return c.unwrap(in, "RSA", Cipher.PRIVATE_KEY);
        }

        private byte[] decryptAesKey(byte[] in) throws Exception {
            // OCI uses BC
            //https://stackoverflow.com/a/23859386/626826
            //https://bugs.openjdk.org/browse/JDK-7038158
            Cipher decrypt = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING", "BC");
            decrypt.init(Cipher.DECRYPT_MODE, wrappingPrivateKey);
            return decrypt.doFinal(in);
        }
    }
}
