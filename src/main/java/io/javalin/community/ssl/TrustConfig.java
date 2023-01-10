package io.javalin.community.ssl;

import lombok.AllArgsConstructor;
import lombok.Getter;
import nl.altindag.ssl.util.CertificateUtils;
import nl.altindag.ssl.util.KeyStoreUtils;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for the trust store, used to verify the identity of the clients.
 * Using this configuration, the server will only accept connections from clients that are trusted.
 * If no trust store is configured, the server will accept any client.
 */

public class TrustConfig {


    /**
     * List of certificates to be trusted, can be loaded using the helper methods or directly.
     * This list is complementary to the keys
     */
    public List<Certificate> certificates = new ArrayList<>();

    /**
     * List of KeyStores to be trusted, can be loaded using the helper methods or directly.
     */
    public List<KeyStore> keyStores = new ArrayList<>();


    ///////////////////////////////////////////////////////////////
    // Certificate Loading Methods (PEM, P7B and DER)
    ///////////////////////////////////////////////////////////////

    /**
     * Load certificate data from a given path in the system.
     * The certificate can be in PEM, P7B/PKCS#7 or DER format.
     *
     * @param certificatePath path to the certificate file.
     */
    public void certificateFromPath(String certificatePath) {
        certificates.addAll(CertificateUtils.loadCertificate(Paths.get(certificatePath)));
    }

    /**
     * Load certificate data from the classpath.
     * The certificate can be in PEM, P7B/PKCS#7 or DER format.
     *
     * @param certificateFile The name of the certificate file in the classpath.
     */
    public void certificateFromClasspath(String certificateFile) {
        certificates.addAll(CertificateUtils.loadCertificate(certificateFile));
    }

    /**
     * Load certificate data from a given input stream.
     * The certificate can be in PEM, P7B/PKCS#7 or DER format.
     *
     * @param certificateInputStream input stream to the certificate file.
     */
    public void certificateFromInputStream(InputStream certificateInputStream) {
        certificates.addAll(CertificateUtils.loadCertificate(certificateInputStream));
    }

    /**
     * Load P7B certificate data from a given string.
     * The certificate must be in P7B/PKCS#7 format.
     *
     * @param certificateString P7B encoded certificate.
     */
    public void p7bCertificateFromString(String certificateString) {
        certificates.addAll(CertificateUtils.parseP7bCertificate(certificateString));
    }

    /**
     * Load pem formatted identity data from a given string.
     * The certificate must be in PEM format.
     * @param certificateString PEM encoded certificate.
     */
    public void pemFromString(String certificateString) {
        certificates.addAll(CertificateUtils.parsePemCertificate(certificateString));
    }


    ///////////////////////////////////////////////////////////////
    // Trust Store Loading Methods (JKS, PKCS12)
    ///////////////////////////////////////////////////////////////


    /**
     * Load a trust store from a given path in the system.
     * The trust store can be in JKS or PKCS12 format.
     *
     * @param trustStorePath path to the trust store file.
     * @param trustStorePassword password for the trust store.
     */
    public void trustStoreFromPath(String trustStorePath, String trustStorePassword) {
        keyStores.add(KeyStoreUtils.loadKeyStore(Paths.get(trustStorePath), trustStorePassword.toCharArray()));
    }

    /**
     * Load a trust store from a given input stream.
     * The trust store can be in JKS or PKCS12 format.
     *
     * @param trustStoreInputStream input stream to the trust store file.
     * @param trustStorePassword password for the trust store.
     */
    public void trustStoreFromInputStream(InputStream trustStoreInputStream, String trustStorePassword) {
        keyStores.add(KeyStoreUtils.loadKeyStore(trustStoreInputStream, trustStorePassword.toCharArray()));
    }

    /**
     * Load a trust store from the classpath.
     * @param trustStoreFile The name of the trust store file in the classpath.
     * @param trustStorePassword password for the trust store.
     */
    public void trustStoreFromClasspath(String trustStoreFile, String trustStorePassword) {
        keyStores.add(KeyStoreUtils.loadKeyStore(trustStoreFile, trustStorePassword.toCharArray()));
    }
}
