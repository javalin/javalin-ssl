package io.javalin.ssl.plugin;

import org.jetbrains.annotations.Nullable;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

@SuppressWarnings("unused")
public class SSLConfig {

    /**
     * Host to bind to.
     */
    public String host = null;

    /**
     * Disable the default http (insecure) connector.
     */
    public boolean disableInsecure = false;

    /**
     * Disable the default https (secure) connector.
     */
    public boolean disableSecure = false;

    /**
     * Port to use on the SSL (secure) connector.
     */
    public int sslPort = 443;

    /**
     * Port to use on the http (insecure) connector.
     */
    public int insecurePort = 80;

    /**
     * Enables HTTP/2 Support
     */
    public boolean enableHttp2 = true;

    /**
     * Enables HTTP/3 Support.
     * <b>Disabled by default because it is not yet working on Jetty.</b>
     */
    public final boolean enableHttp3 = false;

    /**
     * Disables the handler that adds an "Alt-Svc" header to any non HTTP/3 response.
     * <b>Disabled by default because it is not yet working on Jetty.</b>
     */
    public final boolean disableHttp3Upgrade = false;

    /**
     * UDP Port to use on the HTTP/3 connector.
     * <b>Disabled by default because it is not yet working on Jetty.</b>
     */
    public final int http3Port = 443;

    public InnerConfig inner = new InnerConfig();

    /**
     * Configuration for the SSL (secure) connector, meant to be accessed using its setters.
     */
    public static class InnerConfig {

        /**
         * Name of the certificate chain PEM file in the classpath.
         */
        @Nullable
        public String pemCertificatesFile = null;

        /**
         * Name of the private key PEM file in the classpath.
         */
        @Nullable
        public String pemPrivateKeyFile = null;

        /**
         * Input stream to the certificate chain PEM file.
         */
        @Nullable
        public InputStream pemCertificatesInputStream = null;

        /**
         * Input stream to the private key PEM file.
         */
        @Nullable
        public InputStream pemPrivateKeyInputStream = null;

        /**
         * Path to the PEM certificate chain PEM file.
         */
        @Nullable
        public Path pemCertificatesPath = null;

        /**
         * Path to the private key PEM file.
         */
        @Nullable
        public Path pemPrivateKeyPath = null;

        /**
         * Certificate chain as a PEM encoded string.
         */
        @Nullable
        public String pemCertificatesString = null;

        /**
         * Private key as a PEM encoded string.
         */
        @Nullable
        public String pemPrivateKeyString = null;

        /**
         * Password for the private key.
         */
        @Nullable
        public String privateKeyPassword = null;
    }

    /**
     * Set the path to the pem certificate file.
     *
     * @param pemCertificatesPath The path to the pem certificate file.
     */
    public void setPemCertificatesPath(String pemCertificatesPath) {
        inner.pemCertificatesPath = Paths.get(pemCertificatesPath);
    }

    /**
     * Set the path to the pem private key file.
     *
     * @param pemPrivateKeyPath The path to the pem private key file.
     */
    public void setPemPrivateKeyPath(String pemPrivateKeyPath) {
        inner.pemPrivateKeyPath = Paths.get(pemPrivateKeyPath);
    }

    /**
     * Set the name of the pem certificate file in the classpath.
     *
     * @param pemCertificatesFile The name of the pem certificate file in the classpath.
     */
    public void setPemCertificatesFile(String pemCertificatesFile) {
        inner.pemCertificatesFile = pemCertificatesFile;
    }

    /**
     * Set the name of the pem private key file in the classpath.
     *
     * @param pemPrivateKeyFile The name of the pem private key file in the classpath.
     */
    public void setPemPrivateKeyFile(String pemPrivateKeyFile) {
        inner.pemPrivateKeyFile = pemPrivateKeyFile;
    }

    /**
     * Set the input stream to the pem certificate file.
     *
     * @param pemCertificatesInputStream The input stream to the pem certificate file.
     */
    public void setPemCertificatesInputStream(InputStream pemCertificatesInputStream) {
        inner.pemCertificatesInputStream = pemCertificatesInputStream;
    }

    /**
     * Set the input stream to the pem private key file.
     *
     * @param pemPrivateKeyInputStream The input stream to the pem private key file.
     */
    public void setPemPrivateKeyInputStream(InputStream pemPrivateKeyInputStream) {
        inner.pemPrivateKeyInputStream = pemPrivateKeyInputStream;
    }

    /**
     * Set the pem certificate chain as a PEM encoded string.
     *
     * @param pemCertificatesString The pem certificate chain as a PEM encoded string.
     */
    public void setPemCertificatesString(String pemCertificatesString) {
        inner.pemCertificatesString = pemCertificatesString;
    }

    /**
     * Set the pem private key as a PEM encoded string.
     *
     * @param pemPrivateKeyString The pem private key as a PEM encoded string.
     */
    public void setPemPrivateKeyString(String pemPrivateKeyString) {
        inner.pemPrivateKeyString = pemPrivateKeyString;
    }



}
