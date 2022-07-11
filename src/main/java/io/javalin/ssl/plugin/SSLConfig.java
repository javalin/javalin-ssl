package io.javalin.ssl.plugin;

import lombok.Getter;
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
     * Disables HTTP/2 Support
     */
    public boolean disableHttp2 = false;

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

        public enum IdentityLoadingType {
            NONE,
            PEM_CLASS_PATH,
            PEM_FILE_PATH,
            PEM_STRING,
            PEM_INPUT_STREAM
        }

        @Getter
        IdentityLoadingType identityLoadingType = IdentityLoadingType.NONE;

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
     * Load pem formatted identity data from a given path in the system.
     *
     * @param certificatePath path to the certificate chain PEM file.
     * @param privateKeyPath  path to the private key PEM file.
     */
    public void loadPemFromPath(String certificatePath, String privateKeyPath) {
        if (inner.identityLoadingType != InnerConfig.IdentityLoadingType.NONE) {
            throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
        }
        inner.pemCertificatesPath = Paths.get(certificatePath);
        inner.pemPrivateKeyPath = Paths.get(privateKeyPath);
       inner.identityLoadingType = InnerConfig.IdentityLoadingType.PEM_FILE_PATH;
    }

    /**
     * Load pem formatted identity data from a given path in the system.
     *
     * @param certificatePath    path to the certificate chain PEM file.
     * @param privateKeyPath     path to the private key PEM file.
     * @param privateKeyPassword password for the private key.
     */
    public void loadPemFromPath(String certificatePath, String privateKeyPath, String privateKeyPassword) {
        loadPemFromPath(certificatePath, privateKeyPath);
        inner.privateKeyPassword = privateKeyPassword;
    }


    /**
     * Load pem formatted identity data from the classpath.
     *
     * @param certificateFile The name of the pem certificate file in the classpath.
     * @param privateKeyFile  The name of the pem private key file in the classpath.
     */
    public void loadPemFromClasspath(String certificateFile, String privateKeyFile) {
        if (inner.identityLoadingType != InnerConfig.IdentityLoadingType.NONE) {
            throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
        }
        inner.pemCertificatesFile = certificateFile;
        inner.pemPrivateKeyFile = privateKeyFile;
       inner.identityLoadingType = InnerConfig.IdentityLoadingType.PEM_CLASS_PATH;
    }

    /**
     * Load pem formatted identity data from the classpath.
     *
     * @param certificateFile    The name of the pem certificate file in the classpath.
     * @param privateKeyFile     The name of the pem private key file in the classpath.
     * @param privateKeyPassword password for the private key.
     */
    public void loadPemFromClasspath(String certificateFile, String privateKeyFile, String privateKeyPassword) {
        loadPemFromClasspath(certificateFile, privateKeyFile);
        inner.privateKeyPassword = privateKeyPassword;
    }


    /**
     * Load pem formatted identity data from a given input stream.
     *
     * @param certificateInputStream input stream to the certificate chain PEM file.
     * @param privateKeyInputStream  input stream to the private key PEM file.
     */
    public void loadPemFromInputStream(InputStream certificateInputStream, InputStream privateKeyInputStream) {
        if (inner.identityLoadingType != InnerConfig.IdentityLoadingType.NONE) {
            throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
        }
        inner.pemCertificatesInputStream = certificateInputStream;
        inner.pemPrivateKeyInputStream = privateKeyInputStream;
       inner.identityLoadingType = InnerConfig.IdentityLoadingType.PEM_INPUT_STREAM;
    }

    /**
     * Load pem formatted identity data from a given input stream.
     *
     * @param certificateInputStream input stream to the certificate chain PEM file.
     * @param privateKeyInputStream  input stream to the private key PEM file.
     * @param privateKeyPassword     password for the private key.
     */
    public void loadPemFromInputStream(InputStream certificateInputStream, InputStream privateKeyInputStream, String privateKeyPassword) {
        loadPemFromInputStream(certificateInputStream, privateKeyInputStream);
        inner.privateKeyPassword = privateKeyPassword;
    }


    /**
     * Load pem formatted identity data from a given string.
     *
     * @param certificateString PEM encoded certificate chain.
     * @param privateKeyString  PEM encoded private key.
     */
    public void loadPemFromString(String certificateString, String privateKeyString) {
        if (inner.identityLoadingType != InnerConfig.IdentityLoadingType.NONE) {
            throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
        }
        inner.pemCertificatesString = certificateString;
        inner.pemPrivateKeyString = privateKeyString;
       inner.identityLoadingType = InnerConfig.IdentityLoadingType.PEM_STRING;
    }

    /**
     * Load pem formatted identity data from a given string.
     *
     * @param certificateString PEM encoded certificate chain.
     * @param privateKeyString  PEM encoded private key.
     * @param privateKeyPassword password for the private key.
     */
    public void loadPemFromString(String certificateString, String privateKeyString, String privateKeyPassword) {
        loadPemFromString(certificateString, privateKeyString);
        inner.privateKeyPassword = privateKeyPassword;
    }


}
