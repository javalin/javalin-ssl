package io.javalin.community.ssl;

import io.javalin.community.ssl.util.SSLUtils;
import lombok.Getter;
import org.eclipse.jetty.server.ServerConnector;
import org.jetbrains.annotations.Nullable;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.util.function.Consumer;

/**
 * Data class to hold the configuration for the plugin.
 */
@SuppressWarnings("unused")
public class SSLConfig {

    /**
     * Host to bind to.
     */
    public String host = null;

    /**
     * Toggle the default http (insecure) connector.
     */
    public boolean insecure = true;

    /**
     * Toggle the default https (secure) connector.
     */
    public boolean secure = true;

    /**
     * Port to use on the SSL (secure) connector.
     */
    public int securePort = 443;

    /**
     * Port to use on the http (insecure) connector.
     */
    public int insecurePort = 80;

    /**
     * Enable http to https redirection.
     */
    public boolean redirect = false;

    /**
     * Toggle HTTP/2 Support
     */
    public boolean http2 = true;

    /**
     * Disable SNI checks.
     * @see <a href="https://www.eclipse.org/jetty/documentation/jetty-11/operations-guide/index.html#og-protocols-ssl-sni">Configuring SNI</a>
     */
    public boolean sniHostCheck = true;

    /**
     * TLS Security configuration
     */
    public TLSConfig tlsConfig = TLSConfig.INTERMEDIATE;

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
         * Type of identity loading types.
         */
        public enum IdentityLoadingType {
            NONE,
            PEM_CLASS_PATH,
            PEM_FILE_PATH,
            PEM_STRING,
            PEM_INPUT_STREAM,
            KEY_STORE_CLASS_PATH,
            KEY_STORE_FILE_PATH,
            KEY_STORE_INPUT_STREAM
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

        /**
         * Path to the key store file.
         */
        @Nullable
        public Path keyStorePath = null;


        /**
         * Name of the key store file in the classpath.
         */
        @Nullable
        public String keyStoreFile = null;

        /**
         * Input stream to the key store file.
         */
        @Nullable
        public InputStream keyStoreInputStream = null;

        /**
         * Password for the key store.
         */
        @Nullable
        public String keyStorePassword = null;
    }

    ///////////////////////////////////////////////////////////////
    // PEM Loading Methods
    ///////////////////////////////////////////////////////////////

    /**
     * Load pem formatted identity data from a given path in the system.
     *
     * @param certificatePath path to the certificate chain PEM file.
     * @param privateKeyPath  path to the private key PEM file.
     */
    public void pemFromPath(String certificatePath, String privateKeyPath) {
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
    public void pemFromPath(String certificatePath, String privateKeyPath, String privateKeyPassword) {
        pemFromPath(certificatePath, privateKeyPath);
        inner.privateKeyPassword = privateKeyPassword;
    }


    /**
     * Load pem formatted identity data from the classpath.
     *
     * @param certificateFile The name of the pem certificate file in the classpath.
     * @param privateKeyFile  The name of the pem private key file in the classpath.
     */
    public void pemFromClasspath(String certificateFile, String privateKeyFile) {
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
    public void pemFromClasspath(String certificateFile, String privateKeyFile, String privateKeyPassword) {
        pemFromClasspath(certificateFile, privateKeyFile);
        inner.privateKeyPassword = privateKeyPassword;
    }


    /**
     * Load pem formatted identity data from a given input stream.
     *
     * @param certificateInputStream input stream to the certificate chain PEM file.
     * @param privateKeyInputStream  input stream to the private key PEM file.
     */
    public void pemFromInputStream(InputStream certificateInputStream, InputStream privateKeyInputStream) {
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
    public void pemFromInputStream(InputStream certificateInputStream, InputStream privateKeyInputStream, String privateKeyPassword) {
        pemFromInputStream(certificateInputStream, privateKeyInputStream);
        inner.privateKeyPassword = privateKeyPassword;
    }


    /**
     * Load pem formatted identity data from a given string.
     *
     * @param certificateString PEM encoded certificate chain.
     * @param privateKeyString  PEM encoded private key.
     */
    public void pemFromString(String certificateString, String privateKeyString) {
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
     * @param certificateString  PEM encoded certificate chain.
     * @param privateKeyString   PEM encoded private key.
     * @param privateKeyPassword password for the private key.
     */
    public void pemFromString(String certificateString, String privateKeyString, String privateKeyPassword) {
        pemFromString(certificateString, privateKeyString);
        inner.privateKeyPassword = privateKeyPassword;
    }

    ///////////////////////////////////////////////////////////////
    // Key Store Loading Methods
    ///////////////////////////////////////////////////////////////


    /**
     * Load a key store from a given path in the system.
     * @param keyStorePath path to the key store file.
     * @param keyStorePassword password for the key store.
     */
    public void keystoreFromPath(String keyStorePath, String keyStorePassword) {
        if (inner.identityLoadingType != InnerConfig.IdentityLoadingType.NONE) {
            throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
        }
        inner.keyStorePath = Paths.get(keyStorePath);
        inner.identityLoadingType = InnerConfig.IdentityLoadingType.KEY_STORE_FILE_PATH;
        inner.keyStorePassword = keyStorePassword;
    }

    /**
     * Load a key store from a given input stream.
     * @param keyStoreInputStream input stream to the key store file.
     * @param keyStorePassword password for the key store.
     */
    public void keystoreFromInputStream(InputStream keyStoreInputStream, String keyStorePassword) {
        if (inner.identityLoadingType != InnerConfig.IdentityLoadingType.NONE) {
            throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
        }
        inner.keyStoreInputStream = keyStoreInputStream;
        inner.identityLoadingType = InnerConfig.IdentityLoadingType.KEY_STORE_INPUT_STREAM;
        inner.keyStorePassword = keyStorePassword;
    }

    /**
     * Load a key store from the classpath.
     * @param keyStoreFile name of the key store file in the classpath.
     * @param keyStorePassword password for the key store.
     */
    public void keystoreFromClasspath(String keyStoreFile, String keyStorePassword) {
        if (inner.identityLoadingType != InnerConfig.IdentityLoadingType.NONE) {
            throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
        }
        inner.keyStoreFile = keyStoreFile;
        inner.identityLoadingType = InnerConfig.IdentityLoadingType.KEY_STORE_CLASS_PATH;
        inner.keyStorePassword = keyStorePassword;
    }

    ///////////////////////////////////////////////////////////////
    // Advanced Options
    ///////////////////////////////////////////////////////////////

    /**
     * Consumer to configure the different {@link ServerConnector} that will be created.
     * This consumer will be called as the last config step for each connector,
     * allowing to override any previous configuration.
     * @deprecated Use {@link #configConnectors(Consumer<ServerConnector>)} instead, access modifier will be changed
     * to private in the next major release.
     */
    @Getter
    @Deprecated(forRemoval = true, since = "5.3.2")
    public Consumer<ServerConnector> configConnectors = null;

    /**
     * Consumer to configure the different {@link ServerConnector} that will be created.
     * This consumer will be called as the last config step for each connector, allowing to override any previous configuration.
     */
    public void configConnectors(Consumer<ServerConnector> configConnectors) {
        this.configConnectors = configConnectors;
    }

    /**
     * Security provider to use for the SSLContext.
     */
    public Provider securityProvider = null;

    ///////////////////////////////////////////////////////////////
    // Trust Store
    ///////////////////////////////////////////////////////////////

    /**
     * Trust store configuration for the server, if not set, every client will be accepted.
     */
    @Getter
    private TrustConfig trustConfig = null;

    /**
     * Trust configuration as a consumer.
     * @param trustConfigConsumer consumer to configure the trust configuration.
     */
    public void withTrustConfig(Consumer<TrustConfig> trustConfigConsumer) {
        trustConfig = new TrustConfig();
        trustConfigConsumer.accept(trustConfig);
    }
}
