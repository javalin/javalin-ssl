package io.javalin.ssl.plugin;

import org.jetbrains.annotations.Nullable;

import java.nio.file.Path;
import java.nio.file.Paths;

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
         * Path to the certificate chain file.
         */
        @Nullable
        public Path pemCertificatesPath = null;
        /**
         * Path to the private key file.
         */
        @Nullable
        public Path pemPrivateKeyPath = null;

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


}
