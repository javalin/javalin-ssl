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
     * <br>
     * To initiate an HTTP/3 connection, the server should send an {@code Alt-Svc} header in the response to the client.
     * For the default port, the header would be {@code Alt-Svc: h3=":843"}
     * @see <a href="https://www.eclipse.org/jetty/documentation/jetty-11/programming-guide/index.html#pg-server-http-connector-protocol-http3">Jetty Documentation</a>
     */
    public boolean enableHttp3 = false; //TODO: Implement

    /**
     * Port to use on the HTTP/3 connector.
     */
    public int http3Port = 843; //TODO: Implement

    public InnerConfig inner = new InnerConfig();


    /**
     * Configuration for the SSL (secure) connector, meant to be accessed using its setters.
     */
    public static class InnerConfig {
        /**
         * Path to the certificate chain file.
         */
        @Nullable public Path pemCertificatesPath = null;
        /**
         * Path to the private key file.
         */
        @Nullable public Path pemPrivateKeyPath = null;

        /**
         * Password for the private key.
         */
        @Nullable public String privateKeyPassword = null;
    }

    /**
     * Set the path to the pem certificate file.
     *
     * @param pemCertificatePath The path to the pem certificate file.
     */
    public void setPemCertificatePath(String pemCertificatePath) {
        Paths.get(pemCertificatePath);
    }

    /**
     * Set the path to the pem private key file.
     *
     * @param pemPrivateKeyPath The path to the pem private key file.
     */
    public void setPemPrivateKeyPath(String pemPrivateKeyPath) {
        Paths.get(pemPrivateKeyPath);
    }


}
