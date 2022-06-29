package io.javalin.ssl.plugin;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.JettySslUtils;
import nl.altindag.ssl.util.PemUtils;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.http3.server.HTTP3ServerConnectionFactory;
import org.eclipse.jetty.http3.server.HTTP3ServerConnector;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.X509ExtendedKeyManager;

public class ConnectorUtils {

    /**
     * Create and return an insecure connector to the server.
     *
     * @param config The configuration to use.
     * @param server The server to apply the connector to.
     * @return The created {@link Connector}.
     */
    public static ServerConnector createInsecureConnector(SSLConfig config, Server server) {
        ServerConnector connector;

        //The http configuration object
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setUriCompliance(UriCompliance.RFC3986);  // accept ambiguous values in path and let Javalin handle them
        httpConfiguration.setSendServerVersion(false);

        //The factory for HTTP/1.1 connections.
        HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfiguration);

        if (config.enableHttp2) {
            //The factory for HTTP/2 connections.
            HTTP2CServerConnectionFactory http2 = new HTTP2CServerConnectionFactory(httpConfiguration);
            connector = new ServerConnector(server, http11, http2);
        } else {
            connector = new ServerConnector(server, http11);
        }

        connector.setPort(config.insecurePort);
        if (config.host != null) {
            connector.setHost(config.host);
        }
        return connector;
    }

    /**
     * Create and apply an SSL connector to the server.
     *
     * @param config The configuration to use.
     * @param server The server to apply the connector to.
     * @return The created {@link Connector}.
     */
    public static ServerConnector createSecureConnector(SSLConfig config, Server server) {

        SslContextFactory.Server sslContextFactory = createSslContextFactory(config);

        ServerConnector connector;

        //The http configuration object
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setUriCompliance(UriCompliance.RFC3986);  // accept ambiguous values in path and let Javalin handle them
        httpConfiguration.setSendServerVersion(false);
        httpConfiguration.addCustomizer(new SecureRequestCustomizer());

        //The factory for HTTP/1.1 connections
        HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfiguration);

        if (config.enableHttp2) {
            //The factory for HTTP/2 connections.
            HTTP2CServerConnectionFactory http2 = new HTTP2CServerConnectionFactory(httpConfiguration);
            // The ALPN ConnectionFactory.
            ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
            // The default protocol to use in case there is no negotiation.
            alpn.setDefaultProtocol(http11.getProtocol());

            //TODO: Fine tune the TLS configuration
            SslConnectionFactory tlsHttp2 = new SslConnectionFactory(sslContextFactory, alpn.getProtocol());

            connector = new ServerConnector(server, tlsHttp2, alpn, http11, http2);
        } else {
            //TODO: Fine tune the TLS configuration
            SslConnectionFactory tls = new SslConnectionFactory(sslContextFactory, http11.getProtocol());

            connector = new ServerConnector(server, tls, http11);
        }

        connector.setPort(config.sslPort);
        if (config.host != null) {
            connector.setHost(config.host);
        }
        return connector;

    }

    /**
     * Create and apply an HTTP/3 connector to the server.
     *
     * @param config The configuration to use.
     * @param server The server to apply the connector to.
     * @return The created {@link Connector}.
     */
    public static HTTP3ServerConnector createHttp3Connector(SSLConfig config, Server server) {

        //The http configuration object
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setUriCompliance(UriCompliance.RFC3986);  // accept ambiguous values in path and let Javalin handle them
        httpConfiguration.setSendServerVersion(false);
        httpConfiguration.addCustomizer(new SecureRequestCustomizer());

        HTTP3ServerConnector connector = new HTTP3ServerConnector(server,
            createSslContextFactory(config),
            new HTTP3ServerConnectionFactory(httpConfiguration));

        connector.setPort(config.http3Port);
        if (config.host != null) {
            connector.setHost(config.host);
        }
        return connector;
    }

    /**
     * Helper method to create a {@link SslContextFactory} from the given config.
     *
     * @param config The config to use.
     * @return The created {@link SslContextFactory}.
     */
    public static SslContextFactory.Server createSslContextFactory(SSLConfig config) {

        X509ExtendedKeyManager keyManager = null;

        //TODO: Implement support for different loadings of the keystore and formats.
        if (config.inner.pemCertificatesPath != null && config.inner.pemPrivateKeyPath != null) {
            if (config.inner.privateKeyPassword == null) {
                keyManager = PemUtils.loadIdentityMaterial(config.inner.pemCertificatesPath, config.inner.pemPrivateKeyPath);
            } else {
                keyManager = PemUtils.loadIdentityMaterial(config.inner.pemCertificatesPath, config.inner.pemPrivateKeyPath, config.inner.privateKeyPassword.toCharArray());
            }
        }

        if (keyManager == null) {
            throw new IllegalArgumentException("Both certificate and private key must be configured!");
        }
        //The sslcontext-kickstart factory
        SSLFactory sslFactory = SSLFactory.builder()
            .withIdentityMaterial(keyManager)
            .build();

        return JettySslUtils.forServer(sslFactory);
    }
}
