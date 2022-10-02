package io.javalin.community.ssl.util;

import io.javalin.community.ssl.SSLConfig;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.ssl.SslContextFactory;

@AllArgsConstructor
@RequiredArgsConstructor
public class ConnectorFactory {

    private SSLConfig config;
    private Server server;

    private SslContextFactory.Server sslContextFactory = null;


    /**
     * Create and return an insecure connector to the server.
     *
     * @return The created {@link Connector}.
     */
    public ServerConnector createInsecureConnector() {
        ServerConnector connector;

        //The http configuration object
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setUriCompliance(UriCompliance.RFC3986);  // accept ambiguous values in path and let Javalin handle them
        httpConfiguration.setSendServerVersion(false);

        //The factory for HTTP/1.1 connections.
        HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfiguration);

        if (config.http2) {
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
     * @return The created {@link Connector}.
     */
    public ServerConnector createSecureConnector() {

        ServerConnector connector;

        //The http configuration object
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setUriCompliance(UriCompliance.RFC3986);  // accept ambiguous values in path and let Javalin handle them
        httpConfiguration.setSendServerVersion(false);
        httpConfiguration.addCustomizer(new SecureRequestCustomizer(config.sniHostCheck));

        //The factory for HTTP/1.1 connections
        HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfiguration);

        if (config.http2) {
            //The factory for HTTP/2 connections.
            HTTP2ServerConnectionFactory http2 = new HTTP2ServerConnectionFactory(httpConfiguration);
            // The ALPN ConnectionFactory.
            ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
            // The default protocol to use in case there is no negotiation.
            alpn.setDefaultProtocol(http11.getProtocol());

            SslConnectionFactory tlsHttp2 = new SslConnectionFactory(sslContextFactory, alpn.getProtocol());

            connector = new ServerConnector(server, tlsHttp2, alpn, http2, http11);
        } else {
            SslConnectionFactory tls = new SslConnectionFactory(sslContextFactory, http11.getProtocol());

            connector = new ServerConnector(server, tls, http11);
        }

        connector.setPort(config.securePort);
        if (config.host != null) {
            connector.setHost(config.host);
        }
        return connector;

    }


}
