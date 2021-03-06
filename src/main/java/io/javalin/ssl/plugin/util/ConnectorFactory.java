package io.javalin.ssl.plugin.util;

import io.javalin.http.Handler;
import io.javalin.ssl.plugin.SSLConfig;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.http3.server.HTTP3ServerConnectionFactory;
import org.eclipse.jetty.http3.server.HTTP3ServerConnector;
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

        if (!config.disableHttp2) {
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
        httpConfiguration.addCustomizer(new SecureRequestCustomizer());

        //The factory for HTTP/1.1 connections
        HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfiguration);

        if (!config.disableHttp2) {
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

        connector.setPort(config.sslPort);
        if (config.host != null) {
            connector.setHost(config.host);
        }
        return connector;

    }

    /**
     * Create and apply an HTTP/3 connector to the server.
     *
     * @return The created {@link Connector}.
     */
    public HTTP3ServerConnector createHttp3Connector() {

        //The http configuration object
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setUriCompliance(UriCompliance.RFC3986);  // accept ambiguous values in path and let Javalin handle them
        httpConfiguration.setSendServerVersion(false);
        httpConfiguration.addCustomizer(new SecureRequestCustomizer());

        HTTP3ServerConnector connector = new HTTP3ServerConnector(server,
            sslContextFactory, //FIXME: The SSLContextFactory is not properly consumed by the QuicConnector on the jetty side.
            new HTTP3ServerConnectionFactory(httpConfiguration));

        connector.setPort(config.http3Port);
        if (config.host != null) {
            connector.setHost(config.host);
        }
        return connector;
    }


    public static Handler createHttp3UpgradeHandler(SSLConfig config) {
        return context -> {
            if (!context.protocol().equals(HttpVersion.HTTP_3.asString())) { //If the protocol is HTTP/3, then we don't want to handle it.
                context.header("Alt-Svc", "h3=\":" + config.http3Port + "\""); //Set the Alt-Svc header to tell the client to use HTTP/3.
            }
        };
    }

}
