package io.javalin.community.ssl;

import io.javalin.Javalin;
import io.javalin.community.ssl.util.ConnectorFactory;
import io.javalin.jetty.JettyUtil;
import io.javalin.plugin.Plugin;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.SSLFactoryUtils;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.jetbrains.annotations.NotNull;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import static io.javalin.community.ssl.util.SSLUtils.createSslContextFactory;
import static io.javalin.community.ssl.util.SSLUtils.getSslFactory;

/**
 * A plugin to easily enable SSL on a Javalin server.
 * <p>
 * The intended configuration pattern is to use the {@link SSLPlugin#SSLPlugin(Consumer)} constructor to configure the
 * plugin, either though a lambda or a Consumer. This allows for a more fluent configuration pattern.
 * <p>
 * Hot reloading of the SSL certificates is supported. This means that the plugin will replace the SSL certificates without restarting the server, allowing for a seamless transition. This is done by using the {@link SSLPlugin#reload(Consumer)} method.
 *
 * @author Alberto Zugazagoitia
 * @see SSLConfig
 */
public class SSLPlugin implements Plugin {

    private final SSLConfig config;

    private SSLFactory sslFactory = null;

    /**
     * Creates a new SSLPlugin with the default configuration.
     */
    public SSLPlugin() {
        config = new SSLConfig();
    }

    /**
     * Creates a new SSLPlugin with the given configuration.
     *
     * @param config The configuration to use.
     */
    public SSLPlugin(SSLConfig config) {
        this.config = config;
    }

    /**
     * Creates a new SSLPlugin with the given configuration lambda/supplier.
     * This is useful if you want to use the default configuration and only change a few values.
     * Recommended way to create a new SSLPlugin with the given configuration.
     *
     * @param config The configuration to use.
     */
    public SSLPlugin(Consumer<SSLConfig> config) {
        this();
        config.accept(this.config);
    }


    /**
     * Method to apply the plugin to a Javalin instance
     *
     * @param javalin Javalin instance
     */
    @Override
    public void apply(@NotNull Javalin javalin) {

        Consumer<Server> patcher = createJettyServerPatcher(config);

        javalin.cfg.jetty.server(() -> {

            //Check if the server has been manually configured
            Server server = Objects.requireNonNullElseGet(
                javalin.cfg.pvt.server,
                SSLPlugin::getServer);

            //parseConfig returns a consumer configuring the server.
            patcher.accept(server);

            return server;
        });

    }

    /**
     * Method to apply the SSLConfig to a given Jetty Server.
     * Can be used to patch pre-existing or custom servers.
     *
     * @param server The Jetty Server to patch.
     */
    public void patch(@NotNull Server server) {
        Consumer<Server> patcher = createJettyServerPatcher(config);
        patcher.accept(server);
    }


    /**
     * Method to hot-swap the certificate and key material of the plugin.
     * Any configuration changes will be ignored, only the certificate and key material will be updated.
     *
     * @param newConfig A config containing the new certificate and key material.
     * @deprecated Use {@link #reload(Consumer)} instead.
     */
    @Deprecated(forRemoval = true,since = "5.3.2")
    public void reload(SSLConfig newConfig) {
        if(sslFactory == null)
            throw new IllegalStateException("Cannot reload before the plugin has been applied to a Javalin instance, a server has been patched or if the ssl connector is disabled.");

        SSLFactory newFactory = getSslFactory(newConfig,true);
        SSLFactoryUtils.reload(sslFactory, newFactory);
    }

    /**
     * Method to hot-swap the certificate and key material of the plugin.
     * Any configuration changes will be ignored, only the certificate and key material will be updated.
     *
     * @param newConfig A consumer providing the new certificate and key material.
     */
    public void reload(Consumer<SSLConfig> newConfig) {
        SSLConfig conf = new SSLConfig();
        newConfig.accept(conf);
        if(sslFactory == null)
            throw new IllegalStateException("Cannot reload before the plugin has been applied to a Javalin instance, a server has been patched or if the ssl connector is disabled.");

        SSLFactory newFactory = getSslFactory(conf,true);
        SSLFactoryUtils.reload(sslFactory, newFactory);
    }

    /**
     * Method to parse the config and return a consumer that can be used to configure the server.
     *
     * @param config The config to parse.
     * @return A {@link Consumer<Server>} that can be used to configure the server.
     */
    private Consumer<Server> createJettyServerPatcher(SSLConfig config) {

        //Created outside the lambda to have exceptions thrown in the current scope
        SslContextFactory.Server sslContextFactory;

        if (config.secure || config.enableHttp3) {
            sslFactory = getSslFactory(config);
            sslContextFactory =
                createSslContextFactory(sslFactory, config);
        } else {
            sslContextFactory =  null;
        }

        return (server) -> {

            List<Connector> connectorList = new LinkedList<>();
            ConnectorFactory connectorFactory = new ConnectorFactory(config, server, sslContextFactory);

            if (config.insecure) {
                connectorList.add(connectorFactory.createInsecureConnector());
            }

            if (config.secure) {
                connectorList.add(connectorFactory.createSecureConnector());
            }

            if (config.enableHttp3) {
                throw new UnsupportedOperationException("HTTP/3 is not supported yet");
            }

            connectorList.forEach(server::addConnector);
        };
    }

    /**
     * Method to create a new Jetty Server instance using Javalin's default configuration.
     *
     * @return A new Jetty Server instance.
     */
    private static Server getServer() {
        return JettyUtil.getOrDefault(null);
    }


}

