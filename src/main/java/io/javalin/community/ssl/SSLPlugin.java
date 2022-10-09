package io.javalin.community.ssl;

import io.javalin.Javalin;
import io.javalin.community.ssl.util.ConnectorFactory;
import io.javalin.jetty.JettyUtil;
import io.javalin.plugin.Plugin;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.jetbrains.annotations.NotNull;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import static io.javalin.community.ssl.util.SSLUtils.createSslContextFactory;

/**
 * A plugin to easily enable SSL on a Javalin server.
 * <p>
 * The intended configuration pattern is to use the {@link SSLPlugin#SSLPlugin(Consumer)} constructor to configure the
 * plugin, either though a lambda or a Consumer. This allows for a more fluent configuration pattern.
 *
 * @author Alberto Zugazagoitia
 * @see SSLConfig
 */
public class SSLPlugin implements Plugin {

    private final SSLConfig config;

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
     * Method to parse the config and return a consumer that can be used to configure the server.
     *
     * @param config The config to parse.
     * @return A {@link Consumer<Server>} that can be used to configure the server.
     */
    private static Consumer<Server> createJettyServerPatcher(SSLConfig config) {

        //Created outside the lambda to have exceptions thrown in the current scope
        SslContextFactory.Server sslContextFactory;

        if (config.secure || config.enableHttp3) {
            sslContextFactory =
                createSslContextFactory(config);
        } else {
            sslContextFactory =
                null;
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

