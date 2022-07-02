package io.javalin.ssl.plugin;

import io.javalin.Javalin;
import io.javalin.core.plugin.Plugin;
import io.javalin.ssl.plugin.util.ConnectorFactory;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.jetbrains.annotations.NotNull;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import static io.javalin.ssl.plugin.util.ConnectorFactory.*;
import static io.javalin.ssl.plugin.util.SSLUtils.*;

public class SSLPlugin implements Plugin {

    private final SSLConfig config;

    public SSLPlugin(){
        config = new SSLConfig();
    }

    public SSLPlugin(SSLConfig config) {
        this.config = config;
    }

    public SSLPlugin(Consumer<SSLConfig> config) {
        this();
        config.accept(this.config);
    }

    @Override
    public void apply(@NotNull Javalin javalin) {

        Consumer<Server> patcher = createJettyServerPatcher(config);

        javalin.cfg.jetty.server(() -> {
            Server server;

            //Check if the server has been manually configured
            server = Objects.requireNonNullElseGet(javalin.cfg.inner.server, Server::new);

            //parseConfig returns a consumer configuring the server.
            patcher.accept(server);

            return server;
        });

        if(config.enableHttp3 && !config.disableHttp3Upgrade){
            javalin.before(createHttp3UpgradeHandler(config));
        }

    }

    /**
     * Method to parse the config and return a consumer that can be used to configure the server.
     *
     * @param config The config to parse.
     * @return A {@link Consumer<Server>} that can be used to configure the server.
     */
    private static Consumer<Server> createJettyServerPatcher(SSLConfig config) {
        //TODO: Assert that the config is valid before creating the consumer, otherwise exceptions will be buried.

        //Created outside the lambda to have exceptions thrown in the correct context.
        SslContextFactory.Server sslContextFactory;

        if(!config.disableSecure || config.enableHttp3){
            sslContextFactory =
                createSslContextFactory(createKeyManager(config), config);
        } else {
            sslContextFactory =
                createSslContextFactory(null, config);
        }

        return (server) -> {

            List<Connector> connectorList = new LinkedList<>();
            ConnectorFactory connectorFactory = new ConnectorFactory(config, server, sslContextFactory);

            if (!config.disableInsecure) {
                connectorList.add(connectorFactory.createInsecureConnector());
            }

            if (!config.disableSecure) {
                connectorList.add(connectorFactory.createSecureConnector());
            }

            if (config.enableHttp3) {
                connectorList.add(connectorFactory.createHttp3Connector());
            }

            connectorList.forEach(server::addConnector);
        };
    }

}

