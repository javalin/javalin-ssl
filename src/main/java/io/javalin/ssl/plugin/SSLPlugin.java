package io.javalin.ssl.plugin;

import io.javalin.Javalin;
import io.javalin.core.plugin.Plugin;
import org.eclipse.jetty.server.*;
import org.jetbrains.annotations.NotNull;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import static io.javalin.ssl.plugin.ConnectorUtils.*;

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

        javalin._conf.server(() -> {
            Server server;

            //Check if the server has been manually configured
            server = Objects.requireNonNullElseGet(javalin._conf.inner.server, Server::new);

            //parseConfig returns a consumer configuring the server.
            createJettyServerPatcher(config).accept(server);

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

        return (server) -> {

            List<Connector> connectorList = new LinkedList<>();

            if (!config.disableInsecure) {
                connectorList.add(createInsecureConnector(config, server));
            }

            if (!config.disableSecure) {
                connectorList.add(createSecureConnector(config, server));
            }

            if (config.enableHttp3) {
                connectorList.add(createHttp3Connector(config, server));
            }

            connectorList.forEach(server::addConnector);
        };
    }

}

