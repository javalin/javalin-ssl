package io.javalin.community.ssl

import io.javalin.community.ssl.util.ConnectorFactory
import io.javalin.community.ssl.util.SSLUtils
import io.javalin.config.JavalinConfig
import io.javalin.plugin.JavalinPlugin
import io.javalin.plugin.PluginFactory
import io.javalin.plugin.createUserConfig
import io.javalin.router.JavalinDefaultRouting.Companion.Default
import nl.altindag.ssl.SSLFactory
import nl.altindag.ssl.util.SSLFactoryUtils
import org.eclipse.jetty.server.Connector
import org.eclipse.jetty.server.HttpConfiguration
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.handler.SecuredRedirectHandler
import org.eclipse.jetty.util.ssl.SslContextFactory
import java.util.function.BiFunction
import java.util.function.Consumer


/**
 * Plugin to add SSL support to Javalin.
 * The configuration is done via the Consumer<SSLConfig> passed to the constructor.
 * The plugin will add the connectors to the server and apply the necessary handlers.
 *
 * If you want to reload the SSLContextFactory, you can call the reload method, by keeping a reference to the plugin instance.
 */
class SSLPlugin (config: Consumer<SSLConfig>) : JavalinPlugin {

    open class SSLPluginFactory : PluginFactory<SSLPlugin,SSLConfig> {
        override fun create(config: Consumer<SSLConfig>): SSLPlugin = SSLPlugin(config)

    }

    companion object {
        object SSL : SSLPluginFactory()
    }

    private var sslFactory: SSLFactory? = null
    private var pluginConfig = config.createUserConfig(SSLConfig())

    override fun onStart(config: JavalinConfig) {
        //Add the connectors to the server
        config.jetty.connectors.addAll(createConnectors(pluginConfig))

        if(pluginConfig.redirect && pluginConfig.secure) {
            config.jetty.modifyServer{
                it.handler = SecuredRedirectHandler()
            }
            if(!pluginConfig.disableHttp3Upgrade){
                //Add the Alt-Svc header to enable HTTP/3 upgrade, using the configured port
                config.router.mount(Default){
                    it.after {ctx ->
                        ctx.header("Alt-Svc","h3=\":${pluginConfig.http3Port}\"")
                    }
                }
            }
        }

    }

    override fun name(): String = "SSL Plugin"

    /**
     * Reload the SSL configuration with the new certificates and/or keys.
     * @param newConfig The new configuration.
     */
    fun reload(newConfig: Consumer<SSLConfig>) {
        val conf = SSLConfig()
        newConfig.accept(conf)
        checkNotNull(sslFactory) { "Cannot reload before the plugin has been applied to a Javalin instance, a server has been patched or if the ssl connector is disabled." }
        val newFactory = SSLUtils.getSslFactory(conf, true)
        SSLFactoryUtils.reload(sslFactory, newFactory)
    }


    private fun createConnectors(config: SSLConfig): List<BiFunction<Server, HttpConfiguration, Connector>> {

        val sslContextFactory: SslContextFactory.Server?
        if (config.secure || config.http3) {
            sslFactory = SSLUtils.getSslFactory(config)
            sslContextFactory = SSLUtils.createSslContextFactory(sslFactory)
        } else {
            sslContextFactory = null
        }
        val connectorList = ArrayList<BiFunction<Server, HttpConfiguration, Connector>>()

        val connectorFactory =
            ConnectorFactory(config, sslContextFactory)

        if (config.insecure) {
            connectorList.add(connectorFactory::createInsecureConnector)
        }
        if (config.secure) {
            connectorList.add(connectorFactory::createSecureConnector)
        }
        if (config.http3) {
            //TODO: Implement HTTP/3 when tipsy merges the PR
            throw UnsupportedOperationException("HTTP/3 is not supported yet")
        }
        return connectorList


    }
}
