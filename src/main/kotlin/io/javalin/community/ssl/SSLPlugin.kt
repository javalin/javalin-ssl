package io.javalin.community.ssl

import io.javalin.community.ssl.util.ConnectorFactory
import io.javalin.community.ssl.util.SSLUtils
import io.javalin.config.JavalinConfig
import io.javalin.plugin.JavalinPlugin
import io.javalin.plugin.createUserConfig
import nl.altindag.ssl.SSLFactory
import nl.altindag.ssl.util.SSLFactoryUtils
import org.eclipse.jetty.server.Connector
import org.eclipse.jetty.server.HttpConfiguration
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.handler.SecuredRedirectHandler
import org.eclipse.jetty.util.ssl.SslContextFactory
import java.util.function.BiFunction
import java.util.function.Consumer


class SSLPlugin (config: Consumer<SSLConfig>) : JavalinPlugin {

    private var sslFactory: SSLFactory? = null
    private var pluginConfig = config.createUserConfig(SSLConfig())

    override fun onStart(config: JavalinConfig) {
        config.jetty.connectors.addAll(createConnectors(pluginConfig))
        if(pluginConfig.redirect && pluginConfig.secure) {
            config.jetty.modifyServer{
                it.handler = SecuredRedirectHandler()
            }
        }
    }

    override fun name(): String = "SSL Plugin"

    fun reload(newConfig: Consumer<SSLConfig>) {
        val conf = SSLConfig()
        newConfig.accept(conf)
        checkNotNull(sslFactory) { "Cannot reload before the plugin has been applied to a Javalin instance, a server has been patched or if the ssl connector is disabled." }
        val newFactory = SSLUtils.getSslFactory(conf, true)
        SSLFactoryUtils.reload(sslFactory, newFactory)
    }


    private fun createConnectors(config: SSLConfig): List<BiFunction<Server, HttpConfiguration, Connector>> {

        //Created outside the lambda to have exceptions thrown in the current scope
        val sslContextFactory: SslContextFactory.Server?
        if (config.secure || config.enableHttp3) {
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
        if (config.enableHttp3) {
            //TODO: Implement HTTP/3 when tipsy merges the PR
            throw UnsupportedOperationException("HTTP/3 is not supported yet")
        }
        return connectorList


    }
}
