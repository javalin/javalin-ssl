package io.javalin.community.ssl

import io.javalin.Javalin
import io.javalin.community.ssl.certs.Server
import okhttp3.OkHttpClient
import okhttp3.Request
import org.eclipse.jetty.server.ConnectionFactory
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.SslConnectionFactory
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.IOException
import java.util.*

@Tag("integration")
class SSLConfigTests : IntegrationTestClass() {
    @Test
    fun `Test that the insecure connector is disabled when insecure is set to false`() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecure = false
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.securePort = securePort
                config.insecurePort = insecurePort
            }.start().let { app ->
                Assertions.assertThrows(Exception::class.java) {
                    client.newCall(Request.Builder().url(http).build()).execute()
                } // should throw exception
                val response = client.newCall(Request.Builder().url(https).build()).execute() // should not throw exception
                Assertions.assertEquals(200, response.code)
                Assertions.assertEquals(SUCCESS, Objects.requireNonNull(response.body)?.string())
                app.stop()
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the secure connector is disabled when insecure is set to true")
    fun testDisableSecure() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.secure = false
                config.insecurePort = insecurePort
                config.securePort = securePort
            }.start().let { _ ->
                Assertions.assertThrows(Exception::class.java) {
                    client.newCall(Request.Builder().url(https).build()).execute()
                } // should throw exception
                val response = client.newCall(Request.Builder().url(http).build()).execute() // should not throw exception
                Assertions.assertEquals(200, response.code)
                Assertions.assertEquals(SUCCESS, Objects.requireNonNull(response.body)?.string())
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the insecure port can be changed")
    fun testInsecurePortChange() {
        try {
            createTestApp { config: SSLConfig ->
                config.secure = false
                config.insecurePort = 8080
            }.start().let { _ ->
                val response = client.newCall(Request.Builder().url("http://localhost:8080/").build())
                    .execute() // should not throw exception
                Assertions.assertEquals(200, response.code)
                Assertions.assertEquals(SUCCESS, Objects.requireNonNull(response.body)?.string())
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the secure port can be changed")
    fun testSecurePortChange() {
        try {
            createTestApp { config: SSLConfig ->
                config.insecure = false
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.securePort = 8443
            }.start().let { _ ->
                val response = client.newCall(Request.Builder().url("https://localhost:8443/").build())
                    .execute() // should not throw exception
                Assertions.assertEquals(200, response.code)
                Assertions.assertEquals(SUCCESS, Objects.requireNonNull(response.body)?.string())
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that redirecting from http to https works")
    fun testRedirect() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        val noRedirectClient: OkHttpClient = untrustedClientBuilder().also { it.followSslRedirects(false) }.build()
        try {
            createTestApp { config: SSLConfig ->
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.securePort = securePort
                config.insecurePort = insecurePort
                config.redirect = true
            }.start().let { _ ->
                val redirect = noRedirectClient.newCall(Request.Builder().url(http).build()).execute()
                Assertions.assertTrue(redirect.isRedirect)
                Assertions.assertEquals(https, redirect.header("Location"))
                val redirected = client.newCall(Request.Builder().url(http).build()).execute()
                Assertions.assertEquals(200, redirected.code)
                Assertions.assertEquals(SUCCESS, redirected.body!!.string())
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the insecure connector works with http1.1")
    fun testInsecureHttp1() {
        val insecurePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        try {
            createTestApp { config: SSLConfig ->
                config.secure = false
                config.http2 = false
                config.insecurePort = insecurePort
            }.start().let { _ -> testSuccessfulEndpoint(http, okhttp3.Protocol.HTTP_1_1) }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that http2 can be disabled on the insecure connector")
    fun testInsecureDisableHttp2() {
        val http2client: OkHttpClient =
            listOf(okhttp3.Protocol.H2_PRIOR_KNOWLEDGE).let{ OkHttpClient.Builder().protocols(it).build() }
        val http1Client: OkHttpClient = OkHttpClient.Builder().build()
        val insecurePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        try {
            createTestApp { config: SSLConfig ->
                config.secure = false
                config.http2 = false
                config.insecurePort = insecurePort
            }.start().let { _ ->
                Assertions.assertThrows(Exception::class.java) {
                    http2client.newCall(
                        Request.Builder().url(http).build()
                    ).execute()
                } // Should fail to connect using HTTP/2
                testSuccessfulEndpoint(http1Client, http, okhttp3.Protocol.HTTP_1_1)
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    fun `Test that http2 can be disabled on the secure connector`() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.http2 = false
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.securePort = securePort
                config.insecurePort = insecurePort
            }.start().let { _ -> testSuccessfulEndpoint(https, okhttp3.Protocol.HTTP_1_1) }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    fun `Test that the insecure connector works with http2`() {
        val client: OkHttpClient =
            listOf(okhttp3.Protocol.H2_PRIOR_KNOWLEDGE).let { OkHttpClient.Builder().protocols(it).build() }
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        try {
            createTestApp { config: SSLConfig ->
                config.secure = false
                config.http2 = true
                config.insecurePort = insecurePort
                config.securePort = securePort
            }.start().let { _ -> testSuccessfulEndpoint(client, http, okhttp3.Protocol.H2_PRIOR_KNOWLEDGE) }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    fun `Test that the secure connector works with http2`() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.securePort = securePort
                config.insecurePort = insecurePort
            }.start().let { _ -> testSuccessfulEndpoint(https, okhttp3.Protocol.HTTP_2) }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that by default both connectors are enabled, and that http1 and http2 works")
    fun testDefault() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecurePort = insecurePort
                config.securePort = securePort
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            }.start().let { _ ->
                testSuccessfulEndpoint(http, okhttp3.Protocol.HTTP_1_1)
                testSuccessfulEndpoint(https, okhttp3.Protocol.HTTP_2)
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the host can be changed")
    fun testMatchingHost() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecurePort = insecurePort
                config.securePort = securePort
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.host = "localhost"
            }.start().let { _ ->
                testSuccessfulEndpoint(http, okhttp3.Protocol.HTTP_1_1)
                testSuccessfulEndpoint(https, okhttp3.Protocol.HTTP_2)
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the host change fails when it doesn't match")
    fun testWrongHost() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        try {
            createTestApp { config: SSLConfig ->
                config.insecurePort = insecurePort
                config.securePort = securePort
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.host = "wronghost"
            }.start().let { _ -> Assertions.fail<Any>() }
        } catch (ignored: Exception) {}
    }

    @Test
    @DisplayName("Test that sniHostCheck works when it matches")
    fun testEnabledSniHostCheckAndMatchingHostname() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecurePort = insecurePort
                config.securePort = securePort
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.host = "localhost"
                config.sniHostCheck = true
            }.start().let { _ ->
                testSuccessfulEndpoint(http, okhttp3.Protocol.HTTP_1_1)
                testSuccessfulEndpoint(https, okhttp3.Protocol.HTTP_2)
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that sniHostCheck fails when it doesn't match over https")
    fun testEnabledSniHostCheckAndWrongHostname() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecurePort = insecurePort
                config.securePort = securePort
                config.pemFromString(Server.GOOGLE_CERTIFICATE_AS_STRING, Server.GOOGLE_KEY_AS_STRING)
                config.host = "localhost"
                config.sniHostCheck = true
            }.start().let { _ ->
                //http request should be successful
                testSuccessfulEndpoint(untrustedClient, http, okhttp3.Protocol.HTTP_1_1)
                //https request should fail
                val wrongHttpsResponse = untrustedClient.newCall(Request.Builder().url(https).build()).execute()
                Assertions.assertEquals(400, wrongHttpsResponse.code)
                Assertions.assertTrue(
                    Objects.requireNonNull(wrongHttpsResponse.body)?.string()!!.contains("Error 400 Invalid SNI")
                )
                wrongHttpsResponse.close()
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that sniHostCheck can be disabled and a request with a wrong hostname can be made")
    fun testDisabledSniHostCheck() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecurePort = insecurePort
                config.securePort = securePort
                config.pemFromString(Server.GOOGLE_CERTIFICATE_AS_STRING, Server.GOOGLE_KEY_AS_STRING)
                config.host = "localhost"
                config.sniHostCheck = false
            }.start().let { _ ->
                testSuccessfulEndpoint(untrustedClient, http, okhttp3.Protocol.HTTP_1_1)
                testSuccessfulEndpoint(untrustedClient, https, okhttp3.Protocol.HTTP_2)
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the connectors can be configured through the consumer")
    fun testConnectorConfigConsumer() {
        val insecurePort = ports.getAndIncrement()
        val securePort = ports.getAndIncrement()
        val http = HTTP_URL_WITH_PORT.apply(insecurePort)
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecurePort = insecurePort
                config.securePort = securePort
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.configConnectors { connector: ServerConnector ->
                    connector.setIdleTimeout(1000)
                    connector.name = "customName"
                }
            }.start().let { app ->
                testSuccessfulEndpoint(http, okhttp3.Protocol.HTTP_1_1)
                testSuccessfulEndpoint(https, okhttp3.Protocol.HTTP_2)
                for (connector in app.unsafeConfig().pvt.jetty.server!!.connectors) {
                    Assertions.assertEquals(1000, connector.idleTimeout)
                    Assertions.assertEquals("customName", connector.name)
                }
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the Security Provider can be automatically configured when the config is set to null")
    fun testNullSecurityProvider() {
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecure = false
                config.securePort = securePort
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
                config.securityProvider = null
            }.start().let { app ->
                printSecurityProviderName(app)
                testSuccessfulEndpoint(https, okhttp3.Protocol.HTTP_2)
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    @Test
    @DisplayName("Test that the Security Provider works when it is set to the default")
    fun testDefaultSecurityProvider() {
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        try {
            createTestApp { config: SSLConfig ->
                config.insecure = false
                config.securePort = securePort
                config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            }.start().let { app ->
                printSecurityProviderName(app)
                testSuccessfulEndpoint(https, okhttp3.Protocol.HTTP_2)
            }
        } catch (e: IOException) {
            Assertions.fail<Any>(e)
        }
    }

    companion object {
        private fun getSecurityProviderName(app: Javalin): String {
            val conn = app.jettyServer()!!.server().getConnectors()[0] as ServerConnector
            return conn.connectionFactories.stream()
                .filter { cf: ConnectionFactory? -> cf is SslConnectionFactory }
                .map { cf: ConnectionFactory -> cf as SslConnectionFactory }
                .map { sslConnectionFactory: SslConnectionFactory -> sslConnectionFactory.sslContextFactory.sslContext.provider.name }
                .findFirst()
                .orElseThrow()
        }

        private fun printSecurityProviderName(app: Javalin) {
            println("Security provider: " + getSecurityProviderName(app))
        }
    }
}
