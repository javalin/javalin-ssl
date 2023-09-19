package io.javalin.community.ssl

import io.javalin.community.ssl.certs.Server
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.TlsVersion
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.net.UnknownServiceException
import javax.net.ssl.SSLHandshakeException

@Tag("integration")
class TLSConfigTest : IntegrationTestClass() {
    @Test
    @DisplayName("Test that a Modern TLS config does not allow old protocols")
    fun testModernConfigWithOldProtocols() {

        val protocols = TLSConfig.OLD.protocols.subtract(TLSConfig.MODERN.protocols.asIterable())

        // remove modern protocols from old protocols, so that ONLY unsupported protocols are left
        val client = clientWithTLSConfig(TLSConfig(TLSConfig.MODERN.cipherSuites, protocols.toTypedArray()))
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.MODERN
        }.start().use { _ ->
            //Should fail with SSLHandshakeException because of the old protocols
            Assertions.assertThrows(SSLHandshakeException::class.java) {
                client.newCall(
                    Request.Builder().url(
                        https
                    ).build()
                ).execute()
            }
        }
    }

    @Test
    @DisplayName("Test that a Modern TLS config does not allow old cipher suites")
    fun testModernConfigWithOldCipherSuites() {
        val cipherSuites = TLSConfig.OLD.cipherSuites.subtract(TLSConfig.MODERN.cipherSuites.asIterable())
        // remove modern cipher suites from old cipher suites, so that we can test ONLY the old cipher suites
        val client = clientWithTLSConfig(TLSConfig(cipherSuites.toTypedArray(), TLSConfig.MODERN.protocols))
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.MODERN
        }.start().use { _ ->
            //Should fail with SSLHandshakeException because of the old cipher suites
            Assertions.assertThrows(SSLHandshakeException::class.java) {
                client.newCall(
                    Request.Builder().url(
                        https
                    ).build()
                ).execute()
            }
        }
    }

    @Test
    @DisplayName("Test that an Intermediate TLS config does not allow old protocols")
    fun testIntermediateConfigWithOldProtocols() {
        val protocols = TLSConfig.OLD.protocols.subtract(TLSConfig.INTERMEDIATE.protocols.asIterable())
        // remove intermediate protocols from old protocols, so that ONLY unsupported protocols are left
        val client = clientWithTLSConfig(TLSConfig(TLSConfig.INTERMEDIATE.cipherSuites, protocols.toTypedArray()))
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.INTERMEDIATE
        }.start().use { _ ->
            //Should fail with SSLHandshakeException because of the old protocols
            Assertions.assertThrows(UnknownServiceException::class.java) {
                client.newCall(
                    Request.Builder().url(https).build()
                ).execute()
            }
        }
    }

    @Test
    @DisplayName("Test that an Intermediate TLS config does not allow old cipher suites")
    fun testIntermediateConfigWithOldCipherSuites() {
        val cipherSuites = TLSConfig.OLD.cipherSuites.subtract(TLSConfig.INTERMEDIATE.cipherSuites.asIterable())
        // remove intermediate cipher suites from old cipher suites, so that we can test ONLY the old cipher suites
        val client = clientWithTLSConfig(TLSConfig(cipherSuites.toTypedArray(), TLSConfig.INTERMEDIATE.protocols))
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.INTERMEDIATE
        }.start().use { _ ->
            //Should fail with SSLHandshakeException because of the old cipher suites
            Assertions.assertThrows(SSLHandshakeException::class.java) {
                client.newCall(
                    Request.Builder().url(
                        https
                    ).build()
                ).execute()
            }
        }
    }

    @Test
    @DisplayName("Test an Intermediate TLS config works with TLSv1.3")
    fun testIntermediateConfigWithTLSv13() {
        val spec: ConnectionSpec = ConnectionSpec.RESTRICTED_TLS
        val client: OkHttpClient = untrustedClientBuilder().connectionSpecs(listOf(spec))
            .build()
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.INTERMEDIATE
        }.start().use { _ ->
            //Should work with TLSv1.3
            try {
                client.newCall(Request.Builder().url(https).build()).execute().use { response ->
                    Assertions.assertEquals(200, response.code)
                    Assertions.assertEquals(TlsVersion.TLS_1_3, response.handshake!!.tlsVersion)
                }
            } catch (e: Exception) {
                e.printStackTrace()
                Assertions.fail<Any>(e)
            }
        }
    }

    companion object {

        private fun clientWithTLSConfig(config: TLSConfig): OkHttpClient {


            val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .cipherSuites(*config.cipherSuites)
                .tlsVersions(*config.protocols)
                .build()

            return listOf(spec).let {
                OkHttpClient.Builder()
                    .connectionSpecs(it)
                    .build()
            }
        }
    }
}
