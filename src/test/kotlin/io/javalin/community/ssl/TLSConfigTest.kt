package io.javalin.community.ssl

import io.javalin.community.ssl.certs.Server
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.net.UnknownServiceException
import javax.net.ssl.SSLHandshakeException


@Tag("integration")
class TLSConfigTest : IntegrationTestClass() {
    @Test
    fun `test that a Modern TLS config does not allow old protocols`() {

        val protocols = TLSConfig.OLD.protocols.subtract(TLSConfig.MODERN.protocols.asIterable().toSet())

        // remove modern protocols from old protocols, so that ONLY unsupported protocols are left
        val client = clientWithTLSConfig(TLSConfig(TLSConfig.MODERN.cipherSuites, protocols.toTypedArray()))
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.MODERN
        }.start().let { _ ->
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
    fun `test that a Modern TLS config does not allow old cipher suites`() {
        val cipherSuites = TLSConfig.OLD.cipherSuites.subtract(TLSConfig.MODERN.cipherSuites.asIterable().toSet())
        // remove modern cipher suites from old cipher suites, so that we can test ONLY the old cipher suites
        val client = clientWithTLSConfig(TLSConfig(cipherSuites.toTypedArray(), TLSConfig.MODERN.protocols))
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.MODERN
        }.start().let { _ ->
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
    fun `test that an Intermediate TLS config does not allow old protocols`() {
        val protocols = TLSConfig.OLD.protocols.subtract(TLSConfig.INTERMEDIATE.protocols.asIterable().toSet())
        // remove intermediate protocols from old protocols, so that ONLY unsupported protocols are left
        val client = clientWithTLSConfig(TLSConfig(TLSConfig.INTERMEDIATE.cipherSuites, protocols.toTypedArray()))
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.INTERMEDIATE
        }.start().let { _ ->
            //Should fail with SSLHandshakeException because of the old protocols
            Assertions.assertThrows(UnknownServiceException::class.java) {
                client.newCall(
                    Request.Builder().url(https).build()
                ).execute()
            }
        }
    }

    @Test
    fun `test that an Intermediate TLS config does not allow old cipher suites`(){
        val cipherSuites = TLSConfig.OLD.cipherSuites.subtract(TLSConfig.INTERMEDIATE.cipherSuites.asIterable().toSet())
        // remove intermediate cipher suites from old cipher suites, so that we can test ONLY the old cipher suites
        val client = clientWithTLSConfig(TLSConfig(cipherSuites.toTypedArray(), TLSConfig.INTERMEDIATE.protocols))
        val securePort = ports.getAndIncrement()
        val https = HTTPS_URL_WITH_PORT.apply(securePort)
        createTestApp { config: SSLConfig ->
            config.insecure = false
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING)
            config.securePort = securePort
            config.tlsConfig = TLSConfig.INTERMEDIATE
        }.start().let { _ ->
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
