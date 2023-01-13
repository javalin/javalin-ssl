package io.javalin.community.ssl;

import io.javalin.Javalin;
import io.javalin.community.ssl.certs.Server;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLHandshakeException;
import java.net.UnknownServiceException;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("integration")
public class TLSConfigTest extends IntegrationTestClass {

    private static String[] substractArray(String[] array, String[] toRemove) {
        return Arrays.stream(array).filter(s -> !Arrays.asList(toRemove).contains(s)).toArray(String[]::new);
    }

    private static OkHttpClient clientWithTLSConfig(TLSConfig config) {

        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .tlsVersions(config.getProtocols())
            .cipherSuites(config.getCipherSuites())
            .build();

        new TLSConfig(new String[]{""}, new String[]{""});
        return untrustedClientBuilder()
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }

    @Test
    @DisplayName("Test that a Modern TLS config does not allow old protocols")
    void testModernConfigWithOldProtocols() {

        String[] protocols = substractArray(TLSConfig.OLD.getProtocols(), TLSConfig.MODERN.getProtocols()); // remove modern protocols from old protocols, so that ONLY unsupported protocols are left

        OkHttpClient client = clientWithTLSConfig(new TLSConfig(TLSConfig.MODERN.getCipherSuites(), protocols));

        int securePort = ports.getAndIncrement();
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecure = false;
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING);
            config.securePort = securePort;
            config.tlsConfig = TLSConfig.MODERN;
        }).start()) {
            //Should fail with SSLHandshakeException because of the old protocols
            assertThrows(SSLHandshakeException.class, () -> client.newCall(new Request.Builder().url(https).build()).execute());
        }
    }

    @Test
    @DisplayName("Test that a Modern TLS config does not allow old cipher suites")
    void testModernConfigWithOldCipherSuites() {

        String[] cipherSuites = substractArray(TLSConfig.OLD.getCipherSuites(), TLSConfig.MODERN.getCipherSuites()); // remove modern cipher suites from old cipher suites, so that we can test ONLY the old cipher suites

        OkHttpClient client = clientWithTLSConfig(new TLSConfig(cipherSuites, TLSConfig.MODERN.getProtocols()));

        int securePort = ports.getAndIncrement();
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecure = false;
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING);
            config.securePort = securePort;
            config.tlsConfig = TLSConfig.MODERN;
        }).start()) {
            //Should fail with SSLHandshakeException because of the old cipher suites
            assertThrows(SSLHandshakeException.class, () -> client.newCall(new Request.Builder().url(https).build()).execute());
        }
    }

    @Test
    @DisplayName("Test that an Intermediate TLS config does not allow old protocols")
    void testIntermediateConfigWithOldProtocols() {

        String[] protocols = substractArray(TLSConfig.OLD.getProtocols(), TLSConfig.INTERMEDIATE.getProtocols()); // remove intermediate protocols from old protocols, so that ONLY unsupported protocols are left

        OkHttpClient client = clientWithTLSConfig(new TLSConfig(TLSConfig.INTERMEDIATE.getCipherSuites(), protocols));

        int securePort = ports.getAndIncrement();
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecure = false;
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING);
            config.securePort = securePort;
            config.tlsConfig = TLSConfig.INTERMEDIATE;
        }).start()) {
            //Should fail with SSLHandshakeException because of the old protocols
            assertThrows(UnknownServiceException.class, () -> client.newCall(new Request.Builder().url(https).build()).execute());
        }
    }


    @Test
    @DisplayName("Test that an Intermediate TLS config does not allow old cipher suites")
    void testIntermediateConfigWithOldCipherSuites() {

        String[] cipherSuites = substractArray(TLSConfig.OLD.getCipherSuites(), TLSConfig.INTERMEDIATE.getCipherSuites()); // remove intermediate cipher suites from old cipher suites, so that we can test ONLY the old cipher suites

        OkHttpClient client = clientWithTLSConfig(new TLSConfig(cipherSuites, TLSConfig.INTERMEDIATE.getProtocols()));

        int securePort = ports.getAndIncrement();
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecure = false;
            config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING);
            config.securePort = securePort;
            config.tlsConfig = TLSConfig.INTERMEDIATE;
        }).start()) {
            //Should fail with SSLHandshakeException because of the old cipher suites
            assertThrows(SSLHandshakeException.class, () -> client.newCall(new Request.Builder().url(https).build()).execute());
        }
    }

}
