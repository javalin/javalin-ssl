package io.javalin.community.ssl.certs;

import io.javalin.Javalin;
import io.javalin.community.ssl.IntegrationTestClass;
import io.javalin.community.ssl.SSLPlugin;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.pem.util.PemUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import java.util.Objects;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the testing the trust of Certificates using a CA.
 * <a href="https://github.com/javalin/javalin-ssl/issues/56#issuecomment-1378373123">issue</a>
 */
@Tag("integration")
public class CertificateAuthorityTests extends IntegrationTestClass {

    public static final String ROOT_CERT_NAME = "ca/root-ca.cer";

    public static final String CLIENT_FULLCHAIN_CER = "ca/client-fullchain.cer";
    public static final String CLIENT_CER = "ca/client-nochain.cer";
    public static final String CLIENT_KEY_NAME = "ca/client.key";

    public static final String SERVER_CERT_NAME = "ca/server.cer";
    public static final String SERVER_KEY_NAME = "ca/server.key";

    protected static void testSuccessfulEndpoint(String url, OkHttpClient client) throws IOException {
        Response response = client.newCall(new Request.Builder().url(url).build()).execute();
        assertEquals(200, response.code());
        assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        response.close();
        client.connectionPool().evictAll();

    }

    protected static void testWrongCertOnEndpoint(String url, OkHttpClient client) {
        assertThrows(Exception.class, () -> {
            client.newCall(new Request.Builder().url(url).build()).execute().close();
            client.connectionPool().evictAll();
        });
    }

    protected static void assertClientWorks(OkHttpClient client) {
        int securePort = ports.getAndIncrement();
        String url = HTTPS_URL_WITH_PORT.apply(securePort);

        try (Javalin ignored = createTestApp(config -> {
            config.insecure = false;
            config.securePort = securePort;
            config.pemFromClasspath(SERVER_CERT_NAME, SERVER_KEY_NAME);
            config.http2 = false;
            config.withTrustConfig(trustConfig -> trustConfig.certificateFromClasspath(ROOT_CERT_NAME));
        }).start()) {
            testSuccessfulEndpoint(url, client);
        } catch (Exception e) {
            fail(e);
        }
    }

    protected static void assertClientFails(OkHttpClient client) {
        int securePort = ports.getAndIncrement();
        String url = HTTPS_URL_WITH_PORT.apply(securePort);

        try (Javalin ignored = createTestApp(config -> {
            config.insecure = false;
            config.securePort = securePort;
            config.pemFromClasspath(SERVER_CERT_NAME, SERVER_KEY_NAME);
            config.http2 = false;
            config.withTrustConfig(trustConfig -> trustConfig.certificateFromClasspath(ROOT_CERT_NAME));
        }).start()) {
            testWrongCertOnEndpoint(url, client);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    @DisplayName("Client certificate works when trusting root CA")
    void clientCertificateWorksWhenTrustingRootCA() {
        final X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(CLIENT_FULLCHAIN_CER, CLIENT_KEY_NAME);

        SSLFactory sslFactory = SSLFactory.builder()
            .withIdentityMaterial(keyManager)
            .withTrustingAllCertificatesWithoutValidation()
            .build();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().orElseThrow());
        builder.hostnameVerifier(sslFactory.getHostnameVerifier());
        assertClientWorks(builder.build());
    }

    @Test
    @DisplayName("Client fails when no certificate is provided")
    void noCertificateFails() {
        SSLFactory sslFactory = SSLFactory.builder()
            .withTrustingAllCertificatesWithoutValidation()
            .build();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().orElseThrow());
        builder.hostnameVerifier(sslFactory.getHostnameVerifier());

        assertClientFails(builder.build());
    }

    @Test
    @DisplayName("Client fails when a self-signed certificate is provided, and a CA is trusted")
    void selfsignedCertificateFails() {
        SSLFactory sslFactory = SSLFactory.builder()
            .withIdentityMaterial(PemUtils.parseIdentityMaterial(Client.CLIENT_CERTIFICATE_AS_STRING, Client.CLIENT_PRIVATE_KEY_AS_STRING, "".toCharArray()))
            .withTrustingAllCertificatesWithoutValidation()
            .build();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().orElseThrow());
        builder.hostnameVerifier(sslFactory.getHostnameVerifier());

        assertClientFails(builder.build());
    }

    @Test
    @DisplayName("Client fails when a certificate without chain is provided, and a CA is trusted")
    void certificateWithoutChainFails() {

        final X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(CLIENT_CER, CLIENT_KEY_NAME);

        SSLFactory sslFactory = SSLFactory.builder()
            .withIdentityMaterial(keyManager)
            .withTrustingAllCertificatesWithoutValidation()
            .build();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().orElseThrow());
        builder.hostnameVerifier(sslFactory.getHostnameVerifier());
        assertClientFails(builder.build());
    }

    @Test
    @DisplayName("mTLS works when trusting a root CA, and an intermediate CA issues both the client and server certificates")
    void mTLSWithIntermediateIssuerCAAndTrustedRootWorks() {
        final X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(CLIENT_FULLCHAIN_CER, CLIENT_KEY_NAME);

        SSLFactory sslFactory = SSLFactory.builder()
            .withIdentityMaterial(keyManager)
            .withTrustMaterial(PemUtils.loadTrustMaterial(ROOT_CERT_NAME))
            .withUnsafeHostnameVerifier() // we don't care about the hostname, we just want to test the certificate
            .build();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().orElseThrow());
        builder.hostnameVerifier(sslFactory.getHostnameVerifier());
        assertClientWorks(builder.build());
    }

    @Test
    @DisplayName("Hot reloading works when using mTLS")
    void mTLSWithHotReloadingWorks() {
        final X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(CLIENT_FULLCHAIN_CER, CLIENT_KEY_NAME);

        Supplier<OkHttpClient> client = () -> {
            SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(keyManager)
                .withTrustMaterial(PemUtils.loadTrustMaterial(ROOT_CERT_NAME)) // root cert of the client above
                .withUnsafeHostnameVerifier() // we don't care about the hostname, we just want to test the certificate
                .build();

            return new OkHttpClient.Builder()
                .sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().orElseThrow())
                .hostnameVerifier(sslFactory.getHostnameVerifier())
                .build();
        };
        int securePort = ports.getAndIncrement();
        String url = HTTPS_URL_WITH_PORT.apply(securePort);

        SSLPlugin sslPlugin = new SSLPlugin(config -> {
            config.insecure = false;
            config.securePort = securePort;
            config.pemFromClasspath(SERVER_CERT_NAME, SERVER_KEY_NAME);
            config.http2 = false;
            config.configConnectors((conn) -> conn.setIdleTimeout(0)); // disable idle timeout for testing
            config.withTrustConfig(trustConfig -> trustConfig.certificateFromClasspath(ROOT_CERT_NAME));
        });


        try (Javalin ignored = Javalin.create((javalinConfig) -> {
                javalinConfig.showJavalinBanner = false;
                javalinConfig.plugins.register(sslPlugin);
            }).get("/", ctx -> ctx.result(SUCCESS))
            .start()) {
            testSuccessfulEndpoint(url, client.get()); // works
            sslPlugin.reload(config -> {
                config.pemFromClasspath(SERVER_CERT_NAME, SERVER_KEY_NAME);
                config.withTrustConfig(trustConfig -> {
                    trustConfig.certificateFromClasspath(Server.CERTIFICATE_FILE_NAME); // this is some other certificate
                });
            });
            testWrongCertOnEndpoint(url, client.get()); // fails because the server now has a different trust material
            sslPlugin.reload(config -> {
                config.pemFromClasspath(SERVER_CERT_NAME, SERVER_KEY_NAME);
                config.withTrustConfig(trustConfig -> {
                    trustConfig.certificateFromClasspath(ROOT_CERT_NAME); // back to the original certificate
                });
            });
            testSuccessfulEndpoint(url, client.get()); // works again
        } catch (Exception e) {
            fail(e);
        }
    }


}
