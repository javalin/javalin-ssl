package io.javalin.community.ssl;

import io.javalin.Javalin;
import io.javalin.community.ssl.certs.Client;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.tls.Certificates;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

@SuppressWarnings("CodeBlock2Expr")
@Tag("integration")
public class TrustConfigTests extends IntegrationTestClass {

    private static final Supplier<OkHttpClient> authenticatedClient =
        () -> httpsClientBuilder(Client.CLIENT_CERTIFICATE_AS_STRING, Client.CLIENT_PRIVATE_KEY_AS_STRING);


    private static final Supplier<OkHttpClient> wrongClient =
        () -> httpsClientBuilder(Client.WRONG_CLIENT_CERTIFICATE_AS_STRING, Client.WRONG_CLIENT_PRIVATE_KEY_AS_STRING);

    private static final Supplier<HttpClient> wrongJavaClient =
        () -> javaHttpClientBuilder(Client.WRONG_CLIENT_CERTIFICATE_AS_STRING, Client.WRONG_CLIENT_PRIVATE_KEY_AS_STRING);
    private static OkHttpClient httpsClientBuilder(String clientCertificate, String privateKey) {
        HandshakeCertificates.Builder builder = new HandshakeCertificates.Builder();
        //Server certificate
        builder.addTrustedCertificate(Certificates.decodeCertificatePem(Client.SERVER_CERTIFICATE_AS_STRING));

        //Client certificate (Concatenated with the private key)
        HeldCertificate heldCertificate = HeldCertificate
            .decode(clientCertificate + privateKey);
        builder.heldCertificate(heldCertificate);

        HandshakeCertificates clientCertificates = builder.build();

        final SSLContext sslContext;

        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            sslContext.init(new X509KeyManager[]{clientCertificates.keyManager()},
                new X509TrustManager[]{clientCertificates.trustManager()},
                null);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), clientCertificates.trustManager())
            .hostnameVerifier((hostname, session) -> true)
            .connectionPool(new okhttp3.ConnectionPool(0, 1, TimeUnit.MICROSECONDS))
            .build();
    }

    /**
     * Needed in order to test multiple wrong clients, see:
     * <a href="https://stackoverflow.com/a/32513368/5899345">Java HTTPS client certificate authentication</a>
     * <a href="https://stackoverflow.com/questions/54671365/java-caching-ssl-failures-can-i-flush-these-somehow">
     *     Java caching SSL failures - can I flush these somehow
     * </a>
     */
    private static HttpClient javaHttpClientBuilder(String clientCertificate, String privateKey){
        HandshakeCertificates.Builder builder = new HandshakeCertificates.Builder();
        //Server certificate
        builder.addTrustedCertificate(Certificates.decodeCertificatePem(Client.SERVER_CERTIFICATE_AS_STRING));

        //Client certificate (Concatenated with the private key)
        HeldCertificate heldCertificate = HeldCertificate
            .decode(clientCertificate + privateKey);
        builder.heldCertificate(heldCertificate);

        HandshakeCertificates clientCertificates = builder.build();

        final SSLContext sslContext;

        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            sslContext.init(new X509KeyManager[]{clientCertificates.keyManager()},
                new X509TrustManager[]{clientCertificates.trustManager()},
                null);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();

    }
    @Test
    void unauthenticatedUserFails() {
        OkHttpClient unauthClient = IntegrationTestClass.getClient(); //This is the client without the client certificate

        int securePort = ports.getAndIncrement();
        String url = HTTPS_URL_WITH_PORT.apply(securePort);

        try (Javalin ignored = createTestApp(config -> {
            config.insecure = false;
            config.securePort = securePort;
            config.http2 = false; // Disable HTTP/2 to avoid "connection closed" errors in tests due to connection reuse
            config.pemFromString(Client.SERVER_CERTIFICATE_AS_STRING, Client.SERVER_PRIVATE_KEY_AS_STRING);
            config.withTrustConfig(trustConfig -> {
                trustConfig.pemFromString(Client.CLIENT_CERTIFICATE_AS_STRING);
            });
        }).start()) {
            unauthClient.newCall(new Request.Builder().url(url).build()).execute();
        } catch (Exception e) {
            String error = "certificate_required";
            boolean errorInStackTrace =
                Arrays.stream(e.getSuppressed())
                    .anyMatch(throwable -> throwable.getMessage().contains(error));
            if(!errorInStackTrace) {
                fail(e);
            }

        }

    }

    @Test
    void wrongCertificateFails() {
        int securePort = ports.getAndIncrement();
        String url = HTTPS_URL_WITH_PORT.apply(securePort);

        try(Javalin ignored = createTestApp(config -> {
            config.insecure = false;
            config.securePort = securePort;
            config.http2 = false; // Disable HTTP/2 to avoid "connection closed" errors in tests due to connection reuse
            config.pemFromString(Client.SERVER_CERTIFICATE_AS_STRING, Client.SERVER_PRIVATE_KEY_AS_STRING);
            config.withTrustConfig(trustConfig -> {
                trustConfig.pemFromString(Client.CLIENT_CERTIFICATE_AS_STRING);
            });
        }).start()) {
            //wrongClient.get().newCall(new Request.Builder().url(url).build()).execute();
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();
            wrongJavaClient.get().send(req, (response) -> {
                return null;
            });
            fail("Should have thrown an exception");

        } catch (Exception e) {
            String error = "certificate_unknown";
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            boolean errorInStackTrace = sw.toString().contains(error);
            if(!errorInStackTrace) {
                fail(e);
            }
        }
    }

    protected static void testSuccessfulEndpoint(String url) throws IOException {
        OkHttpClient client = authenticatedClient.get();
        Response response = client.newCall(new Request.Builder().url(url).build()).execute();
        assertEquals(200, response.code());
        assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        response.close();
    }

    protected static void testWrongCertOnEndpoint(String url) {
        try {
            //TrustConfigTests.wrongClient.get().newCall(new Request.Builder().url(url).build()).execute();
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();
            wrongJavaClient.get().send(req, (response) -> {
                System.out.println(response.statusCode());
                return null;
            });
            fail("Should have thrown an exception");
        } catch (Exception e) {
            String error = "certificate_unknown";
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            boolean errorInStackTrace = sw.toString().contains(error);
            if(!errorInStackTrace) {
                fail(e);
            }
        }
    }

    protected static void trustConfigWorks(Consumer<TrustConfig> consumer){
        int securePort = ports.getAndIncrement();
        String url = HTTPS_URL_WITH_PORT.apply(securePort);

        try(Javalin ignored = createTestApp(config -> {
            config.insecure = false;
            config.securePort = securePort;
            config.pemFromString(Client.SERVER_CERTIFICATE_AS_STRING, Client.SERVER_PRIVATE_KEY_AS_STRING);
            config.http2 = false; // Disable HTTP/2 to avoid "connection closed" errors in tests due to connection reuse
            config.withTrustConfig(consumer);
        }).start()) {
            testSuccessfulEndpoint(url);
            testWrongCertOnEndpoint(url);
        } catch (Exception e) {
            fail(e);
        }
    }
    @Test
    void pemFromPathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromPath(Client.CLIENT_PEM_PATH);
        });
    }

    @Test
    void p7bFromPathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromPath(Client.CLIENT_P7B_PATH);
        });
    }

    @Test
    void derFromPathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromPath(Client.CLIENT_DER_PATH);
        });
    }

    @Test
    void pemFromClasspathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromClasspath(Client.CLIENT_PEM_FILE_NAME);
        });
    }

    @Test
    void p7bFromClasspathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromClasspath(Client.CLIENT_P7B_FILE_NAME);
        });
    }

    @Test
    void derFromClasspathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromClasspath(Client.CLIENT_DER_FILE_NAME);
        });
    }

    @Test
    void pemFromInputStreamWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromInputStream(Client.CLIENT_PEM_INPUT_STREAM_SUPPLIER.get());
        });
    }

    @Test
    void p7bFromInputStreamWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromInputStream(Client.CLIENT_P7B_INPUT_STREAM_SUPPLIER.get());
        });
    }

    @Test
    void derFromInputStreamWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.certificateFromInputStream(Client.CLIENT_DER_INPUT_STREAM_SUPPLIER.get());
        });
    }

    @Test
    void p7bFromStringWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.p7bCertificateFromString(Client.CLIENT_P7B_CERTIFICATE_AS_STRING);
        });
    }

    @Test
    void pemFromStringWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.pemFromString(Client.CLIENT_CERTIFICATE_AS_STRING);
        });
    }


    @Test
    void jksFromPathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.trustStoreFromPath(Client.CLIENT_JKS_PATH, Client.KEYSTORE_PASSWORD);
        });
    }

    @Test
    void p12FromPathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.trustStoreFromPath(Client.CLIENT_P12_PATH, Client.KEYSTORE_PASSWORD);
        });
    }

    @Test
    void jksFromClasspathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.trustStoreFromClasspath(Client.CLIENT_JKS_FILE_NAME, Client.KEYSTORE_PASSWORD);
        });
    }

    @Test
    void p12FromClasspathWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.trustStoreFromClasspath(Client.CLIENT_P12_FILE_NAME, Client.KEYSTORE_PASSWORD);
        });
    }

    @Test
    void jksFromInputStreamWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.trustStoreFromInputStream(Client.CLIENT_JKS_INPUT_STREAM_SUPPLIER.get(), Client.KEYSTORE_PASSWORD);
        });
    }

    @Test
    void p12FromInputStreamWorks(){
        trustConfigWorks(trustConfig -> {
            trustConfig.trustStoreFromInputStream(Client.CLIENT_P12_INPUT_STREAM_SUPPLIER.get(), Client.KEYSTORE_PASSWORD);
        });
    }


}
