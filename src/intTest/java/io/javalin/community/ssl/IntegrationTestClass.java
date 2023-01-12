package io.javalin.community.ssl;

import io.javalin.Javalin;
import io.javalin.community.ssl.certs.Server;
import lombok.Getter;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.tls.Certificates;
import okhttp3.tls.HandshakeCertificates;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class IntegrationTestClass {

    static final Logger log = org.slf4j.LoggerFactory.getLogger(IntegrationTestClass.class);

    public static final String SUCCESS = "success";

    public static final Function<Integer, String> HTTPS_URL_WITH_PORT = (Integer port) -> String.format("https://localhost:%s/", port);
    public static final Function<Integer, String> HTTP_URL_WITH_PORT = (Integer port) -> String.format("http://localhost:%s/", port);

    public static final X509TrustManager[] trustAllCerts = new X509TrustManager[]{new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[]{};
        }
    }};

    protected static final AtomicInteger ports = new AtomicInteger(10000);
    @Getter
    private static final OkHttpClient client = createHttpsClient();

    @Getter
    private static final OkHttpClient untrustedClient = untrustedHttpsClient();



    private static OkHttpClient createHttpsClient() {
        HandshakeCertificates.Builder builder = new HandshakeCertificates.Builder();
        builder.addTrustedCertificate(Certificates.decodeCertificatePem(Server.CERTIFICATE_AS_STRING));
        try {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(Server.P12_KEY_STORE_INPUT_STREAM_SUPPLIER.get(), Server.KEY_STORE_PASSWORD.toCharArray());
            for (String alias : Collections.list(ks.aliases())) {
                builder.addTrustedCertificate((X509Certificate) ks.getCertificate(alias));
            }
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
        HandshakeCertificates clientCertificates = builder.build();
        return new OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager()).hostnameVerifier((hostname, session) -> true).build();
    }

    private static OkHttpClient untrustedHttpsClient() {
        OkHttpClient.Builder newBuilder = untrustedClientBuilder();

        return newBuilder.build();
    }

    @NotNull
    protected static OkHttpClient.Builder untrustedClientBuilder() {

        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }

        OkHttpClient.Builder newBuilder = new OkHttpClient.Builder();
        newBuilder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
        newBuilder.hostnameVerifier((hostname, session) -> true);
        return newBuilder;
    }

    public static Javalin createTestApp(Consumer<SSLConfig> config) {
        return Javalin.create((javalinConfig) -> {
            javalinConfig.showJavalinBanner = false;
            javalinConfig.plugins.register(new SSLPlugin(config));
        }).get("/", ctx -> ctx.result(SUCCESS));
    }

    protected static void testSuccessfulEndpoint(OkHttpClient client, String url, okhttp3.Protocol protocol) throws IOException {
        Response response = client.newCall(new Request.Builder().url(url).build()).execute();
        assertEquals(200, response.code());
        assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        assertEquals(protocol, response.protocol());
        response.close();
    }

    protected static void testSuccessfulEndpoint(String url, okhttp3.Protocol protocol) throws IOException {
        IntegrationTestClass.testSuccessfulEndpoint(getClient(), url, protocol);
    }



    void assertWorks(Protocol protocol, Consumer<SSLConfig> config) {

        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        String url = protocol == Protocol.HTTP ? http : https;
        config = config.andThen(sslConfig -> {
            sslConfig.insecurePort = insecurePort;
            sslConfig.securePort = securePort;
        });
        try (Javalin app = IntegrationTestClass.createTestApp(config)) {
            app.start();
            Response response = client.newCall(new Request.Builder().url(url).build()).execute();
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
            response.close();
        } catch (IOException e) {
            fail(e);
        }
    }

    void assertSslWorks(Consumer<SSLConfig> config) {
        assertWorks(Protocol.HTTPS, config);
    }

    void assertHttpWorks(Consumer<SSLConfig> config) {
        assertWorks(Protocol.HTTP, config);
    }

    private enum Protocol {
        HTTP, HTTPS
    }
}
