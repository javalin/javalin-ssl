package io.javalin.community.ssl;

import io.javalin.Javalin;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

@Tag("integration")
public class SSLConfigTests extends IntegrationTestClass {

    @Test
    void testDisableInsecure() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.insecure = false;
            config.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            config.securePort = securePort;
            config.insecurePort = insecurePort;
        }).start()) {
            assertThrows(Exception.class, () -> getClient().newCall(new Request.Builder().url(http).build()).execute()); // should throw exception
            Response response = getClient().newCall(new Request.Builder().url(https).build()).execute(); // should not throw exception
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
            app.stop();
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testDisableSecure() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.secure = false;
            config.insecurePort = insecurePort;
            config.securePort = securePort;
        }).start()) {
            assertThrows(Exception.class, () -> getClient().newCall(new Request.Builder().url(https).build()).execute()); // should throw exception
            Response response = getClient().newCall(new Request.Builder().url(http).build()).execute(); // should not throw exception
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testInsecurePortChange() {
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.secure = false;
            config.insecurePort = 8080;
        }).start()) {
            Response response = getClient().newCall(new Request.Builder().url("http://localhost:8080/").build()).execute(); // should not throw exception
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testSecurePortChange() {
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecure = false;
            config.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            config.securePort = 8443;
        }).start()) {
            Response response = getClient().newCall(new Request.Builder().url("https://localhost:8443/").build()).execute(); // should not throw exception
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testInsecureHttp1() {
        int insecurePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.secure = false;
            config.http2 = false;
            config.insecurePort = insecurePort;
        }).start()) {
            testSuccessfulEndpoint(http, Protocol.HTTP_1_1);
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testInsecureDisableHttp2() {
        OkHttpClient http2client = new OkHttpClient.Builder().protocols(Collections.singletonList(Protocol.H2_PRIOR_KNOWLEDGE)).build();
        OkHttpClient http1Client = new OkHttpClient.Builder().build();
        int insecurePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.secure = false;
            config.http2 = false;
            config.insecurePort = insecurePort;
        }).start()) {
            assertThrows(Exception.class, () -> http2client.newCall(new Request.Builder().url(http).build()).execute()); // Should fail to connect using HTTP/2
            testSuccessfulEndpoint(http1Client, http, Protocol.HTTP_1_1);
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testSecureDisableHttp2() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.http2 = false;
            config.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            config.securePort = securePort;
            config.insecurePort = insecurePort;
        }).start()) {
            testSuccessfulEndpoint(https, Protocol.HTTP_1_1);
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testInsecureHttp2() {
        OkHttpClient client = new OkHttpClient.Builder().protocols(Collections.singletonList(Protocol.H2_PRIOR_KNOWLEDGE)).build();
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);

        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.secure = false;
            config.http2 = true;
            config.insecurePort = insecurePort;
            config.securePort = securePort;
        }).start()) {
            testSuccessfulEndpoint(client, http, Protocol.H2_PRIOR_KNOWLEDGE);
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testSecureHttp2() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            config.securePort = securePort;
            config.insecurePort = insecurePort;
        }).start()) {
            testSuccessfulEndpoint(https, Protocol.HTTP_2);
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testDefault() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecurePort = insecurePort;
            config.securePort = securePort;
            config.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
        }).start()) {
            testSuccessfulEndpoint(http, Protocol.HTTP_1_1);
            testSuccessfulEndpoint(https, Protocol.HTTP_2);
        } catch (IOException e) {
            fail(e);
        }
    }

    private static void testSuccessfulEndpoint(OkHttpClient client, String url, Protocol protocol) throws IOException {
        Response response = client.newCall(new Request.Builder().url(url).build()).execute();
        assertEquals(200, response.code());
        assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        assertEquals(protocol, response.protocol());
        response.close();
    }

    private static void testSuccessfulEndpoint(String url, Protocol protocol) throws IOException {
        testSuccessfulEndpoint(getClient(), url, protocol);
    }

    @Test
    void testMatchingHost() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecurePort = insecurePort;
            config.securePort = securePort;
            config.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            config.host = "localhost";
        }).start()) {
            testSuccessfulEndpoint(http, Protocol.HTTP_1_1);
            testSuccessfulEndpoint(https, Protocol.HTTP_2);
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testWrongHost() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        try (Javalin ignored1 = IntegrationTestClass.createTestApp(config -> {
            config.insecurePort = insecurePort;
            config.securePort = securePort;
            config.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            config.host = "wronghost";
        }).start()) {
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    void testEnabledSniHostCheckAndMatchingHostname() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecurePort = insecurePort;
            config.securePort = securePort;
            config.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            config.host = "localhost";
            config.sniHostCheck = true;
        }).start()) {
            testSuccessfulEndpoint(http, Protocol.HTTP_1_1);
            testSuccessfulEndpoint(https, Protocol.HTTP_2);
        } catch (IOException e) {
            fail(e);
        }

    }

    @Test
    void testEnabledSniHostCheckAndWrongHostname() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecurePort = insecurePort;
            config.securePort = securePort;
            config.pemFromString(GOOGLE_CERTIFICATE_AS_STRING, GOOGLE_KEY_AS_STRING);
            config.host = "localhost";
            config.sniHostCheck = true;
        }).start()) {
            //http request should be successful
            testSuccessfulEndpoint(getUntrustedClient(), http, Protocol.HTTP_1_1);
            //https request should fail
            Response wrongHttpsResponse = getUntrustedClient().newCall(new Request.Builder().url(https).build()).execute();
            assertEquals(400, wrongHttpsResponse.code());
            assertTrue(Objects.requireNonNull(wrongHttpsResponse.body()).string().contains("Error 400 Invalid SNI"));

            wrongHttpsResponse.close();
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testDisabledSniHostCheck() {
        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        try (Javalin ignored = IntegrationTestClass.createTestApp(config -> {
            config.insecurePort = insecurePort;
            config.securePort = securePort;
            config.pemFromString(GOOGLE_CERTIFICATE_AS_STRING, GOOGLE_KEY_AS_STRING);
            config.host = "localhost";
            config.sniHostCheck = false;
        }).start()) {
            testSuccessfulEndpoint(getUntrustedClient(), http, Protocol.HTTP_1_1);
            testSuccessfulEndpoint(getUntrustedClient(), https, Protocol.HTTP_2);
        } catch (IOException e) {
            fail(e);
        }
    }
}
