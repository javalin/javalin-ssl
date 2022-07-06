package io.javalin.ssl.plugin;

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
public class ConfigIntegrationTests extends IntegrationTestClass {

    @Test
    void testDisableInsecure(){
        OkHttpClient client = createHttpsClient();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.disableInsecure = true;
            config.loadPemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
        })) {
            app.start();
            assertThrows(Exception.class,()->client.newCall(new Request.Builder().url(HTTP_URL).build()).execute()); // should throw exception
            Response response = client.newCall(new Request.Builder().url(HTTPS_URL).build()).execute(); // should not throw exception
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testDisableSecure(){
        OkHttpClient client = createHttpsClient();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.disableSecure = true;
        })) {
            app.start();
            assertThrows(Exception.class,()->client.newCall(new Request.Builder().url(HTTPS_URL).build()).execute()); // should throw exception
            Response response = client.newCall(new Request.Builder().url(HTTP_URL).build()).execute(); // should not throw exception
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testInsecurePortChange(){
        OkHttpClient client = createHttpsClient();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.disableSecure = true;
            config.insecurePort = 12345;
        })) {
            app.start();
            assertThrows(Exception.class,()->client.newCall(new Request.Builder().url(HTTP_URL).build()).execute()); // should throw exception
            Response response = client.newCall(new Request.Builder().url("http://localhost:12345/").build()).execute(); // should not throw exception
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testSecurePortChange(){
        OkHttpClient client = createHttpsClient();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.disableInsecure = true;
            config.loadPemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            config.sslPort = 12345;
        })) {
            app.start();
            assertThrows(Exception.class,()->client.newCall(new Request.Builder().url(HTTPS_URL).build()).execute()); // should throw exception
            Response response = client.newCall(new Request.Builder().url("https://localhost:12345/").build()).execute(); // should not throw exception
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testInsecureHttp1() {
        OkHttpClient client = new OkHttpClient.Builder().build();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.disableSecure = true;
            config.disableHttp2 = true;
        })) {
            app.start();
            Response response = client.newCall(new Request.Builder().url(HTTP_URL).build()).execute();
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
            assertEquals(Protocol.HTTP_1_1, response.protocol());
            response.close();
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testInsecureDisableHttp2(){
        OkHttpClient http2client = new OkHttpClient.Builder()
            .protocols(Collections.singletonList(Protocol.H2_PRIOR_KNOWLEDGE))
            .build();
        OkHttpClient http1Client = new OkHttpClient.Builder()
            .build();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.disableSecure = true;
            config.disableHttp2 = true;
        })) {
            app.start();
            assertThrows(Exception.class,() -> http2client.newCall(new Request.Builder().url(HTTP_URL).build()).execute()); // Should fail to connect using HTTP/2
            Response response = http1Client.newCall(new Request.Builder().url(HTTP_URL).build()).execute(); // Should connect using HTTP/1.1
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
            assertEquals(Protocol.HTTP_1_1, response.protocol());
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testSecureDisableHttp2(){
        OkHttpClient client = createHttpsClient();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.disableHttp2 = true;
            config.loadPemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
        })) {
            app.start();
            Response response = client.newCall(new Request.Builder().url(HTTPS_URL).build()).execute();
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
            assertEquals(Protocol.HTTP_1_1, response.protocol());
            response.close();
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testInsecureHttp2(){
        OkHttpClient client = new OkHttpClient.Builder()
            .protocols(Collections.singletonList(Protocol.H2_PRIOR_KNOWLEDGE))
            .build();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> {
            config.disableSecure = true;
            config.disableHttp2 = false;
        })) {
            app.start();
            Response response = client.newCall(new Request.Builder().url(HTTP_URL).build()).execute();
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
            assertEquals(Protocol.H2_PRIOR_KNOWLEDGE, response.protocol());
            response.close();
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void testSecureHttp2(){
        OkHttpClient client = createHttpsClient();
        try (Javalin app = IntegrationTestClass.createTestApp(config -> config.loadPemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING));) {
            app.start();
            Response response = client.newCall(new Request.Builder().url(HTTPS_URL).build()).execute();
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
            assertEquals(Protocol.HTTP_2, response.protocol());
            response.close();
        } catch (IOException e) {
            fail(e);
        }
    }
}
