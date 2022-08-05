package io.javalin.ssl.plugin;

import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("integration")
public class KeystoreLoadingTest extends IntegrationTestClass {

    private static final String MALFORMED_JKS_FILE_NAME = "malformed.jks";

    private static final String MALFORMED_P12_FILE_NAME = "malformed.p12";

    private static final String MALFORMED_JKS_FILE_PATH;

    private static final String MALFORMED_P12_FILE_PATH;

    static {
        try {
            MALFORMED_JKS_FILE_PATH = Path.of(ClassLoader.getSystemResource(MALFORMED_JKS_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            MALFORMED_P12_FILE_PATH = Path.of(ClassLoader.getSystemResource(MALFORMED_P12_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static final Supplier<InputStream> MALFORMED_JKS_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return KeystoreLoadingTest.class.getResourceAsStream(MALFORMED_JKS_FILE_NAME);
        } catch (Exception e) {
            throw new GenericIOException(e);
        }
    };

    public static final Supplier<InputStream> MALFORMED_P12_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return KeystoreLoadingTest.class.getResourceAsStream(MALFORMED_JKS_FILE_NAME);
        } catch (Exception e) {
            throw new GenericIOException(e);
        }
    };

    //////////////////////////////
    // Valid keystore loading   //
    //////////////////////////////

    @Test
    void loadValidJKSFromClasspath() {
        assertSslWorks(config -> config.keystoreFromClasspath(P12_KEY_STORE_NAME,KEY_STORE_PASSWORD));
    }

    @Test
    void loadValidP12FromClasspath(){
        assertSslWorks(config -> config.keystoreFromClasspath(P12_KEY_STORE_NAME,KEY_STORE_PASSWORD));
    }

    @Test
    void loadValidJKSFromPath(){
        assertSslWorks(config -> config.keystoreFromPath(P12_KEY_STORE_PATH,KEY_STORE_PASSWORD));
    }

    @Test
    void loadValidP12FromPath(){
        assertSslWorks(config -> config.keystoreFromPath(P12_KEY_STORE_PATH,KEY_STORE_PASSWORD));
    }

    @Test
    void loadValidJKSFromInputStream(){
        assertSslWorks(config -> config.keystoreFromInputStream(JKS_KEY_STORE_INPUT_STREAM_SUPPLIER.get(),KEY_STORE_PASSWORD));
    }

    @Test
    void loadValidP12FromInputStream(){
        assertSslWorks(config -> config.keystoreFromInputStream(P12_KEY_STORE_INPUT_STREAM_SUPPLIER.get(),KEY_STORE_PASSWORD));
    }

    //////////////////////////////
    // Invalid keystore loading //
    //////////////////////////////

    @Test
    void loadKeystoreFromInvalidClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath("invalid",KEY_STORE_PASSWORD)));
    }

    @Test
    void loadBadPasswordJKSFromClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath(JKS_KEY_STORE_NAME, "invalid")));
    }

    @Test
    void loadBadPasswordP12FromClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath(P12_KEY_STORE_NAME, "invalid")));
    }

    @Test
    void loadKeystoreFromInvalidPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath("invalid",KEY_STORE_PASSWORD)));
    }

    @Test
    void loadBadPasswordJKSFromPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath(JKS_KEY_STORE_PATH, "invalid")));
    }

    @Test
    void loadBadPasswordP12FromPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath(P12_KEY_STORE_PATH, "invalid")));
    }

    @Test
    void loadKeystoreFromInvalidInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(InputStream.nullInputStream(), KEY_STORE_PASSWORD)));
    }

    @Test
    void loadBadPasswordJKSFromInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(JKS_KEY_STORE_INPUT_STREAM_SUPPLIER.get(), "invalid")));
    }

    @Test
    void loadBadPasswordP12FromInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(P12_KEY_STORE_INPUT_STREAM_SUPPLIER.get(), "invalid")));
    }

    @Test
    void loadMalformedJKSFromClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath(MALFORMED_JKS_FILE_NAME, KEY_STORE_PASSWORD)));
    }

    @Test
    void loadMalformedP12FromClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath(MALFORMED_P12_FILE_NAME, KEY_STORE_PASSWORD)));
    }

    @Test
    void loadMalformedJKSFromPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath(MALFORMED_JKS_FILE_PATH, KEY_STORE_PASSWORD)));
    }

    @Test
    void loadMalformedP12FromPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath(MALFORMED_P12_FILE_PATH, KEY_STORE_PASSWORD)));
    }

    @Test
    void loadMalformedJKSFromInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(MALFORMED_JKS_INPUT_STREAM_SUPPLIER.get(), KEY_STORE_PASSWORD)));
    }

    @Test
    void loadMalformedP12FromInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(MALFORMED_P12_INPUT_STREAM_SUPPLIER.get(), KEY_STORE_PASSWORD)));
    }



    //TODO: add tests for invalid and empty keystore
}

