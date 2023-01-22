package io.javalin.community.ssl;

import io.javalin.community.ssl.certs.Server;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("integration")
public class KeystoreLoadingTests extends IntegrationTestClass {

    private static final String MALFORMED_JKS_FILE_NAME = "server/malformed.jks";

    private static final String MALFORMED_P12_FILE_NAME = "server/malformed.p12";

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
            return KeystoreLoadingTests.class.getResourceAsStream(MALFORMED_JKS_FILE_NAME);
        } catch (Exception e) {
            throw new GenericIOException(e);
        }
    };

    public static final Supplier<InputStream> MALFORMED_P12_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return KeystoreLoadingTests.class.getResourceAsStream(MALFORMED_JKS_FILE_NAME);
        } catch (Exception e) {
            throw new GenericIOException(e);
        }
    };

    //////////////////////////////
    // Valid keystore loading   //
    //////////////////////////////

    @Test
    @DisplayName("Loading a valid JKS keystore from the classpath")
    void loadValidJKSFromClasspath() {
        assertSslWorks(config -> config.keystoreFromClasspath(Server.P12_KEY_STORE_NAME, Server.KEY_STORE_PASSWORD));
    }

    @Test
    @DisplayName("Loading a valid P12 keystore from the classpath")
    void loadValidP12FromClasspath(){
        assertSslWorks(config -> config.keystoreFromClasspath(Server.P12_KEY_STORE_NAME, Server.KEY_STORE_PASSWORD));
    }

    @Test
    @DisplayName("Loading a valid JKS keystore from a path")
    void loadValidJKSFromPath(){
        assertSslWorks(config -> config.keystoreFromPath(Server.P12_KEY_STORE_PATH, Server.KEY_STORE_PASSWORD));
    }

    @Test
    @DisplayName("Loading a valid P12 keystore from a path")
    void loadValidP12FromPath(){
        assertSslWorks(config -> config.keystoreFromPath(Server.P12_KEY_STORE_PATH, Server.KEY_STORE_PASSWORD));
    }

    @Test
    @DisplayName("Loading a valid JKS keystore from an input stream")
    void loadValidJKSFromInputStream(){
        assertSslWorks(config -> config.keystoreFromInputStream(Server.JKS_KEY_STORE_INPUT_STREAM_SUPPLIER.get(), Server.KEY_STORE_PASSWORD));
    }

    @Test
    @DisplayName("Loading a valid P12 keystore from an input stream")
    void loadValidP12FromInputStream(){
        assertSslWorks(config -> config.keystoreFromInputStream(Server.P12_KEY_STORE_INPUT_STREAM_SUPPLIER.get(), Server.KEY_STORE_PASSWORD));
    }

    //////////////////////////////
    // Invalid keystore loading //
    //////////////////////////////

    @Test
    @DisplayName("Loading a missing JKS keystore from the classpath fails")
    void loadKeystoreFromInvalidClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath("invalid", Server.KEY_STORE_PASSWORD)));
    }

    @Test
    @DisplayName("Loading a JKS keystore from the classpath with an invalid password fails")
    void loadBadPasswordJKSFromClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath(Server.JKS_KEY_STORE_NAME, "invalid")));
    }

    @Test
    @DisplayName("Loading a P12 keystore from the classpath with an invalid password fails")
    void loadBadPasswordP12FromClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath(Server.P12_KEY_STORE_NAME, "invalid")));
    }

    @Test
    @DisplayName("Loading a missing JKS keystore from a path fails")
    void loadKeystoreFromInvalidPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath("invalid", Server.KEY_STORE_PASSWORD)));
    }

    @Test
    @DisplayName("Loading a JKS keystore from a path with an invalid password fails")
    void loadBadPasswordJKSFromPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath(Server.JKS_KEY_STORE_PATH, "invalid")));
    }

    @Test
    @DisplayName("Loading a P12 keystore from a path with an invalid password fails")
    void loadBadPasswordP12FromPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath(Server.P12_KEY_STORE_PATH, "invalid")));
    }

    @Test
    @DisplayName("Loading a missing JKS keystore from an input stream fails")
    void loadKeystoreFromInvalidInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(InputStream.nullInputStream(), Server.KEY_STORE_PASSWORD)));
    }

    @Test
    @DisplayName("Loading a JKS keystore from an input stream with an invalid password fails")
    void loadBadPasswordJKSFromInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(Server.JKS_KEY_STORE_INPUT_STREAM_SUPPLIER.get(), "invalid")));
    }

    @Test
    @DisplayName("Loading a P12 keystore from an input stream with an invalid password fails")
    void loadBadPasswordP12FromInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(Server.P12_KEY_STORE_INPUT_STREAM_SUPPLIER.get(), "invalid")));
    }

    @Test
    @DisplayName("Loading a malformed JKS keystore from the classpath fails")
    void loadMalformedJKSFromClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath(MALFORMED_JKS_FILE_NAME, Server.KEY_STORE_PASSWORD)));
    }

    @Test
    @DisplayName("Loading a malformed P12 keystore from the classpath fails")
    void loadMalformedP12FromClasspath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromClasspath(MALFORMED_P12_FILE_NAME, Server.KEY_STORE_PASSWORD)));
    }

    @Test
    @DisplayName("Loading a malformed JKS keystore from a path fails")
    void loadMalformedJKSFromPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath(MALFORMED_JKS_FILE_PATH, Server.KEY_STORE_PASSWORD)));
    }

    @Test
    @DisplayName("Loading a malformed P12 keystore from a path fails")
    void loadMalformedP12FromPath() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromPath(MALFORMED_P12_FILE_PATH, Server.KEY_STORE_PASSWORD)));
    }

    @Test
    @DisplayName("Loading a malformed JKS keystore from an input stream fails")
    void loadMalformedJKSFromInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(MALFORMED_JKS_INPUT_STREAM_SUPPLIER.get(), Server.KEY_STORE_PASSWORD)));
    }

    @Test
    @DisplayName("Loading a malformed P12 keystore from an input stream fails")
    void loadMalformedP12FromInputStream() {
        assertThrows(GenericKeyStoreException.class, () -> assertSslWorks(config -> config.keystoreFromInputStream(MALFORMED_P12_INPUT_STREAM_SUPPLIER.get(), Server.KEY_STORE_PASSWORD)));
    }

}

