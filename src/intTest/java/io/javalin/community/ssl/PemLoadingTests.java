package io.javalin.community.ssl;

import io.javalin.community.ssl.certs.Server;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.pem.exception.CertificateParseException;
import nl.altindag.ssl.pem.exception.PrivateKeyParseException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("integration")
public class PemLoadingTests extends IntegrationTestClass {


    @Test
    @DisplayName("Loading a passwordless PEM file from a string works")
    void loadValidPasswordlessFromString() {
        assertSslWorks(config -> config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING));
    }

    @Test
    @DisplayName("Loading a an invalid key PEM file from a string fails")
    void loadInvalidKeyFromString() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromString(Server.CERTIFICATE_AS_STRING, "invalid")));
    }

    @Test
    @DisplayName("Loading a an invalid certificate PEM file from a string fails")
    void loadInvalidCertificateFromString() {
        assertThrows(CertificateParseException.class, () -> assertSslWorks(config -> config.pemFromString("invalid", Server.NON_ENCRYPTED_KEY_AS_STRING)));
    }

    @Test
    @DisplayName("Loading a PEM file with a wrong password from a string fails")
    void loadInvalidPasswordFromString() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.ENCRYPTED_KEY_AS_STRING, "invalid")));
    }

    @Test
    @DisplayName("Loading an encrypted PEM file from a string works")
    void loadValidEncryptedFromString() {
        assertSslWorks(config -> config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.ENCRYPTED_KEY_AS_STRING, Server.KEY_PASSWORD));
    }

    @Test
    @DisplayName("Loading a passwordless PEM file from the classpath works")
    void loadValidPasswordlessFromClasspath() {
        assertSslWorks(config -> config.pemFromClasspath(Server.CERTIFICATE_FILE_NAME, Server.NON_ENCRYPTED_KEY_FILE_NAME));
    }

    @Test
    @DisplayName("Loading an encrypted PEM file from the classpath works")
    void loadValidEncryptedFromClasspath() {
        assertSslWorks(config -> config.pemFromClasspath(Server.CERTIFICATE_FILE_NAME, Server.ENCRYPTED_KEY_FILE_NAME, Server.KEY_PASSWORD));
    }

    @Test
    @DisplayName("Loading a PEM file with a wrong password from the classpath fails")
    void loadInvalidPasswordFromClasspath() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromClasspath(Server.CERTIFICATE_FILE_NAME, Server.ENCRYPTED_KEY_FILE_NAME, "invalid")));
    }

    @Test
    @DisplayName("Loading a PEM file from an invalid classpath cert location fails")
    void loadInvalidCertificateFromClasspath() {
        assertThrows(IllegalArgumentException.class, () -> assertSslWorks(config -> config.pemFromClasspath("invalid", Server.NON_ENCRYPTED_KEY_FILE_NAME)));
    }

    @Test
    @DisplayName("Loading a PEM file from an invalid classpath key location fails")
    void loadInvalidKeyFromClasspath() {
        assertThrows(IllegalArgumentException.class, () -> assertSslWorks(config -> config.pemFromClasspath(Server.CERTIFICATE_FILE_NAME, "invalid")));
    }

    @Test
    @DisplayName("Loading a passwordless PEM file from a path works")
    void loadValidPasswordlessFromFile() {
        assertSslWorks(config -> config.pemFromPath(Server.CERTIFICATE_PATH, Server.NON_ENCRYPTED_KEY_PATH));
    }

    @Test
    @DisplayName("Loading an encrypted PEM file from a path works")
    void loadValidEncryptedFromFile() {
        assertSslWorks(config -> config.pemFromPath(Server.CERTIFICATE_PATH, Server.ENCRYPTED_KEY_PATH, Server.KEY_PASSWORD));
    }

    @Test
    @DisplayName("Loading a PEM file with a wrong password from a path fails")
    void loadInvalidPasswordFromFile() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromPath(Server.CERTIFICATE_PATH, Server.ENCRYPTED_KEY_PATH, "invalid")));
    }

    @Test
    @DisplayName("Loading a PEM file from an invalid cert path fails")
    void loadInvalidCertificateFromFile() {
        assertThrows(GenericIOException.class, () -> assertSslWorks(config -> config.pemFromPath("invalid", Server.NON_ENCRYPTED_KEY_PATH)));
    }

    @Test
    @DisplayName("Loading a PEM file from an invalid key path fails")
    void loadInvalidKeyFromFile() {
        assertThrows(GenericIOException.class, () -> assertSslWorks(config -> config.pemFromPath(Server.CERTIFICATE_PATH, "invalid")));
    }

    @Test
    @DisplayName("Loading a passwordless PEM file from an input stream works")
    void loadValidPasswordlessFromInputStream() {
        assertSslWorks(config -> config.pemFromInputStream(Server.CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), Server.NON_ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get()));
    }

    @Test
    @DisplayName("Loading an encrypted PEM file from an input stream works")
    void loadValidEncryptedFromInputStream() {
        assertSslWorks(config -> config.pemFromInputStream(Server.CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), Server.ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(), Server.KEY_PASSWORD));
    }

    @Test
    @DisplayName("Loading a PEM file with a wrong password from an input stream fails")
    void loadInvalidPasswordFromInputStream() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromInputStream(Server.CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), Server.ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(), "invalid")));
    }

    @Test
    @DisplayName("Loading a PEM file from an invalid cert input stream fails")
    void loadInvalidCertificateFromInputStream() {
        assertThrows(CertificateParseException.class, () -> assertSslWorks(config -> config.pemFromInputStream(InputStream.nullInputStream(), Server.NON_ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get())));
    }

    @Test
    @DisplayName("Loading a PEM file from an invalid key input stream fails")
    void loadInvalidKeyFromInputStream() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromInputStream(Server.ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(), InputStream.nullInputStream())));
    }

}
