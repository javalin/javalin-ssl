package io.javalin.community.ssl;

import io.javalin.community.ssl.certs.Server;
import nl.altindag.ssl.exception.CertificateParseException;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.exception.PrivateKeyParseException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

@Tag("integration")
public class PemLoadingTests extends IntegrationTestClass {


    @Test
    void loadValidPasswordlessFromString() {
        assertSslWorks(config -> config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.NON_ENCRYPTED_KEY_AS_STRING));
    }

    @Test
    void loadInvalidKeyFromString() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromString(Server.CERTIFICATE_AS_STRING, "invalid")));
    }

    @Test
    void loadInvalidCertificateFromString() {
        assertThrows(CertificateParseException.class, () -> assertSslWorks(config -> config.pemFromString("invalid", Server.NON_ENCRYPTED_KEY_AS_STRING)));
    }

    @Test
    void loadInvalidPasswordFromString() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.ENCRYPTED_KEY_AS_STRING, "invalid")));
    }

    @Test
    void loadValidEncryptedFromString() {
        assertSslWorks(config -> config.pemFromString(Server.CERTIFICATE_AS_STRING, Server.ENCRYPTED_KEY_AS_STRING, Server.KEY_PASSWORD));
    }

    @Test
    void loadValidPasswordlessFromClasspath() {
        assertSslWorks(config -> config.pemFromClasspath(Server.CERTIFICATE_FILE_NAME, Server.NON_ENCRYPTED_KEY_FILE_NAME));
    }

    @Test
    void loadValidEncryptedFromClasspath() {
        assertSslWorks(config -> config.pemFromClasspath(Server.CERTIFICATE_FILE_NAME, Server.ENCRYPTED_KEY_FILE_NAME, Server.KEY_PASSWORD));
    }

    @Test
    void loadInvalidPasswordFromClasspath() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromClasspath(Server.CERTIFICATE_FILE_NAME, Server.ENCRYPTED_KEY_FILE_NAME, "invalid")));
    }

    @Test
    void loadInvalidCertificateFromClasspath() {
        assertThrows(IllegalArgumentException.class, () -> assertSslWorks(config -> config.pemFromClasspath("invalid", Server.NON_ENCRYPTED_KEY_FILE_NAME)));
    }

    @Test
    void loadInvalidKeyFromClasspath() {
        assertThrows(IllegalArgumentException.class, () -> assertSslWorks(config -> config.pemFromClasspath(Server.CERTIFICATE_FILE_NAME, "invalid")));
    }

    @Test
    void loadValidPasswordlessFromFile() {
        assertSslWorks(config -> config.pemFromPath(Server.CERTIFICATE_PATH, Server.NON_ENCRYPTED_KEY_PATH));
    }

    @Test
    void loadValidEncryptedFromFile() {
        assertSslWorks(config -> config.pemFromPath(Server.CERTIFICATE_PATH, Server.ENCRYPTED_KEY_PATH, Server.KEY_PASSWORD));
    }

    @Test
    void loadInvalidPasswordFromFile() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromPath(Server.CERTIFICATE_PATH, Server.ENCRYPTED_KEY_PATH, "invalid")));
    }

    @Test
    void loadInvalidCertificateFromFile() {
        assertThrows(GenericIOException.class, () -> assertSslWorks(config -> config.pemFromPath("invalid", Server.NON_ENCRYPTED_KEY_PATH)));
    }

    @Test
    void loadInvalidKeyFromFile() {
        assertThrows(GenericIOException.class, () -> assertSslWorks(config -> config.pemFromPath(Server.CERTIFICATE_PATH, "invalid")));
    }

    @Test
    void loadValidPasswordlessFromInputStream() {
        assertSslWorks(config -> config.pemFromInputStream(Server.CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), Server.NON_ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get()));
    }

    @Test
    void loadValidEncryptedFromInputStream() {
        assertSslWorks(config -> config.pemFromInputStream(Server.CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), Server.ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(), Server.KEY_PASSWORD));
    }

    @Test
    void loadInvalidPasswordFromInputStream() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromInputStream(Server.CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), Server.ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(), "invalid")));
    }

    @Test
    void loadInvalidCertificateFromInputStream() {
        assertThrows(CertificateParseException.class, () -> assertSslWorks(config -> config.pemFromInputStream(InputStream.nullInputStream(), Server.NON_ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get())));
    }

    @Test
    void loadInvalidKeyFromInputStream() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.pemFromInputStream(Server.ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(), InputStream.nullInputStream())));
    }

}
