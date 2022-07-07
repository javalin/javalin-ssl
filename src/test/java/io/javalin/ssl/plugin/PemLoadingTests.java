package io.javalin.ssl.plugin;

import nl.altindag.ssl.exception.CertificateParseException;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.exception.PrivateKeyParseException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.parallel.ResourceAccessMode.READ_WRITE;

@Tag("integration")
public class PemLoadingTests extends IntegrationTestClass {

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadValidPasswordlessFromString() {
        assertSslWorks(config -> config.loadPemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidKeyFromString() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.loadPemFromString(CERTIFICATE_AS_STRING, "invalid")));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidCertificateFromString() {
        assertThrows(CertificateParseException.class, () -> assertSslWorks(config -> config.loadPemFromString("invalid", NON_ENCRYPTED_KEY_AS_STRING)));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidPasswordFromString() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.loadPemFromString(CERTIFICATE_AS_STRING, ENCRYPTED_KEY_AS_STRING, "invalid")));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadValidEncryptedFromString() {
        assertSslWorks(config -> config.loadPemFromString(CERTIFICATE_AS_STRING, ENCRYPTED_KEY_AS_STRING,KEY_PASSWORD));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadValidPasswordlessFromClasspath() {
        assertSslWorks(config -> config.loadPemFromClasspath(CERTIFICATE_FILE_NAME, NON_ENCRYPTED_KEY_FILE_NAME));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadValidEncryptedFromClasspath() {
        assertSslWorks(config -> config.loadPemFromClasspath(CERTIFICATE_FILE_NAME, ENCRYPTED_KEY_FILE_NAME,KEY_PASSWORD));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidPasswordFromClasspath() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.loadPemFromClasspath(CERTIFICATE_FILE_NAME, ENCRYPTED_KEY_FILE_NAME, "invalid")));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidCertificateFromClasspath() {
        assertThrows(IllegalArgumentException.class, () -> assertSslWorks(config -> config.loadPemFromClasspath("invalid", NON_ENCRYPTED_KEY_FILE_NAME)));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidKeyFromClasspath() {
        assertThrows(IllegalArgumentException.class, () -> assertSslWorks(config -> config.loadPemFromClasspath(CERTIFICATE_FILE_NAME, "invalid")));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadValidPasswordlessFromFile() {
        assertSslWorks(config -> config.loadPemFromPath(CERTIFICATE_PATH, NON_ENCRYPTED_KEY_PATH));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadValidEncryptedFromFile() {
        assertSslWorks(config -> config.loadPemFromPath(CERTIFICATE_PATH, ENCRYPTED_KEY_PATH,KEY_PASSWORD));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidPasswordFromFile() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.loadPemFromPath(CERTIFICATE_PATH, ENCRYPTED_KEY_PATH, "invalid")));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidCertificateFromFile() {
        assertThrows(GenericIOException.class, () -> assertSslWorks(config -> config.loadPemFromPath("invalid", NON_ENCRYPTED_KEY_PATH)));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidKeyFromFile() {
        assertThrows(GenericIOException.class, () -> assertSslWorks(config -> config.loadPemFromPath(CERTIFICATE_PATH, "invalid")));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadValidPasswordlessFromInputStream() {
        assertSslWorks(config -> config.loadPemFromInputStream(CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), NON_ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get()));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadValidEncryptedFromInputStream() {
        assertSslWorks(config -> config.loadPemFromInputStream(CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(),KEY_PASSWORD));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidPasswordFromInputStream() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.loadPemFromInputStream(CERTIFICATE_INPUT_STREAM_SUPPLIER.get(), ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(), "invalid")));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidCertificateFromInputStream() {
        assertThrows(CertificateParseException.class, () -> assertSslWorks(config -> config.loadPemFromInputStream(InputStream.nullInputStream(),NON_ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get())));
    }

    @Test
    @ResourceLock(value = "port443", mode = READ_WRITE)
    void loadInvalidKeyFromInputStream() {
        assertThrows(PrivateKeyParseException.class, () -> assertSslWorks(config -> config.loadPemFromInputStream(ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER.get(), InputStream.nullInputStream())));
    }


}
