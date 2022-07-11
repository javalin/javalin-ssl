package io.javalin.ssl.plugin;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

@Tag("unitary")
class SSLConfigTest {

    final String absolutePathString = "/etc/sample/path";
    final Path absolutePath = Paths.get(absolutePathString);

    final String fileName = "sample.pem";

    final InputStream inputStream = InputStream.nullInputStream();

    final String pemString =
            "----- START CERTIFICATE -----\n" +
            "BLABLABLABLABLABLABLABLABLABLA" +
            "----- END CERTIFICATE -----\n";


    @Test
    void loadPemFromPathCorrectly() {
        SSLConfig config = new SSLConfig();
        assertDoesNotThrow(() -> config.loadPemFromPath(absolutePathString,absolutePathString));
        assertEquals(absolutePath, config.inner.pemCertificatesPath);
        assertEquals(absolutePath, config.inner.pemPrivateKeyPath);
    }

    @Test
    void loadPemFromPathDifferentMethod() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromString("", ""); // load empty strings
        assertThrows(SSLConfigException.class,() -> config.loadPemFromPath(absolutePathString,absolutePathString));
    }

    @Test
    void loadPemFromPathTwice() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromPath(absolutePathString,absolutePathString);
        assertThrows(SSLConfigException.class,() -> config.loadPemFromPath(absolutePathString,absolutePathString));
    }

    @Test
    void loadPemFromPathWithPasswordCorrectly() {
        SSLConfig config = new SSLConfig();
        assertDoesNotThrow(() -> config.loadPemFromPath(absolutePathString,absolutePathString, "password"));
        assertEquals(absolutePath, config.inner.pemCertificatesPath);
        assertEquals(absolutePath, config.inner.pemPrivateKeyPath);
        assertEquals("password", config.inner.privateKeyPassword);
    }

    @Test
    void loadPemFromPathWithPasswordTwice() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromPath(absolutePathString,absolutePathString, "password");
        assertThrows(SSLConfigException.class,() -> config.loadPemFromPath(absolutePathString,absolutePathString, "password"));
    }

    @Test
    void loadPemFromPathWithPasswordPreviouslyLoaded() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromPath(absolutePathString,absolutePathString, "password");
        assertThrows(SSLConfigException.class,() -> config.loadPemFromPath(absolutePathString,absolutePathString, "password"));
    }

    //Repeat the same tests with the method loadPemFromClasspath
    @Test
    void loadPemFromClasspathCorrectly() {
        SSLConfig config = new SSLConfig();
        assertDoesNotThrow(() -> config.loadPemFromClasspath(fileName,fileName));
        assertEquals(fileName, config.inner.pemCertificatesFile);
        assertEquals(fileName, config.inner.pemPrivateKeyFile);
    }

    @Test
    void loadPemFromClasspathDifferentMethod() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromString("", ""); // load empty strings
        assertThrows(SSLConfigException.class,() -> config.loadPemFromClasspath(fileName,fileName));
    }

    @Test
    void loadPemFromClasspathTwice() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromClasspath(fileName,fileName);
        assertThrows(SSLConfigException.class,() -> config.loadPemFromClasspath(fileName,fileName));
    }

    @Test
    void loadPemFromClasspathWithPasswordCorrectly() {
        SSLConfig config = new SSLConfig();
        assertDoesNotThrow(() -> config.loadPemFromClasspath(fileName,fileName, "password"));
        assertEquals(fileName, config.inner.pemCertificatesFile);
        assertEquals(fileName, config.inner.pemPrivateKeyFile);
        assertEquals("password", config.inner.privateKeyPassword);
    }

    @Test
    void loadPemFromClasspathWithPasswordTwice() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromClasspath(fileName,fileName, "password");
        assertThrows(SSLConfigException.class,() -> config.loadPemFromClasspath(fileName,fileName, "password"));
    }

    @Test
    void loadPemFromClasspathWithPasswordPreviouslyLoaded() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromClasspath(fileName,fileName, "password");
        assertThrows(SSLConfigException.class,() -> config.loadPemFromClasspath(fileName,fileName, "password"));
    }

    //Repeat the same tests with the method loadPemFromString
    @Test
    void loadPemFromStringCorrectly() {
        SSLConfig config = new SSLConfig();
        assertDoesNotThrow(() -> config.loadPemFromString(pemString,pemString));
        assertEquals(pemString, config.inner.pemCertificatesString);
        assertEquals(pemString, config.inner.pemPrivateKeyString);
    }

    @Test
    void loadPemFromStringDifferentMethod() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromPath(absolutePathString,absolutePathString); // load empty strings
        assertThrows(SSLConfigException.class,() -> config.loadPemFromString(pemString,pemString));
    }

    @Test
    void loadPemFromStringTwice() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromString(pemString,pemString);
        assertThrows(SSLConfigException.class,() -> config.loadPemFromString(pemString,pemString));
    }

    @Test
    void loadPemFromStringWithPasswordCorrectly() {
        SSLConfig config = new SSLConfig();
        assertDoesNotThrow(() -> config.loadPemFromString(pemString,pemString, "password"));
        assertEquals(pemString, config.inner.pemCertificatesString);
        assertEquals(pemString, config.inner.pemPrivateKeyString);
        assertEquals("password", config.inner.privateKeyPassword);
    }

    @Test
    void loadPemFromStringWithPasswordTwice() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromString(pemString,pemString, "password");
        assertThrows(SSLConfigException.class,() -> config.loadPemFromString(pemString,pemString, "password"));
    }

    @Test
    void loadPemFromStringWithPasswordPreviouslyLoaded() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromString(pemString,pemString, "password");
        assertThrows(SSLConfigException.class,() -> config.loadPemFromString(pemString,pemString, "password"));
    }

    //Repeat the same tests with the method loadPemFromInputStream
    @Test
    void loadPemFromInputStreamCorrectly() {
        SSLConfig config = new SSLConfig();
        assertDoesNotThrow(() -> config.loadPemFromInputStream(inputStream,inputStream));
        assertNotNull(config.inner.pemCertificatesInputStream);
        assertNotNull(config.inner.pemPrivateKeyInputStream);
    }

    @Test
    void loadPemFromInputStreamDifferentMethod() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromString("", ""); // load empty strings
        assertThrows(SSLConfigException.class,() -> config.loadPemFromInputStream(inputStream,inputStream));
    }

    @Test
    void loadPemFromInputStreamTwice() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromInputStream(inputStream,inputStream);
        assertThrows(SSLConfigException.class,() -> config.loadPemFromInputStream(inputStream,inputStream));
    }

    @Test
    void loadPemFromInputStreamWithPasswordCorrectly() {
        SSLConfig config = new SSLConfig();
        assertDoesNotThrow(() -> config.loadPemFromInputStream(inputStream,inputStream, "password"));
        assertNotNull(config.inner.pemCertificatesInputStream);
        assertNotNull(config.inner.pemPrivateKeyInputStream);
        assertEquals("password", config.inner.privateKeyPassword);
    }

    @Test
    void loadPemFromInputStreamWithPasswordTwice() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromInputStream(inputStream,inputStream, "password");
        assertThrows(SSLConfigException.class,() -> config.loadPemFromInputStream(inputStream,inputStream, "password"));
    }

    @Test
    void loadPemFromInputStreamWithPasswordPreviouslyLoaded() {
        SSLConfig config = new SSLConfig();
        config.loadPemFromInputStream(inputStream,inputStream, "password");
        assertThrows(SSLConfigException.class,() -> config.loadPemFromInputStream(inputStream,inputStream, "password"));
    }

}
