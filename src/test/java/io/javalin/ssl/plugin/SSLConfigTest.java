package io.javalin.ssl.plugin;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class SSLConfigTest {

    final String absolutePathString = "/etc/sample/path";
    final Path absolutePath = Paths.get(absolutePathString);

    @Test
    void setPemCertificatesPath() {
        SSLConfig config = new SSLConfig();
        assertNull(config.inner.pemCertificatesPath);
        config.setPemCertificatesPath(absolutePathString);
        assertEquals(absolutePath,config.inner.pemCertificatesPath);
    }

    @Test
    void setPemPrivateKeyPath() {
        SSLConfig config = new SSLConfig();
        assertNull(config.inner.pemPrivateKeyPath);
        config.setPemPrivateKeyPath(absolutePathString);
        assertEquals(absolutePath,config.inner.pemPrivateKeyPath);
    }
}
