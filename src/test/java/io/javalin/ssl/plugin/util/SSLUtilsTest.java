package io.javalin.ssl.plugin.util;

import io.javalin.ssl.plugin.SSLConfig;
import io.javalin.ssl.plugin.SSLConfigException;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

class SSLUtilsTest {

    private final String emptyPemString = "";
    private final String emptyPemFileName = "wrong.pem";

    private final Supplier<InputStream> emptyPemInputStream = InputStream::nullInputStream;
    private final String emptyPemFilePath = String.valueOf(Paths.get( this.getClass().getClassLoader().getResource(emptyPemFileName).toURI()).toFile());

    SSLUtilsTest() throws URISyntaxException {
    }

    @Test
    void createSslContextFactory() {
    }

    @Test
    void createKeyManagerEmptyConfig() {
        SSLConfig config = new SSLConfig();
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_CERT_AND_KEY_FILE.getMessage(), e.getMessage());
        }
    }

}
