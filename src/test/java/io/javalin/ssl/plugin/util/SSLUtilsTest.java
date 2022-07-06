package io.javalin.ssl.plugin.util;

import io.javalin.ssl.plugin.SSLConfig;
import io.javalin.ssl.plugin.SSLConfigException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Tag("unit")
class SSLUtilsTest {

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
