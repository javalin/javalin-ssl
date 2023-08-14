package io.javalin.community.ssl;

import io.javalin.community.ssl.util.SSLUtils;
import nl.altindag.ssl.SSLFactory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Tag("unitary")
class SSLUtilsTest {

    @Test
    void createSslContextFactory() {
        //TODO
    }

    @Test
    void parseIdentityEmptyConfig() {
        SSLConfig config = new SSLConfig();

        try {
            SSLUtils.parseIdentity(config,SSLFactory.builder());
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_CERT_AND_KEY_FILE.getMessage(), e.getMessage());
        }
    }

}
