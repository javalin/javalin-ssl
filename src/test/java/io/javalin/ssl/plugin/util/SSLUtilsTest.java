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

    /* START TESTS USING STRING LOADING FOR WRONG VALUES*/
    @Test
    void createKeyManagerMissingPemCertString() {
        SSLConfig config = new SSLConfig();

        config.setPemPrivateKeyString(emptyPemString);
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_CERTIFICATE.getMessage(), e.getMessage());
        }
    }

    @Test
    void createKeyManagerMissingPemKeyString() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesString(emptyPemString);
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_PRIVATE_KEY.getMessage(), e.getMessage());
        }
    }


    @Test
    void createKeyManagerPresentPemCertAndKeyString() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesString(emptyPemString);
        config.setPemPrivateKeyString(emptyPemString);
        try {
            SSLUtils.createKeyManager(config);
        } catch (SSLConfigException e) {
            fail("Got SSLConfigException: " + e.getMessage());
        } catch (Exception ignored) {

        }
    }
    /* END TESTS USING STRING LOADING FOR WRONG VALUES*/

    /* START TESTS USING CLASSPATH FILE LOADING FOR WRONG VALUES*/
    @Test
    void createKeyManagerMissingCertFile() {
        SSLConfig config = new SSLConfig();
        config.setPemPrivateKeyFile(emptyPemFileName);
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_CERTIFICATE.getMessage(), e.getMessage());
        }
    }

    @Test
    void createKeyManagerMissingKeyFile() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesFile(emptyPemFileName);
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_PRIVATE_KEY.getMessage(), e.getMessage());
        }
    }

    @Test
    void createKeyManagerPresentCertAndKeyFile() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesFile(emptyPemFileName);
        config.setPemPrivateKeyFile(emptyPemFileName);
        try {
            SSLUtils.createKeyManager(config);
        } catch (SSLConfigException e) {
            fail("Got SSLConfigException: " + e.getMessage());
        } catch (Exception ignored) {

        }
    }

    @Test
    void createKeyManagerNonExistingCertFile() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesFile("dummy");
        config.setPemPrivateKeyFile(emptyPemFilePath);
        assertThrows(IllegalArgumentException.class, () -> SSLUtils.createKeyManager(config));
    }

    @Test
    void createKeyManagerNonExistingKeyFile() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesFile(emptyPemFilePath);
        config.setPemPrivateKeyFile("dummy");
        assertThrows(IllegalArgumentException.class, () -> SSLUtils.createKeyManager(config));
    }

    @Test
    void createKeyManagerNonExistingCertAndKeyFile() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesFile("dummy");
        config.setPemPrivateKeyFile("dummy");
        assertThrows(IllegalArgumentException.class, () -> SSLUtils.createKeyManager(config));
    }
    /* END TESTS USING CLASSPATH FILE LOADING FOR WRONG VALUES*/

    /* START TESTS USING PATH LOADING FOR WRONG VALUES*/
    @Test
    void createKeyManagerMissingCertPath() {
        SSLConfig config = new SSLConfig();
        config.setPemPrivateKeyPath(emptyPemFileName);
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_CERTIFICATE.getMessage(), e.getMessage());
        }
    }

    @Test
    void createKeyManagerMissingKeyPath() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesPath(emptyPemFileName);
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_PRIVATE_KEY.getMessage(), e.getMessage());
        }
    }

    @Test
    void createKeyManagerPresentCertAndKeyPath() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesPath(emptyPemFileName);
        config.setPemPrivateKeyPath(emptyPemFileName);
        try {
            SSLUtils.createKeyManager(config);
        } catch (SSLConfigException e) {
            fail("Got SSLConfigException: " + e.getMessage());
        } catch (Exception ignored) {

        }
    }

    @Test
    void createKeyManagerNonExistingCertPath() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesPath("dummy");
        config.setPemPrivateKeyPath(emptyPemFilePath);
        try {
            SSLUtils.createKeyManager(config);
        } catch (SSLConfigException e) {
            fail("Got SSLConfigException: " + e.getMessage());
        } catch (Exception ignored) {

        }    }

    @Test
    void createKeyManagerNonExistingKeyPath() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesPath(emptyPemFilePath);
        config.setPemPrivateKeyPath("dummy");
        try {
            SSLUtils.createKeyManager(config);
        } catch (SSLConfigException e) {
            fail("Got SSLConfigException: " + e.getMessage());
        } catch (Exception ignored) {

        }    }

    @Test
    void createKeyManagerNonExistingCertAndKeyPath() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesPath("dummy");
        config.setPemPrivateKeyPath("dummy");
        try {
            SSLUtils.createKeyManager(config);
        } catch (SSLConfigException e) {
            fail("Got SSLConfigException: " + e.getMessage());
        } catch (Exception ignored) {

        }    }

    @Test
    void createKeyManagerNonExistingCertAndKeyPathWithEmptyPath() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesPath("");
        config.setPemPrivateKeyPath("");
        try {
            SSLUtils.createKeyManager(config);
        } catch (SSLConfigException e) {
            fail("Got SSLConfigException: " + e.getMessage());
        } catch (Exception ignored) {

        }    }
    /* END TESTS USING PATH LOADING FOR WRONG VALUES*/

    /* START TESTS USING InputStream LOADING FOR WRONG VALUES*/
    @Test
    void createKeyManagerMissingCertInputStream() {
        SSLConfig config = new SSLConfig();
        config.setPemPrivateKeyInputStream(emptyPemInputStream.get());
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_CERTIFICATE.getMessage(), e.getMessage());
        }
    }

    @Test
    void createKeyManagerMissingKeyInputStream() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesInputStream(emptyPemInputStream.get());
        try {
            SSLUtils.createKeyManager(config);
            fail("Expected SSLConfigException");
        } catch (SSLConfigException e) {
            assertEquals(SSLConfigException.Types.MISSING_PRIVATE_KEY.getMessage(), e.getMessage());
        }
    }

    @Test
    void createKeyManagerPresentCertAndKeyInputStream() {
        SSLConfig config = new SSLConfig();
        config.setPemCertificatesInputStream(emptyPemInputStream.get());
        config.setPemPrivateKeyInputStream(emptyPemInputStream.get());
        try {
            SSLUtils.createKeyManager(config);
        } catch (SSLConfigException e) {
            fail("Got SSLConfigException: " + e.getMessage());
        } catch (Exception ignored) {

        }
    }
    /* END TESTS USING InputStream LOADING FOR WRONG VALUES*/


}
