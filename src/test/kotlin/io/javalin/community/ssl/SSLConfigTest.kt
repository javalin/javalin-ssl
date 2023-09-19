package io.javalin.community.ssl

import io.javalin.community.ssl.SSLConfigException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.InputStream
import java.nio.file.Paths

@Tag("unitary")
internal class SSLConfigTest {
    val absolutePathString = "/etc/sample/path"
    val absolutePath = Paths.get(absolutePathString)
    val fileName = "sample.pem"
    val inputStream = InputStream.nullInputStream()
    val pemString = """
        ----- START CERTIFICATE -----
        BLABLABLABLABLABLABLABLABLABLA----- END CERTIFICATE -----

        """.trimIndent()
    //Replace test names with a description of what the test does, using the fun ``() syntax
    //////////////////////////////
    // Pem loading tests        //
    //////////////////////////////
    @Test
    fun `load PEM from path correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.pemFromPath(absolutePathString, absolutePathString) }
        Assertions.assertEquals(absolutePath, config.inner.pemCertificatesPath)
        Assertions.assertEquals(absolutePath, config.inner.pemPrivateKeyPath)
    }

    @Test
    fun `load PEM from path with different method`() {
        val config = SSLConfig()
        config.pemFromString("", "") // load empty strings
        Assertions.assertThrows(SSLConfigException::class.java) {
            config.pemFromPath(
                absolutePathString,
                absolutePathString
            )
        }
    }

    @Test
    fun `load PEM from path twice`() {
        val config = SSLConfig()
        config.pemFromPath(absolutePathString, absolutePathString)
        Assertions.assertThrows(SSLConfigException::class.java) {
            config.pemFromPath(
                absolutePathString,
                absolutePathString
            )
        }
    }

    @Test
    fun `load PEM from path with password correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.pemFromPath(absolutePathString, absolutePathString, "password") }
        Assertions.assertEquals(absolutePath, config.inner.pemCertificatesPath)
        Assertions.assertEquals(absolutePath, config.inner.pemPrivateKeyPath)
        Assertions.assertEquals("password", config.inner.privateKeyPassword)
    }

    @Test
    fun `load PEM from path with password twice`() {
        val config = SSLConfig()
        config.pemFromPath(absolutePathString, absolutePathString, "password")
        Assertions.assertThrows(SSLConfigException::class.java) {
            config.pemFromPath(
                absolutePathString,
                absolutePathString,
                "password"
            )
        }
    }

    //Repeat the same tests with the method loadPemFromClasspath
    @Test
    fun `load PEM from classpath correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.pemFromClasspath(fileName, fileName) }
        Assertions.assertEquals(fileName, config.inner.pemCertificatesFile)
        Assertions.assertEquals(fileName, config.inner.pemPrivateKeyFile)
    }

    @Test
    fun `load PEM from classpath with different method`() {
        val config = SSLConfig()
        config.pemFromString("", "") // load empty strings
        Assertions.assertThrows(SSLConfigException::class.java) { config.pemFromClasspath(fileName, fileName) }
    }

    @Test
    fun `load PEM from classpath twice`() {
        val config = SSLConfig()
        config.pemFromClasspath(fileName, fileName)
        Assertions.assertThrows(SSLConfigException::class.java) { config.pemFromClasspath(fileName, fileName) }
    }

    @Test
    fun `load PEM from classpath with password correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.pemFromClasspath(fileName, fileName, "password") }
        Assertions.assertEquals(fileName, config.inner.pemCertificatesFile)
        Assertions.assertEquals(fileName, config.inner.pemPrivateKeyFile)
        Assertions.assertEquals("password", config.inner.privateKeyPassword)
    }

    @Test
    fun `load PEM from classpath with password twice`() {
        val config = SSLConfig()
        config.pemFromClasspath(fileName, fileName, "password")
        Assertions.assertThrows(SSLConfigException::class.java) {
            config.pemFromClasspath(
                fileName,
                fileName,
                "password"
            )
        }
    }

    @Test
    fun `load PEM from string correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.pemFromString(pemString, pemString) }
        Assertions.assertEquals(pemString, config.inner.pemCertificatesString)
        Assertions.assertEquals(pemString, config.inner.pemPrivateKeyString)
    }

    @Test
    fun `load PEM from string with different method`() {
        val config = SSLConfig()
        config.pemFromPath(absolutePathString, absolutePathString) // load empty strings
        Assertions.assertThrows(SSLConfigException::class.java) { config.pemFromString(pemString, pemString) }
    }

    @Test
    fun `load PEM from string twice`() {
        val config = SSLConfig()
        config.pemFromString(pemString, pemString)
        Assertions.assertThrows(SSLConfigException::class.java) { config.pemFromString(pemString, pemString) }
    }

    @Test
    fun `load PEM from string with password correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.pemFromString(pemString, pemString, "password") }
        Assertions.assertEquals(pemString, config.inner.pemCertificatesString)
        Assertions.assertEquals(pemString, config.inner.pemPrivateKeyString)
        Assertions.assertEquals("password", config.inner.privateKeyPassword)
    }

    @Test
    fun `load PEM from string with password twice`() {
        val config = SSLConfig()
        config.pemFromString(pemString, pemString, "password")
        Assertions.assertThrows(SSLConfigException::class.java) {
            config.pemFromString(
                pemString,
                pemString,
                "password"
            )
        }
    }

    //Repeat the same tests with the method loadPemFromInputStream
    @Test
    fun `load PEM from input stream correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.pemFromInputStream(inputStream, inputStream) }
        Assertions.assertNotNull(config.inner.pemCertificatesInputStream)
        Assertions.assertNotNull(config.inner.pemPrivateKeyInputStream)
    }

    @Test
    fun `load PEM from input stream with different method`() {
        val config = SSLConfig()
        config.pemFromString("", "") // load empty strings
        Assertions.assertThrows(SSLConfigException::class.java) { config.pemFromInputStream(inputStream, inputStream) }
    }

    @Test
    fun `load PEM from input stream twice`() {
        val config = SSLConfig()
        config.pemFromInputStream(inputStream, inputStream)
        Assertions.assertThrows(SSLConfigException::class.java) { config.pemFromInputStream(inputStream, inputStream) }
    }

    @Test
    fun `load PEM from input stream with password correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.pemFromInputStream(inputStream, inputStream, "password") }
        Assertions.assertNotNull(config.inner.pemCertificatesInputStream)
        Assertions.assertNotNull(config.inner.pemPrivateKeyInputStream)
        Assertions.assertEquals("password", config.inner.privateKeyPassword)
    }

    @Test
    fun `load PEM from input stream with password twice`() {
        val config = SSLConfig()
        config.pemFromInputStream(inputStream, inputStream, "password")
        Assertions.assertThrows(SSLConfigException::class.java) {
            config.pemFromInputStream(
                inputStream,
                inputStream,
                "password"
            )
        }
    }

    //////////////////////////////
    // Keystore loading tests   //
    //////////////////////////////
    @Test
    fun `load keystore from path correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.keystoreFromPath(absolutePathString, "password") }
        Assertions.assertEquals(absolutePath, config.inner.keyStorePath)
        Assertions.assertEquals("password", config.inner.keyStorePassword)
    }

    @Test
    fun `load keystore from path twice`() {
        val config = SSLConfig()
        config.keystoreFromPath(absolutePathString, "password")
        Assertions.assertThrows(SSLConfigException::class.java) {
            config.keystoreFromPath(
                absolutePathString,
                "password"
            )
        }
    }

    @Test
    fun `load keystore from input stream correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.keystoreFromInputStream(inputStream, "password") }
        Assertions.assertNotNull(config.inner.keyStoreInputStream)
        Assertions.assertEquals("password", config.inner.keyStorePassword)
    }

    @Test
    fun `load keystore from input stream twice`() {
        val config = SSLConfig()
        config.keystoreFromInputStream(inputStream, "password")
        Assertions.assertThrows(SSLConfigException::class.java) {
            config.keystoreFromInputStream(
                inputStream,
                "password"
            )
        }
    }

    @Test
    fun `load keystore from classpath correctly`() {
        val config = SSLConfig()
        Assertions.assertDoesNotThrow { config.keystoreFromClasspath(fileName, "password") }
        Assertions.assertEquals(fileName, config.inner.keyStoreFile)
        Assertions.assertEquals("password", config.inner.keyStorePassword)
    }

    @Test
    fun `load keystore from classpath twice`() {
        val config = SSLConfig()
        config.keystoreFromClasspath(fileName, "password")
        Assertions.assertThrows(SSLConfigException::class.java) { config.keystoreFromClasspath(fileName, "password") }
    }
}
