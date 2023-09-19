package io.javalin.community.ssl

/**
 * Data class for the SSL configuration.
 *
 * @see [Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)
 */
class TLSConfig(
    /**
     * String array of cipher suites to use, following the guidelines in the [ Jetty documentation](https://www.eclipse.org/jetty/documentation/jetty-11/operations-guide/index.html#og-protocols-ssl-customize-ciphers).
     */
    val cipherSuites: Array<String>,
    /**
     * String array of protocols to use, following the guidelines in the [ Jetty documentation](https://www.eclipse.org/jetty/documentation/jetty-11/operations-guide/index.html#og-protocols-ssl-customize-versions).
     */
    val protocols: Array<String>
) {

    override fun toString(): String {
        return "TLSConfig(cipherSuites=" + cipherSuites.contentDeepToString() + ", protocols=" + protocols.contentDeepToString() + ")"
    }

    companion object {
        private const val GUIDELINES_VERSION = "5.7"

        /**
         * For modern clients that support TLS 1.3, with no need for backwards compatibility
         */
        val MODERN = TLSConfig(
            arrayOf(
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256"),
            arrayOf("TLSv1.3")
        )

        /**
         * Recommended configuration for a general-purpose server
         */
        val INTERMEDIATE = TLSConfig(
            arrayOf(
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            ), arrayOf("TLSv1.2","TLSv1.3")
        )

        /**
         * For services accessed by very old clients or libraries, such as Internet Explorer 8 (Windows XP), Java 6, or OpenSSL 0.9.8
         */
        val OLD = TLSConfig(
            arrayOf(
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            ), arrayOf("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
        )
    }
}
