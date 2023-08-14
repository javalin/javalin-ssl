package io.javalin.community.ssl;

/**
 * Data class for the SSL configuration.
 *
 * @see <a href="https://wiki.mozilla.org/Security/Server_Side_TLS">Security/Server Side TLS</a>
 */
public final class TLSConfig {

    private static final String GUIDELINES_VERSION = "5.5";

    /**
     * For modern clients that support TLS 1.3, with no need for backwards compatibility
     */
    public static final TLSConfig MODERN = new TLSConfig(
        new String[]{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
        new String[]{"TLSv1.3"});

    /**
     * Recommended configuration for a general-purpose server
     */
    public static final TLSConfig INTERMEDIATE = new TLSConfig(
        new String[]{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
        new String[]{"TLSv1.2", "TLSv1.3"});

    /**
     * For services accessed by very old clients or libraries, such as Internet Explorer 8 (Windows XP), Java 6, or OpenSSL 0.9.8
     */
    public static final TLSConfig OLD = new TLSConfig(
        new String[]{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
        new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"});


    /**
     * String array of cipher suites to use, following the guidelines in the <a href="https://www.eclipse.org/jetty/documentation/jetty-11/operations-guide/index.html#og-protocols-ssl-customize-ciphers"> Jetty documentation</a>.
     */
    private final String[] cipherSuites;

    /**
     * String array of protocols to use, following the guidelines in the <a href="https://www.eclipse.org/jetty/documentation/jetty-11/operations-guide/index.html#og-protocols-ssl-customize-versions"> Jetty documentation</a>.
     */
    private final String[] protocols;

    public TLSConfig(String[] cipherSuites, String[] protocols) {
        this.cipherSuites = cipherSuites;
        this.protocols = protocols;
    }

    public String[] getCipherSuites() {
        return this.cipherSuites;
    }

    public String[] getProtocols() {
        return this.protocols;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof TLSConfig)) return false;
        final TLSConfig other = (TLSConfig) o;
        if (!java.util.Arrays.deepEquals(this.getCipherSuites(), other.getCipherSuites())) return false;
        if (!java.util.Arrays.deepEquals(this.getProtocols(), other.getProtocols())) return false;
        return true;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        result = result * PRIME + java.util.Arrays.deepHashCode(this.getCipherSuites());
        result = result * PRIME + java.util.Arrays.deepHashCode(this.getProtocols());
        return result;
    }

    public String toString() {
        return "TLSConfig(cipherSuites=" + java.util.Arrays.deepToString(this.getCipherSuites()) + ", protocols=" + java.util.Arrays.deepToString(this.getProtocols()) + ")";
    }
}
