package io.javalin.community.ssl.util;

import io.javalin.community.ssl.SSLConfig;
import io.javalin.community.ssl.SSLConfigException;
import io.javalin.community.ssl.TrustConfig;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.jetty.util.JettySslUtils;
import nl.altindag.ssl.pem.util.PemUtils;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.X509ExtendedKeyManager;
import java.security.Provider;

/**
 * Utility class for SSL related tasks.
 */
public class SSLUtils {

    /**
     * Helper method to create a {@link SslContextFactory} from the SSLFactory.
     * This method is used to create the SSLContextFactory for the Jetty server as well as
     * configure the resulting factory.
     *
     * @param sslFactory The {@link SSLFactory} to use.
     * @param config The {@link SSLConfig} to use.
     * @return The created {@link SslContextFactory}.
     */
    public static SslContextFactory.Server createSslContextFactory(SSLFactory sslFactory, SSLConfig config) {
        return JettySslUtils.forServer(sslFactory);
    }

    /**
     * Helper method to create a {@link SSLFactory} from the given config.
     *
     * @param config The config to use.
     * @return The created {@link SSLFactory}.
     */
    public static SSLFactory getSslFactory(SSLConfig config) {
        return getSslFactory(config, false);
    }

    /**
     * Helper method to create a {@link SSLFactory} from the given config.
     *
     * @param config    The config to use.
     * @param reloading Whether the SSLFactory is being reloaded or is the first time.
     * @return The created {@link SSLFactory}.
     */
    public static SSLFactory getSslFactory(SSLConfig config, boolean reloading) {
        SSLFactory.Builder builder = SSLFactory.builder();

        //Add the identity information
        parseIdentity(config, builder);

        //Add the trust information
        if(config.getTrustConfig() != null) {
            parseTrust(config.getTrustConfig(), builder);
            builder.withNeedClientAuthentication();
        }

        if (!reloading) {
            builder.withSwappableIdentityMaterial();
            builder.withSwappableTrustMaterial();

            builder.withSecurityProvider(config.securityProvider);

            builder.withCiphers(config.tlsConfig.getCipherSuites());
            builder.withProtocols(config.tlsConfig.getProtocols());
        }


        return builder.build();
    }


    /**
     * Helper method to parse the given config and add Identity Material to the given builder.
     *
     * @param config The config to use.
     * @throws SSLConfigException if the key configuration is invalid.
     */
    public static void parseIdentity(SSLConfig config, SSLFactory.Builder builder) throws SSLConfigException {
        X509ExtendedKeyManager keyManager;

        SSLConfig.InnerConfig.IdentityLoadingType identityLoadingType = config.inner.getIdentityLoadingType();

        boolean passwordProtectedPem = config.inner.privateKeyPassword != null;

        switch (identityLoadingType) {
            case PEM_FILE_PATH:
                keyManager = passwordProtectedPem ?
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesPath,
                        config.inner.pemPrivateKeyPath,
                        config.inner.privateKeyPassword.toCharArray()) :
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesPath,
                        config.inner.pemPrivateKeyPath);
                break;
            case PEM_CLASS_PATH:
                keyManager = passwordProtectedPem ?
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesFile,
                        config.inner.pemPrivateKeyFile,
                        config.inner.privateKeyPassword.toCharArray()) :
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesFile,
                        config.inner.pemPrivateKeyFile);
                break;
            case PEM_STRING:
                keyManager = passwordProtectedPem ?
                    PemUtils.parseIdentityMaterial(config.inner.pemCertificatesString,
                        config.inner.pemPrivateKeyString,
                        config.inner.privateKeyPassword.toCharArray()) :
                    PemUtils.parseIdentityMaterial(config.inner.pemCertificatesString,
                        config.inner.pemPrivateKeyString,
                        null);
                break;
            case PEM_INPUT_STREAM:
                keyManager = passwordProtectedPem ?
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesInputStream,
                        config.inner.pemPrivateKeyInputStream,
                        config.inner.privateKeyPassword.toCharArray()) :
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesInputStream,
                        config.inner.pemPrivateKeyInputStream);
                break;
            case KEY_STORE_CLASS_PATH:
                builder.withIdentityMaterial(config.inner.keyStoreFile, config.inner.keyStorePassword.toCharArray());
                return;
            case KEY_STORE_FILE_PATH:
                builder.withIdentityMaterial(config.inner.keyStorePath, config.inner.keyStorePassword.toCharArray());
                return;
            case KEY_STORE_INPUT_STREAM:
                builder.withIdentityMaterial(config.inner.keyStoreInputStream, config.inner.keyStorePassword.toCharArray());
                return;
            case NONE:
            default:
                throw new SSLConfigException(SSLConfigException.Types.MISSING_CERT_AND_KEY_FILE);
        }

        builder.withIdentityMaterial(keyManager);
    }


    /**
     * Helper method to parse the given config and add Trust Material to the given builder.
     *
     * @param config The config to use.
     */
    public static void parseTrust(TrustConfig config, SSLFactory.Builder builder) {
        if (!config.certificates.isEmpty()) {
            builder.withTrustMaterial(config.certificates);
        }

        if (!config.keyStores.isEmpty()) {
            config.keyStores.forEach(builder::withTrustMaterial);
        }
    }


    /**
     * Helper method to create a working {@link Provider} for the current JVM.
     */
    public static Provider getSecurityProvider() {
        if (osSupportsConscrypt()) {
            return new org.conscrypt.OpenSSLProvider();
        } else {
            return null;
        }
    }

    /**
     * Checks if the current OS is supported by Conscrypt.
     * Currently only Windows (x86, x64), Linux (x64) and Mac OS X (x64) are supported.
     *
     * @return true if the current OS is supported by Conscrypt.
     */
    public static boolean osSupportsConscrypt() {
        String osName = System.getProperty("os.name").toLowerCase();
        //Remove all non-alphanumeric characters from the os name
        osName = osName.replaceAll("[^a-z0-9]", "");

        if (osName.contains("windows")) {
            return true;
        } else if (osName.contains("linux") || (osName.contains("macosx") || osName.contains("osx"))) {
            return osIsAmd64();
        } else {
            return false;
        }
    }

    /**
     * Checks if the current OS runs on an x86_64 architecture.
     *
     * @return true if the current OS runs on an x86_64 architecture.
     */
    public static boolean osIsAmd64() {
        String osArch = System.getProperty("os.arch").toLowerCase();
        osArch = osArch.replaceAll("[^a-z0-9]", "");

        String[] archNames = new String[]{"x8664", "amd64", "ia32e", "em64t", "x64"};
        for (String archName : archNames) {
            if (osArch.contains(archName)) {
                return true;
            }
        }
        return false;
    }
}
