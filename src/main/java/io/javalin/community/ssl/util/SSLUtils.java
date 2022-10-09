package io.javalin.community.ssl.util;

import io.javalin.community.ssl.SSLConfig;
import io.javalin.community.ssl.SSLConfigException;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.JettySslUtils;
import nl.altindag.ssl.util.PemUtils;
import org.conscrypt.Conscrypt;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.X509ExtendedKeyManager;

/**
 * Utility class for SSL related tasks.
 */
public class SSLUtils {

    /**
     * Helper method to create a {@link SslContextFactory} from the given config.
     *
     * @param config The config to use.
     * @return The created {@link SslContextFactory}.
     */
    public static SslContextFactory.Server createSslContextFactory(SSLConfig config) {

        //The sslcontext-kickstart factory
        SSLFactory.Builder builder = SSLFactory.builder();

        //Add the identity information
        parseIdentity(config, builder);

        builder.withSecurityProvider(Conscrypt.newProvider());

        builder.withCiphers(config.tlsConfig.getCipherSuites());
        builder.withProtocols(config.tlsConfig.getProtocols());

        SSLFactory sslFactory = builder.build();

        return JettySslUtils.forServer(sslFactory);
    }

    /**
     * Helper method to parse the given config and add Identity Material to the given builder.
     *
     * @param config  The config to use.
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
}
