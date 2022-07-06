package io.javalin.ssl.plugin.util;

import io.javalin.ssl.plugin.SSLConfig;
import io.javalin.ssl.plugin.SSLConfigException;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.JettySslUtils;
import nl.altindag.ssl.util.PemUtils;
import org.conscrypt.Conscrypt;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.X509ExtendedKeyManager;

public class SSLUtils {

    /**
     * Helper method to create a {@link SslContextFactory} from the given config.
     *
     * @param keyManager The key manager to use.
     * @param config The config to use.
     * @return The created {@link SslContextFactory}.
     */
    public static SslContextFactory.Server createSslContextFactory(X509ExtendedKeyManager keyManager, SSLConfig config) {

        //The sslcontext-kickstart factory
        SSLFactory.Builder builder = SSLFactory.builder();

        //Add the identity information
        builder.withIdentityMaterial(keyManager);

        builder.withSecurityProvider(Conscrypt.newProvider());

        SSLFactory sslFactory = builder.build();

        //TODO: Fine tune the TLS configuration

        return JettySslUtils.forServer(sslFactory);
    }

    /**
     * Helper method to create a {@link X509ExtendedKeyManager} from the given config.
     *
     * @param config The config to use.
     * @return The created {@link X509ExtendedKeyManager}.
     * @throws SSLConfigException if the key configuration is invalid.
     */
    public static X509ExtendedKeyManager createKeyManager(SSLConfig config) {
        X509ExtendedKeyManager keyManager;

        //TODO: Implement support for formats other than PEM

        SSLConfig.InnerConfig.IdentityLoadingType identityLoadingType = config.inner.getIdentityLoadingType();

        boolean passwordProtected = config.inner.privateKeyPassword != null;

        switch (identityLoadingType) {
            case PEM_FILE_PATH:
                keyManager = passwordProtected ?
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesPath,
                        config.inner.pemPrivateKeyPath,
                        config.inner.privateKeyPassword.toCharArray()) :
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesPath,
                        config.inner.pemPrivateKeyPath);
                break;
            case PEM_CLASS_PATH:
                keyManager = passwordProtected ?
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesFile,
                        config.inner.pemPrivateKeyFile,
                        config.inner.privateKeyPassword.toCharArray()) :
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesFile,
                        config.inner.pemPrivateKeyFile);
                break;
            case PEM_STRING:
                keyManager = passwordProtected ?
                    PemUtils.parseIdentityMaterial(config.inner.pemCertificatesString,
                        config.inner.pemPrivateKeyString,
                        config.inner.privateKeyPassword.toCharArray()) :
                    PemUtils.parseIdentityMaterial(config.inner.pemCertificatesString,
                        config.inner.pemPrivateKeyString,
                        null);
                break;
            case PEM_INPUT_STREAM:
                keyManager = passwordProtected ?
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesInputStream,
                        config.inner.pemPrivateKeyInputStream,
                        config.inner.privateKeyPassword.toCharArray()) :
                    PemUtils.loadIdentityMaterial(config.inner.pemCertificatesInputStream,
                        config.inner.pemPrivateKeyInputStream);
                break;
            case NONE:
            default:
                throw new SSLConfigException(SSLConfigException.Types.MISSING_CERT_AND_KEY_FILE);
        }

        return keyManager;

    }
}
