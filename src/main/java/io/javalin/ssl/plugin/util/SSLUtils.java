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
        X509ExtendedKeyManager keyManager = null;

        //TODO: Implement support for formats other than PEM
        boolean keyPresent = false;

        //Load pem data from a given path.
        if (config.inner.pemCertificatesPath != null) {
            if (config.inner.pemPrivateKeyPath != null) {
                if (!keyPresent) { //If the key has not been created yet by other means, create it.
                    if (config.inner.privateKeyPassword == null) {
                        keyManager = PemUtils.loadIdentityMaterial(config.inner.pemCertificatesPath, config.inner.pemPrivateKeyPath);
                    } else {
                        keyManager = PemUtils.loadIdentityMaterial(config.inner.pemCertificatesPath, config.inner.pemPrivateKeyPath, config.inner.privateKeyPassword.toCharArray());
                    }
                    keyPresent = true;
                } else {
                    throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
                }
            } else {
                throw new SSLConfigException(SSLConfigException.Types.MISSING_PRIVATE_KEY);
            }
        } else {
            if (config.inner.pemPrivateKeyPath != null) {
                throw new SSLConfigException(SSLConfigException.Types.MISSING_CERTIFICATE);
            }
        }

        //Load pem data from a given string.
        if (config.inner.pemCertificatesString != null) {
            if (config.inner.pemPrivateKeyString != null) {
                if (!keyPresent) { //If the key has not been created yet by other means, create it.
                    if (config.inner.privateKeyPassword == null) {
                        keyManager = PemUtils.parseIdentityMaterial(config.inner.pemCertificatesString, config.inner.pemPrivateKeyString,null);
                    } else {
                        keyManager = PemUtils.parseIdentityMaterial(config.inner.pemCertificatesString, config.inner.pemPrivateKeyString, config.inner.privateKeyPassword.toCharArray());
                    }
                    keyPresent = true;
                } else {
                    throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
                }
            } else {
                throw new SSLConfigException(SSLConfigException.Types.MISSING_PRIVATE_KEY);
            }
        } else {
            if (config.inner.pemPrivateKeyString != null) {
                throw new SSLConfigException(SSLConfigException.Types.MISSING_CERTIFICATE);
            }
        }

        //Load pem data from a given file.
        if (config.inner.pemCertificatesFile != null) {
            if (config.inner.pemPrivateKeyFile != null) {
                if (!keyPresent) { //If the key has not been created yet by other means, create it.
                    if (config.inner.privateKeyPassword == null) {
                        keyManager = PemUtils.loadIdentityMaterial(config.inner.pemCertificatesFile, config.inner.pemPrivateKeyFile);
                    } else {
                        keyManager = PemUtils.loadIdentityMaterial(config.inner.pemCertificatesFile, config.inner.pemPrivateKeyFile, config.inner.privateKeyPassword.toCharArray());
                    }
                    keyPresent = true;
                } else {
                    throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
                }
            } else {
                throw new SSLConfigException(SSLConfigException.Types.MISSING_PRIVATE_KEY);
            }
        } else {
            if (config.inner.pemPrivateKeyFile != null) {
                throw new SSLConfigException(SSLConfigException.Types.MISSING_CERTIFICATE);
            }
        }

        //Load pem data from a given InputStream.
        if (config.inner.pemCertificatesInputStream != null) {
            if (config.inner.pemPrivateKeyInputStream != null) {
                if (!keyPresent) { //If the key has not been created yet by other means, create it.
                    if (config.inner.privateKeyPassword == null) {
                        keyManager = PemUtils.loadIdentityMaterial(config.inner.pemCertificatesInputStream, config.inner.pemPrivateKeyInputStream);
                    } else {
                        keyManager = PemUtils.loadIdentityMaterial(config.inner.pemCertificatesInputStream, config.inner.pemPrivateKeyInputStream, config.inner.privateKeyPassword.toCharArray());
                    }
                    keyPresent = true;
                } else {
                    throw new SSLConfigException(SSLConfigException.Types.MULTIPLE_IDENTITY_LOADING_OPTIONS);
                }
            } else {
                throw new SSLConfigException(SSLConfigException.Types.MISSING_PRIVATE_KEY);
            }
        } else {
            if (config.inner.pemPrivateKeyInputStream != null) {
                throw new SSLConfigException(SSLConfigException.Types.MISSING_CERTIFICATE);
            }
        }


        if (!keyPresent) {
            throw new SSLConfigException(SSLConfigException.Types.MISSING_CERT_AND_KEY_FILE);
        } else
            return keyManager;

    }
}
