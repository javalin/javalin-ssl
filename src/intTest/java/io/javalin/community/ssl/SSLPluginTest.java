package io.javalin.community.ssl;

import io.javalin.Javalin;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.tls.Certificates;
import okhttp3.tls.HandshakeCertificates;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Tag("integration")
public class SSLPluginTest extends IntegrationTestClass {

    @Test
    public void testReloadIdentityPemCert() {
        int securePort = ports.getAndIncrement();
        String https = HTTPS_URL_WITH_PORT.apply(securePort);

        // Create a http client that trusts the self-signed certificates
        HandshakeCertificates.Builder builder = new HandshakeCertificates.Builder();
        builder.addTrustedCertificate(Certificates.decodeCertificatePem(CERTIFICATE_AS_STRING)); // Valid certificate from Vigo
        builder.addTrustedCertificate(Certificates.decodeCertificatePem(NORWAY_CERTIFICATE_AS_STRING)); // Valid certificate from Bergen
        HandshakeCertificates clientCertificates = builder.build();

        // Two clients are needed, one for the initial connection and one for after the reload, due to the way OkHttp caches connections
        OkHttpClient client = new OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager()).hostnameVerifier((hostname, session) -> true).build();
        OkHttpClient client2 = new OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager()).hostnameVerifier((hostname, session) -> true).build();

        SSLPlugin sslPlugin = new SSLPlugin(sslConfig -> {
            sslConfig.insecure = false;
            sslConfig.securePort = securePort;
            sslConfig.pemFromString(NORWAY_CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
        });


        try (Javalin app = Javalin.create(config -> {
            config.showJavalinBanner = false;
            config.plugins.register(sslPlugin);
        }).get("/", ctx -> ctx.result(SUCCESS)).start()) {

            // Initial connection
            Response res = client.newCall(new Request.Builder().url(https).build()).execute();
            //Check that the certificate is the one we expect
            X509Certificate cert = (X509Certificate) res.handshake().peerCertificates().get(0);
            log.info("First Certificate: {}", cert.getSubjectX500Principal().getName());
            assertTrue(cert.getIssuerX500Principal().getName().contains("Bergen"));

            // Reload the identity
            sslPlugin.reload(newConf -> {
                newConf.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            });
            // Second connection
            res = client2.newCall(new Request.Builder().url(https).build()).execute();
            cert = (X509Certificate) res.handshake().peerCertificates().get(0);
            log.info("Second Certificate: {}", cert.getSubjectX500Principal().getName());
            assertTrue(cert.getIssuerX500Principal().getName().contains("Vigo"));
        } catch (IOException e) {
            fail(e);
        }

    }

    public void testReloadIdentityKeystore(String norwayKeyStorePath, String vigoKeyStorePath) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        int securePort = ports.getAndIncrement();
        String https = HTTPS_URL_WITH_PORT.apply(securePort);

        List<X509Certificate> certificates = new ArrayList<>();

        // Create a http client that trusts the self-signed certificates
        KeyStore keyStore = KeyStore.getInstance(new File(norwayKeyStorePath),KEY_STORE_PASSWORD.toCharArray()); // Valid certificate from Bergen
        keyStore.aliases().asIterator().forEachRemaining(alias -> {
            try {
                certificates.add((X509Certificate) keyStore.getCertificate(alias));
            } catch (KeyStoreException e) {
                fail(e);
            }
        });
        KeyStore keyStore2 = KeyStore.getInstance(new File(vigoKeyStorePath),KEY_STORE_PASSWORD.toCharArray()); // Valid certificate from Vigo
        keyStore2.aliases().asIterator().forEachRemaining(alias -> {
            try {
                certificates.add((X509Certificate) keyStore2.getCertificate(alias));
            } catch (KeyStoreException e) {
                fail(e);
            }
        });

        // Create a http client that trusts the self-signed certificates
        HandshakeCertificates.Builder builder = new HandshakeCertificates.Builder();
        for (X509Certificate certificate : certificates) {
            builder.addTrustedCertificate(certificate);
        }
        HandshakeCertificates clientCertificates = builder.build();

        // Two clients are needed, one for the initial connection and one for after the reload, due to the way OkHttp caches connections
        OkHttpClient client = new OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager()).hostnameVerifier((hostname, session) -> true).build();
        OkHttpClient client2 = new OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager()).hostnameVerifier((hostname, session) -> true).build();

        SSLPlugin sslPlugin = new SSLPlugin(sslConfig -> {
            sslConfig.insecure = false;
            sslConfig.securePort = securePort;
            sslConfig.keystoreFromPath(norwayKeyStorePath, KEY_STORE_PASSWORD);
        });

        try (Javalin app = Javalin.create(config -> {
            config.showJavalinBanner = false;
            config.plugins.register(sslPlugin);
        }).get("/", ctx -> ctx.result(SUCCESS)).start()) {

            // Initial connection
            Response res = client.newCall(new Request.Builder().url(https).build()).execute();
            //Check that the certificate is the one we expect
            X509Certificate cert = (X509Certificate) res.handshake().peerCertificates().get(0);
            log.info("First Certificate: {}", cert.getSubjectX500Principal().getName());
            assertTrue(cert.getIssuerX500Principal().getName().contains("Bergen"));

            // Reload the identity
            sslPlugin.reload(newConf -> {
                newConf.keystoreFromPath(vigoKeyStorePath, KEY_STORE_PASSWORD);
            });

            // Second connection
            res = client2.newCall(new Request.Builder().url(https).build()).execute();
            cert = (X509Certificate) res.handshake().peerCertificates().get(0);
            log.info("Second Certificate: {}", cert.getSubjectX500Principal().getName());
            assertTrue(cert.getIssuerX500Principal().getName().contains("Vigo"));
        } catch (IOException e) {
            fail(e);
        }

    }

    @Test
    public void testReloadP12(){
        try {
            testReloadIdentityKeystore(NORWAY_P12_KEY_STORE_PATH, P12_KEY_STORE_PATH);
        } catch (Exception e){
            fail(e);
        }
    }

    @Test
    public void testReloadJks(){
        try {
            testReloadIdentityKeystore(NORWAY_JKS_KEY_STORE_PATH, JKS_KEY_STORE_PATH);
        } catch (Exception e){
            fail(e);
        }
    }

    @Test
    public void testReloadIdentityNonSslServer(){
        int insecurePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);

        SSLPlugin sslPlugin = new SSLPlugin(sslConfig -> {
            sslConfig.secure = false;
            sslConfig.insecurePort = insecurePort;
        });

        try (Javalin app = Javalin.create(config -> {
            config.showJavalinBanner = false;
            config.plugins.register(sslPlugin);
        }).get("/", ctx -> ctx.result(SUCCESS)).start()) {
            Response res = new OkHttpClient().newCall(new Request.Builder().url(http).build()).execute();
            assertTrue(res.isSuccessful());
            assertThrows(IllegalStateException.class, () -> sslPlugin.reload(newConf -> {
                newConf.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
            }));
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    public void testReloadIdentityNonStartedServer(){
        SSLPlugin sslPlugin = new SSLPlugin(sslConfig -> {
            sslConfig.secure = false;
            sslConfig.insecurePort = ports.getAndIncrement();
        });
        assertThrows(IllegalStateException.class, () -> sslPlugin.reload(newConf -> {
            newConf.pemFromString(CERTIFICATE_AS_STRING, NON_ENCRYPTED_KEY_AS_STRING);
        }));
    }

}
