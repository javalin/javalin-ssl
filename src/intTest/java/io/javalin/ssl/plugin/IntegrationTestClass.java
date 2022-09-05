package io.javalin.ssl.plugin;

import io.javalin.Javalin;
import lombok.Getter;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.tls.Certificates;
import okhttp3.tls.HandshakeCertificates;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class IntegrationTestClass {

    static final String CERTIFICATE_AS_STRING = "-----BEGIN CERTIFICATE-----\n" + "MIIDpjCCAo6gAwIBAgIUKK29nJVFCs8SjBqcvxrg7boyem8wDQYJKoZIhvcNAQEL\n" + "BQAwQjESMBAGA1UEAwwJbG9jYWxob3N0MQswCQYDVQQGEwJFUzEQMA4GA1UECAwH\n" + "R2FsaWNpYTENMAsGA1UEBwwEVmlnbzAgFw0yMjA3MDYxMTQyMDdaGA80MDA1MDMx\n" + "MjExNDIwN1owQjESMBAGA1UEAwwJbG9jYWxob3N0MQswCQYDVQQGEwJFUzEQMA4G\n" + "A1UECAwHR2FsaWNpYTENMAsGA1UEBwwEVmlnbzCCASIwDQYJKoZIhvcNAQEBBQAD\n" + "ggEPADCCAQoCggEBALtW247iPVAuCcQByuqgj8tSzJcwVqCmheT6ld0Xe7DYoLOL\n" + "EsjilB/jgG9aBEBfYJ2h74K7SIdqiSDz4rgUuJUzhZnJo5d3n3wT9Wb2AZcsqFce\n" + "JK0UNBKe2/1b01dFWtQFW4zHC/JM/Gp0dMTy1Vt1Zf/3SmQjSD/KzgJf4m2O/GOP\n" + "3iRFsCSPC4CU3TZCDmI5/qRr4icJCY5s3gJ+RT+edfsvtdkfAO4hK/p+37RrwHax\n" + "nyFLoAzYdJMcnDX/+V7Ez2y7jkTkcUk2gKG+3dpio2XqAE9pXcXa4kYk0NL9Vw6L\n" + "C2QMefFKHLDqLWx/bfQXpbULFawldETDbuLVe7UCAwEAAaOBkTCBjjAdBgNVHQ4E\n" + "FgQUiiPTBoFstcGbb0zYWsM/ZwupRRYwHwYDVR0jBBgwFoAUiiPTBoFstcGbb0zY\n" + "WsM/ZwupRRYwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\n" + "BgEFBQcDAjAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcN\n" + "AQELBQADggEBAGvqUrtYWZpKBJNYL4UVLnm2+dQl33l8BH7PhU6YvMufThDCVjOw\n" + "IJ7ezOReDlCAmytQD7ChKpsJrAOBzKRdrifL0f88psbE83+6Ys/s/1rHMq282p/S\n" + "WPRiZDVO8Mw2ra9v9b6cprW5phHJkp7TiIBP82A+v19lt3R+vE4HZ91ZyioNqMzf\n" + "Aqvd5gfxHexpilgil0osF0o/8ajSnLiBfWI82Lz/1JB+xUMYW91ahRgt13/54h13\n" + "eL70steoAmx55he3pQaaeRZKzI1nLxsrTkjs055jDn0G/yj1L6kY3OeVFg3AhETJ\n" + "sg+yATMTef2Qskr4dgzb1LJkC9meaU2TFwk=\n" + "-----END CERTIFICATE-----";
    static final String NON_ENCRYPTED_KEY_AS_STRING = "-----BEGIN PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VtuO4j1QLgnE\n" + "AcrqoI/LUsyXMFagpoXk+pXdF3uw2KCzixLI4pQf44BvWgRAX2Cdoe+Cu0iHaokg\n" + "8+K4FLiVM4WZyaOXd598E/Vm9gGXLKhXHiStFDQSntv9W9NXRVrUBVuMxwvyTPxq\n" + "dHTE8tVbdWX/90pkI0g/ys4CX+Jtjvxjj94kRbAkjwuAlN02Qg5iOf6ka+InCQmO\n" + "bN4CfkU/nnX7L7XZHwDuISv6ft+0a8B2sZ8hS6AM2HSTHJw1//lexM9su45E5HFJ\n" + "NoChvt3aYqNl6gBPaV3F2uJGJNDS/VcOiwtkDHnxShyw6i1sf230F6W1CxWsJXRE\n" + "w27i1Xu1AgMBAAECggEAfPI7UZr3BckO3lnLup0ICrXYmmW1AUTPPJ8c4O7Oom55\n" + "EAaLqsvjuzkC6kGBYGW8jKX6lpjOkPKvLvk6l0fKrEhGrQFdSKKSDjFJlTgya19v\n" + "j1sdXwqAiILHer2JwUUShSJlowkGoL5UA7RURR8oye0M8KFATnVxtIpQyCinXiW/\n" + "LkDuqUr8MIbu6V/KcoSOLfJyTWyuwSRPHuFKhv154UAqaTkSPbf2mCTa9hH5Tb4f\n" + "Lfzy9o3Ux4ieZceG28De+SmC7uMzbBs1stowOuDmFg3znI/1Br/sQEAXPFngDe3s\n" + "soDD2PbLo7/4SPBNgl5vygf7jhvxHPY3DTUXOxLSgQKBgQD4EzKVTx/GpF7Yswma\n" + "oixidzSi/KnHJiMjIERF4QPVfDNnggRORNMbPnRhNWSRhS7r+INYbN4yB/vBZO5I\n" + "IIqowdJbLjGbmq91equP0zzrP2wCjqtFK6gRElX7acAWY5xTesIT5Fa1Ug++dFLS\n" + "MxCZKL6JMZaHJzZVzXugaltMsQKBgQDBUvPSaDnIBrZGdNtAyNMxZyVbp/ObIKW1\n" + "TvCDX2hqf+yiTVclbZr5QkwCE3MHErfsKlWU01K9CtzsQh4u9L5tPaeFlvm6iZq6\n" + "ktbflNvI+z+qEW3JbROR4WwwbmWFvKRLBA0OQom7tGuNnNyRtkDFxlkFJPcD6Eff\n" + "ZEq+ewrQRQKBgQCV7URM6J0TuJN58/qB8jFQ8Spmtr0FFw91UzLv6KYgiAepLvLb\n" + "Os07UeuUNGiragqJoo//CQzgv+JvZ0h7Xu9uPnWblbd1i28vWQwGyGuw4Yutn/vy\n" + "ugfBCYvdfnQRE/KOoUpaK04cF5RcToEfeK03Y2CEGewXkqNMB/wHXz/+gQKBgE8Y\n" + "34WQ+0Mp69375dEl2bL23sQXfYZU3zfFaoZ1vMUGPg1R03wO0j91rp+S0ZdtQy8v\n" + "SwCvTcTm8uj/TFYt8NPFTAtOcDKwJkx708p6n0ol8jBlHSQyqrUfJCLUqFkFi7rd\n" + "l3HkK3JPKUoxidVcWjgRJU8DhsVkfjOaVzKEKTJ5AoGARBwn7gt2H35urQ6/U3nJ\n" + "hFjOVn01F5uV0NvRtRDCsAIUMeA2T4pwALUUIqlA9HmpwYgLeG4bZ+SkhNpy70N/\n" + "qcufT1DeM+q3H5zFPANyjcqVaqa6KUnttvi/lhxMdRb6GsA9TzzHzY1P9ovpIOCK\n" + "IS639NPzxpI0Ka+v6t+nFEM=\n" + "-----END PRIVATE KEY-----\n";
    static final String ENCRYPTED_KEY_AS_STRING = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + "MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIMDP+/JKdUc4CAggA\n" + "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBRfpz0ZTscSvALfUISuNYIBIIE\n" + "0I8rVF2h/qQANJ3WvXFcmm7dFqEiQwUm8cDxaDpPd8RRweclTesEj70yg+3xcGLh\n" + "rhSFrNSB2wmy/jB6lFcN02KcSU3p6H7aSuLRffbYYAQ3LGU6Ie79NW68x189zB/b\n" + "sDi6gWkxHCrGzBydKR4a6ZvF9TMnP743hCw3t3NrO/4xdoZ9+YaxmBaBjt4E1Bns\n" + "J2yCHHV5kXXsWOZJvTTWxf+fIEQNe1cjidBxcpvQxreZpOsday2KM8tctom+p9lw\n" + "DEF0mhUi/FHZZnmfgr1Cz4+PmspjOTykX+0RWD1wi0kMJwqo6aRHwlEbEE+f83Df\n" + "kazqIXOfD0VrzSXTwr1kIzjQI+DK8sKyfg5lfTby1AFy5cvtJxL7cK6As9Cq05XI\n" + "i2fX5PWUj1sHplMOI2+qh31R7w6qb0DygXC22ZFNLlFYwP0QKPp9XzZZLIvPI662\n" + "9xlF4VgtcS9JV7hztrg6Bbc23l1cSsBXPqreWd39NM/Kggf6J3GV/P0AacYYp0OY\n" + "A3Pt9i+RV+HHv8OwfZ+v4RH8hVhtDkPWyBJX581zwF5OQLqjksKa1FNC8qB/VlE4\n" + "Ponm33vn1gWtKY962sYoJxDVHbgWwpWP7bSqtO66jiwlTEyQwltd3LbZGcJ4yJNd\n" + "eEJUE8vFHyXmEx1KoDHUh2/v9l6pdo59PgBlY8mxl95AuTNds+dtuqZQE6ZNZvDZ\n" + "lw7dOp+BATb/3YWCF5O6jQjm11ji9kZxgnPBTSiaegFFIa4OxdQwP2pxbyVk4rGH\n" + "/gs6olWtc3hqqQspMJDqT2cJeaE61us7hUya1w1LjivOvofR3Zt2v2Wtxmm+ey3e\n" + "/mPBZH1LIRdP9vEuHxKkjjppXVRWL5TdHeN9Ai6jG3/WCp/NgBnjOi9/5GVX7j+T\n" + "dUzGBaxwUGt10QZ8Yvo9qT8Cg2tiUD770EzaD09aiRfoAs7YwLsVi35gul+JyNrD\n" + "CzqZ8I2NZ6Uo/r9I9Xda9qkoxbS2hNg+53whm5L2fT4SrJ69MOY/tM3mR8q1Ta18\n" + "W+dXuFSD+3nAU7Aqug4LlKcOS9/RW18kRtHRVatXZscxITO5dlgmw7zEVzrkwa+q\n" + "r1y4YG488XZZ3KCXPJthnmP4nIYERW6hn62P8EKzM8wfxxT39O96QNzMgszor/WA\n" + "TG8o0JDRvG5WW/OfVA4Ls8QK6lx3E2cPhyqnvM+HirtP2xL4Gd0SibGIK7QvewSf\n" + "9a5TnbQsuoWvTqtzX7PEb9snLxQjaxTLZEbTyimwEyaaZ1Ev72did2EdmA3UEtzq\n" + "e+X86mvYOZrAJIWNGIfoMI3QPtxlC2MbDjUcLB5crk90T2dCcIdwpr6cKGdnEqP+\n" + "DmkkwTl84MSV2tVQ2qCJPtiwsR8V2xkwqesD1p0G5whR2SxsUQDoG48l1zRkLrA5\n" + "PbwUii9Xapp5+R08t+dIt19cRJyewjAKxpWkKHNjtXmBMJpvJ65A4wAAV5vqcTdY\n" + "FIrJEMySqFDrodCwkAs9s8FKIWvEnWKkaX2NvjoTWdQEGmKpiEazUsknd4wNX8js\n" + "MjjY/VHqWNYR6cF84H+WuFS86S37Vt3nBEpos0vp9n8epNNC+ETcewKMgovLJMnt\n" + "na5mQXa7ctzrJ+bqW9B+QLBX6KZk3tRnigYO6Fum0t7I\n" + "-----END ENCRYPTED PRIVATE KEY-----\n";

    static final String GOOGLE_CERTIFICATE_AS_STRING = "-----BEGIN CERTIFICATE-----\n" + "MIIDXTCCAkWgAwIBAgIULxRctoyJitKoVft6Dn6F458+uK8wDQYJKoZIhvcNAQEL\n" + "BQAwJzETMBEGA1UEAwwKZ29vZ2xlLmNvbTEQMA4GA1UECgwHSmF2YWxpbjAgFw0y\n" + "MjA4MDgwOTE4NDRaGA8yMTIyMDcxNTA5MTg0NFowJzETMBEGA1UEAwwKZ29vZ2xl\n" + "LmNvbTEQMA4GA1UECgwHSmF2YWxpbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" + "AQoCggEBANgf9ywzZUgab2y9WIJTf4H6rxMITbRDC3xYJRVEHc8WgegrlPwXw4V/\n" + "Qr92xChowUKZBQX98yvLXMc0YziRmqY+m5IriaWY7Jvr82pkHkLKWyjzFmHZBMAd\n" + "lWWjDKDD5abKPhsPu4tJg3YedRm7SjZIm7rpj+rEau4ALGRonM8L4jpqZJ+Jg8Sq\n" + "DDKTnVGLiYuhxtmby+/PRV/mhmJJ6dPOOcdIQlIn1PCrUDJbt2zMkuflrVzl+6eY\n" + "7GYq5h+QqCgO2XK+6q5RQBxtMUIp8Bi0AR6j+g3yAE6uiAPXhDQOj+fzKRJhoYcf\n" + "cQ84yxzN4benHPPPfLw42rquA7qB/BECAwEAAaN/MH0wHQYDVR0OBBYEFCIswSAR\n" + "oq1RbOP1ygckApt9wHPKMB8GA1UdIwQYMBaAFCIswSARoq1RbOP1ygckApt9wHPK\n" + "MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\n" + "DAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAi4zGlp2DmaH9sMiRgqA5\n" + "dDO8UbrW1TNNES7Dwo1519sERiosCzGVBqjVOzUzFYyrW/jF8kKd8NoIZSlWvoeQ\n" + "A0+6dxYy7oNY0UTJbW25hSRXMF1FCnxBfLLZ1J9lowzhts3yx5REJZVWEvsF0Agy\n" + "qgNEkKYSaeUtuSzUhMVPGs9AuMwl/M0M1q+2WBMeDLaGXhAXJC5jZ47BkEVgnz5+\n" + "/IIWbFJQ+eGEgL+GVFCxgebvJwncPruDipaS7i486kYyoymBKiSXeUN+z+gdaIHk\n" + "YHuSkRVAU4BiSGd72UK+KWIYBttkeINcYLRyZbdYkY5sgBGTJnj2ke0vnM13o7UM\n" + "jw==\n" + "-----END CERTIFICATE-----\n";

    static final String GOOGLE_KEY_AS_STRING = "-----BEGIN PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDYH/csM2VIGm9s\n" + "vViCU3+B+q8TCE20Qwt8WCUVRB3PFoHoK5T8F8OFf0K/dsQoaMFCmQUF/fMry1zH\n" + "NGM4kZqmPpuSK4mlmOyb6/NqZB5Cylso8xZh2QTAHZVlowygw+Wmyj4bD7uLSYN2\n" + "HnUZu0o2SJu66Y/qxGruACxkaJzPC+I6amSfiYPEqgwyk51Ri4mLocbZm8vvz0Vf\n" + "5oZiSenTzjnHSEJSJ9Twq1AyW7dszJLn5a1c5funmOxmKuYfkKgoDtlyvuquUUAc\n" + "bTFCKfAYtAEeo/oN8gBOrogD14Q0Do/n8ykSYaGHH3EPOMsczeG3pxzzz3y8ONq6\n" + "rgO6gfwRAgMBAAECggEAOCrWid4xjDOSkagDwJsCoD0OEtwtlZN3ALHHsWcqeA9Z\n" + "Y4UwCvQCFEemiSvMftP6pdwuugftkowfaIXs416z2lCbDbnS4/6CP2Nqt1Odqa39\n" + "Uv8Z6gQEgAkwMmHVflJq9JXK3i2Qh/pq99+ifzV1a/YiwsjAZjr1rzTMVKv7VLM/\n" + "cRwEffg/kus8b/RDUVDcTFlX2drypfAI9T2P7kaiMLVKI7tcWnn1RPUdUqlG8LjB\n" + "4ZyyZXNGNrd93zYWWe1DflUwP187SyoGbsn0vQe15n0U7cVOE8xLOBNFJiKSUJGi\n" + "hdUUeIgXZS9MGTfQN6QldRsFNlv6DGDvSzocqtl7gQKBgQD6P96IbtQeD/UwVKb1\n" + "1KzvDzdzlxT4XG7e2ZPj71tG9d84V72PDPAYnzftPJRkD08lDJLvAvKqqKCPTX3V\n" + "QgauF2njX1XLa649E4/hb5VHnJQj9Fwlx3/KUaNWI8zu3PR+5gKp/dlJiJz0v84T\n" + "gNw/VYhzfXyjPtbJXYrij8QpRQKBgQDdF1pbBKDAkBwoiOa2jgBtjnzHm7SxLCqq\n" + "/BBsKT54q8yxdTsY6MZ4J+497Z+AL65zHKMgcDsMEOvKDqLhurvqvWzUGTCv/5St\n" + "xOuwJ0k4kIVrQEBvvAJmBT44WOQZM3M9vxbwoG2mjfsSPz7OdrkK+hnwBlu91AjK\n" + "mP9rKa/mXQKBgQDYbfSgOnnpphOAQTZE1jLabmae6cORKSAaTELDl3dx36O2ruua\n" + "lK3yHYHZA9Oy1iq0+DL706jcQArc5UA2+GuelVFW/FTPIcoHuKtvZXnN/XWBww0O\n" + "/4NeD00casoKq74pIfSb4JfUKPrWEizAYWoavHbOq3DoHqjUbrp3R693oQKBgA7i\n" + "T5bpDNlp2jtwW/fWP3kgqo3VkaiLzKOOLJzbefUtu64Gsl/O6+2S4psQsDg0/Y2K\n" + "VAEPDSqWyQjlS1ne9F+tOPJeb8SpdBzusN8/BdLlB9ZckPn0skSj/bhVY6W+rPdv\n" + "MeApLLiVvl1QHK5Rl8uBYtWh1/NDnwPkoO1Z9RmRAoGALzIURD5Dg9FCpd9ym+UZ\n" + "JWI9lPvbL3uBzD53ys0dtzoSaTayishooeggYYJEbYpAxNH0WE1M7dqZH/OjTaAO\n" + "Kp7LluqrRTUGMYHogBX485sCWhZ91r4RqPa90UcUcpjXUnVu7Absn7/FOcT1z++M\n" + "6HNWxu22y49Nc0iAEtqCOVk=\n" + "-----END PRIVATE KEY-----\n";

    public static final String CERTIFICATE_FILE_NAME = "cert.crt";
    public static final String ENCRYPTED_KEY_FILE_NAME = "encrypted.key";
    public static final String NON_ENCRYPTED_KEY_FILE_NAME = "passwordless.key";
    public static final String CERTIFICATE_PATH;
    public static final String ENCRYPTED_KEY_PATH;
    public static final String NON_ENCRYPTED_KEY_PATH;
    public static final String SUCCESS = "success";

    static {
        try {
            CERTIFICATE_PATH = Path.of(ClassLoader.getSystemResource(CERTIFICATE_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            ENCRYPTED_KEY_PATH = Path.of(ClassLoader.getSystemResource(ENCRYPTED_KEY_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            NON_ENCRYPTED_KEY_PATH = Path.of(ClassLoader.getSystemResource(NON_ENCRYPTED_KEY_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static final Supplier<InputStream> CERTIFICATE_INPUT_STREAM_SUPPLIER = () -> new ByteArrayInputStream(CERTIFICATE_AS_STRING.getBytes(StandardCharsets.UTF_8));
    public static final Supplier<InputStream> ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER = () -> new ByteArrayInputStream(ENCRYPTED_KEY_AS_STRING.getBytes(StandardCharsets.UTF_8));
    public static final Supplier<InputStream> NON_ENCRYPTED_KEY_INPUT_STREAM_SUPPLIER = () -> new ByteArrayInputStream(NON_ENCRYPTED_KEY_AS_STRING.getBytes(StandardCharsets.UTF_8));
    public static final String KEY_PASSWORD = "password";


    public static final String JKS_KEY_STORE_NAME = "keystore.jks";
    public static final String P12_KEY_STORE_NAME = "keystore.p12";

    public static final String JKS_KEY_STORE_PATH;
    public static final String P12_KEY_STORE_PATH;

    static {
        try {
            JKS_KEY_STORE_PATH = Path.of(ClassLoader.getSystemResource(JKS_KEY_STORE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            P12_KEY_STORE_PATH = Path.of(ClassLoader.getSystemResource(P12_KEY_STORE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static final Supplier<InputStream> JKS_KEY_STORE_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return ClassLoader.getSystemResource(JKS_KEY_STORE_NAME).openStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    };

    public static final Supplier<InputStream> P12_KEY_STORE_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return ClassLoader.getSystemResource(P12_KEY_STORE_NAME).openStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    };

    public static final String KEY_STORE_PASSWORD = "password";

    public static final Function<Integer, String> HTTPS_URL_WITH_PORT = (Integer port) -> String.format("https://localhost:%s/", port);
    public static final Function<Integer, String> HTTP_URL_WITH_PORT = (Integer port) -> String.format("http://localhost:%s/", port);
    protected static final AtomicInteger ports = new AtomicInteger(10000);
    @Getter
    private static final OkHttpClient client = createHttpsClient();

    @Getter
    private static final OkHttpClient untrustedClient = untrustedHttpsClient();

    private static OkHttpClient createHttpsClient() {
        HandshakeCertificates.Builder builder = new HandshakeCertificates.Builder();
        builder.addTrustedCertificate(Certificates.decodeCertificatePem(CERTIFICATE_AS_STRING));
        try {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(P12_KEY_STORE_INPUT_STREAM_SUPPLIER.get(), KEY_STORE_PASSWORD.toCharArray());
            for (String alias : Collections.list(ks.aliases())) {
                builder.addTrustedCertificate((X509Certificate) ks.getCertificate(alias));
            }
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
        HandshakeCertificates clientCertificates = builder.build();
        return new OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager()).hostnameVerifier((hostname, session) -> true).build();
    }

    private static OkHttpClient untrustedHttpsClient() {
        OkHttpClient.Builder newBuilder = untrustedClientBuilder();

        return newBuilder.build();
    }

    @NotNull
    protected static OkHttpClient.Builder untrustedClientBuilder() {
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[]{};
            }
        }};

        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }

        OkHttpClient.Builder newBuilder = new OkHttpClient.Builder();
        newBuilder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
        newBuilder.hostnameVerifier((hostname, session) -> true);
        return newBuilder;
    }

    public static Javalin createTestApp(Consumer<SSLConfig> config) {
        return Javalin.create((javalinConfig) -> {
            javalinConfig.showJavalinBanner = false;
            javalinConfig.plugins.register(new SSLPlugin(config));
        }).get("/", ctx -> ctx.result(SUCCESS));
    }

    void assertWorks(Protocol protocol, Consumer<SSLConfig> config) {

        int insecurePort = ports.getAndIncrement();
        int securePort = ports.getAndIncrement();
        String http = HTTP_URL_WITH_PORT.apply(insecurePort);
        String https = HTTPS_URL_WITH_PORT.apply(securePort);
        String url = protocol == Protocol.HTTP ? http : https;
        config = config.andThen(sslConfig -> {
            sslConfig.insecurePort = insecurePort;
            sslConfig.securePort = securePort;
        });
        try (Javalin app = IntegrationTestClass.createTestApp(config)) {
            app.start();
            Response response = client.newCall(new Request.Builder().url(url).build()).execute();
            assertEquals(200, response.code());
            assertEquals(SUCCESS, Objects.requireNonNull(response.body()).string());
            response.close();
        } catch (IOException e) {
            fail(e);
        }
    }

    void assertSslWorks(Consumer<SSLConfig> config) {
        assertWorks(Protocol.HTTPS, config);
    }

    void assertHttpWorks(Consumer<SSLConfig> config) {
        assertWorks(Protocol.HTTP, config);
    }

    private enum Protocol {
        HTTP, HTTPS
    }
}
