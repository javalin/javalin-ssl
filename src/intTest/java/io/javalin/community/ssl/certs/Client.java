package io.javalin.community.ssl.certs;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.function.Supplier;

public class Client {

    public static final String SERVER_CERTIFICATE_AS_STRING = "-----BEGIN CERTIFICATE-----\n" + "MIIDpjCCAo6gAwIBAgIUKK29nJVFCs8SjBqcvxrg7boyem8wDQYJKoZIhvcNAQEL\n" + "BQAwQjESMBAGA1UEAwwJbG9jYWxob3N0MQswCQYDVQQGEwJFUzEQMA4GA1UECAwH\n" + "R2FsaWNpYTENMAsGA1UEBwwEVmlnbzAgFw0yMjA3MDYxMTQyMDdaGA80MDA1MDMx\n" + "MjExNDIwN1owQjESMBAGA1UEAwwJbG9jYWxob3N0MQswCQYDVQQGEwJFUzEQMA4G\n" + "A1UECAwHR2FsaWNpYTENMAsGA1UEBwwEVmlnbzCCASIwDQYJKoZIhvcNAQEBBQAD\n" + "ggEPADCCAQoCggEBALtW247iPVAuCcQByuqgj8tSzJcwVqCmheT6ld0Xe7DYoLOL\n" + "EsjilB/jgG9aBEBfYJ2h74K7SIdqiSDz4rgUuJUzhZnJo5d3n3wT9Wb2AZcsqFce\n" + "JK0UNBKe2/1b01dFWtQFW4zHC/JM/Gp0dMTy1Vt1Zf/3SmQjSD/KzgJf4m2O/GOP\n" + "3iRFsCSPC4CU3TZCDmI5/qRr4icJCY5s3gJ+RT+edfsvtdkfAO4hK/p+37RrwHax\n" + "nyFLoAzYdJMcnDX/+V7Ez2y7jkTkcUk2gKG+3dpio2XqAE9pXcXa4kYk0NL9Vw6L\n" + "C2QMefFKHLDqLWx/bfQXpbULFawldETDbuLVe7UCAwEAAaOBkTCBjjAdBgNVHQ4E\n" + "FgQUiiPTBoFstcGbb0zYWsM/ZwupRRYwHwYDVR0jBBgwFoAUiiPTBoFstcGbb0zY\n" + "WsM/ZwupRRYwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\n" + "BgEFBQcDAjAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcN\n" + "AQELBQADggEBAGvqUrtYWZpKBJNYL4UVLnm2+dQl33l8BH7PhU6YvMufThDCVjOw\n" + "IJ7ezOReDlCAmytQD7ChKpsJrAOBzKRdrifL0f88psbE83+6Ys/s/1rHMq282p/S\n" + "WPRiZDVO8Mw2ra9v9b6cprW5phHJkp7TiIBP82A+v19lt3R+vE4HZ91ZyioNqMzf\n" + "Aqvd5gfxHexpilgil0osF0o/8ajSnLiBfWI82Lz/1JB+xUMYW91ahRgt13/54h13\n" + "eL70steoAmx55he3pQaaeRZKzI1nLxsrTkjs055jDn0G/yj1L6kY3OeVFg3AhETJ\n" + "sg+yATMTef2Qskr4dgzb1LJkC9meaU2TFwk=\n" + "-----END CERTIFICATE-----\n";
    public static final String SERVER_PRIVATE_KEY_AS_STRING = "-----BEGIN PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VtuO4j1QLgnE\n" + "AcrqoI/LUsyXMFagpoXk+pXdF3uw2KCzixLI4pQf44BvWgRAX2Cdoe+Cu0iHaokg\n" + "8+K4FLiVM4WZyaOXd598E/Vm9gGXLKhXHiStFDQSntv9W9NXRVrUBVuMxwvyTPxq\n" + "dHTE8tVbdWX/90pkI0g/ys4CX+Jtjvxjj94kRbAkjwuAlN02Qg5iOf6ka+InCQmO\n" + "bN4CfkU/nnX7L7XZHwDuISv6ft+0a8B2sZ8hS6AM2HSTHJw1//lexM9su45E5HFJ\n" + "NoChvt3aYqNl6gBPaV3F2uJGJNDS/VcOiwtkDHnxShyw6i1sf230F6W1CxWsJXRE\n" + "w27i1Xu1AgMBAAECggEAfPI7UZr3BckO3lnLup0ICrXYmmW1AUTPPJ8c4O7Oom55\n" + "EAaLqsvjuzkC6kGBYGW8jKX6lpjOkPKvLvk6l0fKrEhGrQFdSKKSDjFJlTgya19v\n" + "j1sdXwqAiILHer2JwUUShSJlowkGoL5UA7RURR8oye0M8KFATnVxtIpQyCinXiW/\n" + "LkDuqUr8MIbu6V/KcoSOLfJyTWyuwSRPHuFKhv154UAqaTkSPbf2mCTa9hH5Tb4f\n" + "Lfzy9o3Ux4ieZceG28De+SmC7uMzbBs1stowOuDmFg3znI/1Br/sQEAXPFngDe3s\n" + "soDD2PbLo7/4SPBNgl5vygf7jhvxHPY3DTUXOxLSgQKBgQD4EzKVTx/GpF7Yswma\n" + "oixidzSi/KnHJiMjIERF4QPVfDNnggRORNMbPnRhNWSRhS7r+INYbN4yB/vBZO5I\n" + "IIqowdJbLjGbmq91equP0zzrP2wCjqtFK6gRElX7acAWY5xTesIT5Fa1Ug++dFLS\n" + "MxCZKL6JMZaHJzZVzXugaltMsQKBgQDBUvPSaDnIBrZGdNtAyNMxZyVbp/ObIKW1\n" + "TvCDX2hqf+yiTVclbZr5QkwCE3MHErfsKlWU01K9CtzsQh4u9L5tPaeFlvm6iZq6\n" + "ktbflNvI+z+qEW3JbROR4WwwbmWFvKRLBA0OQom7tGuNnNyRtkDFxlkFJPcD6Eff\n" + "ZEq+ewrQRQKBgQCV7URM6J0TuJN58/qB8jFQ8Spmtr0FFw91UzLv6KYgiAepLvLb\n" + "Os07UeuUNGiragqJoo//CQzgv+JvZ0h7Xu9uPnWblbd1i28vWQwGyGuw4Yutn/vy\n" + "ugfBCYvdfnQRE/KOoUpaK04cF5RcToEfeK03Y2CEGewXkqNMB/wHXz/+gQKBgE8Y\n" + "34WQ+0Mp69375dEl2bL23sQXfYZU3zfFaoZ1vMUGPg1R03wO0j91rp+S0ZdtQy8v\n" + "SwCvTcTm8uj/TFYt8NPFTAtOcDKwJkx708p6n0ol8jBlHSQyqrUfJCLUqFkFi7rd\n" + "l3HkK3JPKUoxidVcWjgRJU8DhsVkfjOaVzKEKTJ5AoGARBwn7gt2H35urQ6/U3nJ\n" + "hFjOVn01F5uV0NvRtRDCsAIUMeA2T4pwALUUIqlA9HmpwYgLeG4bZ+SkhNpy70N/\n" + "qcufT1DeM+q3H5zFPANyjcqVaqa6KUnttvi/lhxMdRb6GsA9TzzHzY1P9ovpIOCK\n" + "IS639NPzxpI0Ka+v6t+nFEM=\n" + "-----END PRIVATE KEY-----\n";

    public static final String CLIENT_CERTIFICATE_AS_STRING = "-----BEGIN CERTIFICATE-----\n" + "MIIDmDCCAoCgAwIBAgIUdWY83fnUuYRDmDnHi34wkeG+yA4wDQYJKoZIhvcNAQEL\n" + "BQAwUjEPMA0GA1UEAwwGY2xpZW50MQswCQYDVQQGEwJFUzEPMA0GA1UECAwGTWFk\n" + "cmlkMQ8wDQYDVQQHDAZNYWRyaWQxEDAOBgNVBAoMB0phdmFsaW4wIBcNMjMwMTEw\n" + "MTEwNTE0WhgPMjEyMjEyMTcxMTA1MTRaMFIxDzANBgNVBAMMBmNsaWVudDELMAkG\n" + "A1UEBhMCRVMxDzANBgNVBAgMBk1hZHJpZDEPMA0GA1UEBwwGTWFkcmlkMRAwDgYD\n" + "VQQKDAdKYXZhbGluMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCUt\n" + "UOTWxQ3zbVXK8FPFh4DsDCphoUt/k6v8n4miZWxfw45VqsSk5JktmFhqSsmerh0N\n" + "cQZ7rji69LK/dr4wfZJjWLGlyNDJnT1W/PP3HaGErJxDl/NqLjl+xULXsp7+/SP7\n" + "Jz6QcEKmDYOyQND79MaYXlhkCLtt/RslfIP1YQ4AFCGcw4z/cGERuMtcLY8FFT+N\n" + "U4OD26AZX4fAQ+fQRAdALzp63wCnWiYyQ+0Nqeq4wDM+HYlAsUbwSwiJSseIVn2u\n" + "nn1kQq45TUcL8HUuVGr9CF8PyvkOLxbdzC0q43MfPDck7CgqR2YG9XHrca9cT6c+\n" + "zE+BGhjzOjlAxUCYqwIDAQABo2QwYjAdBgNVHQ4EFgQU3MAhBUHI6S9obysrX38v\n" + "HiGLmIcwHwYDVR0jBBgwFoAU3MAhBUHI6S9obysrX38vHiGLmIcwCwYDVR0PBAQD\n" + "AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBVjsXw\n" + "P4ZbUt5XqN8Iy30YqBi90OtfcmWxVnuc7O/HU2ue+PLM3rRyKYVgwY6G/HoRAibq\n" + "HsLnGa/2jT+qzri68CKfjE/wmBIAgzaKF4XmhOxIxQjTUuxbVd4BmrDmGqsMgWoQ\n" + "5XnYvyBQJ9LTnvvxPk4UvhUjm1/6RbPFqqxVenTUpYS4U3JTv1c9ddu9VSA8ebT4\n" + "BGBVq2iwgTm38xN9C6eS/xGCdLXGIaEQvmfgAPi1Nmw32KrLJfL3oz9bWdYhp9Hg\n" + "fZg2Pug5bLDqy8ktyTDdM+q4d+wd3XpKzuLvCIr2q03vrT9j+dMIEOTaqxWQAYiH\n" + "CYGXrU6Ry61UJSer\n" + "-----END CERTIFICATE-----\n";
    public static final String CLIENT_PRIVATE_KEY_AS_STRING = "-----BEGIN PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwJS1Q5NbFDfNt\n" + "VcrwU8WHgOwMKmGhS3+Tq/yfiaJlbF/DjlWqxKTkmS2YWGpKyZ6uHQ1xBnuuOLr0\n" + "sr92vjB9kmNYsaXI0MmdPVb88/cdoYSsnEOX82ouOX7FQteynv79I/snPpBwQqYN\n" + "g7JA0Pv0xpheWGQIu239GyV8g/VhDgAUIZzDjP9wYRG4y1wtjwUVP41Tg4PboBlf\n" + "h8BD59BEB0AvOnrfAKdaJjJD7Q2p6rjAMz4diUCxRvBLCIlKx4hWfa6efWRCrjlN\n" + "RwvwdS5Uav0IXw/K+Q4vFt3MLSrjcx88NyTsKCpHZgb1cetxr1xPpz7MT4EaGPM6\n" + "OUDFQJirAgMBAAECggEADdQNV7Fvbu7mcmnu0akx865aWaYmHfyIWnaBEaFDf4Tf\n" + "i8Gr1gk0DMI9wx0F0zM64t5jBMGGiinn+3fg8hiCRAlvBTKFGlvRyCddoeQhPVFF\n" + "0is+Xzp71n8rBZ92wY4b5JGjkPQncLi6worZPp9peFDy+00jJVBZlSpBaiIN7H2E\n" + "iZQYUMI07u6xJW/EUE6X9g3AhgV9QMxfJawn8AWHXR8+9iNsOb9hlVUWBPwR7xb5\n" + "4KqB/89UFp/40tEDeKz9/MMsH5FjNCNPCaLADJS2Xy1Q1icV6V42HsaZm9vZUL+J\n" + "dru6OwEo6iJhWKjkBaWvVl4HuOPrrUP9sLSN6g6PCQKBgQDXih7xgHF35yDPvnNx\n" + "fqqxfRO+PMHq1se2tOhAdeDmdStUyl/u1NwJ9BE9Fb/lbdulYFfZJtef2TmeX31x\n" + "DaQWXrg4Pai2pnCcSfItogWJSFrg6dphbABwVslTvWw2ikB6hN2jmUaReM0atW2S\n" + "YUVWD0JFMsf4IimgAcGPgebprQKBgQDRNfB2k6NhqgKBXKrshT/3No/kMnhkNl9H\n" + "i/UmiCUYvw5E/L4q2wrsehnERAPpod3EoHjkYCmY/BK4oRCtkz6t1nnWX1zGabY3\n" + "Nn4Ie+BMCYp2NLa7yGZ0sk1rrtlgZBoaR1ZF0+HADPpffELPD6HzvUQuPyN+wlA0\n" + "SWwq8DuGtwKBgBxyxIbHlzJmNTR2RLJ0L39hrNttFYMzegSpeAYaCOciC+gTFfpl\n" + "6ez+Y9AWMM/NYjI/txiYQdl9SFeY7uufC0tQkSwLJ1uEOFTIhch0HBr0i9onw4Uc\n" + "RiqNqeD9nWzNbpk9NCvFrUTCFwAxdhbd89LaDLspaq9bgvb1hGC2mo25AoGBAKVP\n" + "ks+Pf3Unik0/tQupis7DvVVakAjXcdgt/itRPsbcCOF4OKfSZ0JOhNexysmsjnjV\n" + "OFF0rsnkvMJI+s284LUqGSHMPpnFZCciltoLUEOk8lTO+GlPQ64ISebBxaBF2N5U\n" + "6hXJA8PmPVx/6qaEurrHHf3RBDIgRpHaRm9zXgXnAoGASlEFHkUKwf8G3AePstzk\n" + "sHoxJiKMTq2qFb/NTVE4z4+pc03uhxno79+R4aV4JD0dK1gyRaX5/TCwdvI5smS3\n" + "Vfl5JN+HiO0zClecR8N83arOLka2prJ3ZjjCy2JgZKRXZQ/vcsTKnvh3DIFyR/NZ\n" + "OKM5x3IGChzxEZLumfedQX4=\n" + "-----END PRIVATE KEY-----\n";

    public static final String WRONG_CLIENT_CERTIFICATE_AS_STRING = "-----BEGIN CERTIFICATE-----\n" + "MIIDmDCCAoCgAwIBAgIUD0yMp2hSck6P1TtqpbVvf1QlJMswDQYJKoZIhvcNAQEL\n" + "BQAwUjEPMA0GA1UEAwwGY2xpZW50MQswCQYDVQQGEwJFUzEPMA0GA1UECAwGTWFk\n" + "cmlkMQ8wDQYDVQQHDAZNYWRyaWQxEDAOBgNVBAoMB0phdmFsaW4wIBcNMjMwMTEw\n" + "MTE0MzM0WhgPMjEyMjEyMTcxMTQzMzRaMFIxDzANBgNVBAMMBmNsaWVudDELMAkG\n" + "A1UEBhMCRVMxDzANBgNVBAgMBk1hZHJpZDEPMA0GA1UEBwwGTWFkcmlkMRAwDgYD\n" + "VQQKDAdKYXZhbGluMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvt3f\n" + "vHU1vVoZFu5pV53IXjSP7FoRi6mB27RASyOTXZGCdKTmRZxlgUF7yrMjse99zkys\n" + "GR4csPE62vxDB5SHiaLdCVDWFUNmvENJ+Om6v4SnUrVju/1OUDthsTBXe6t7N0Ou\n" + "ihPxN5tZKumdDaB56djIXkEfmPFFc/7vRC9cqYISWvKtFT2bkBwzNkcUzTlR05WL\n" + "8m5napdl8SQ3/Gza+iVjDtkBDvKs4nlG+QmhT0U4+5B1vah1doKfv+Sn2CAfoTs0\n" + "aIMuHAcdApLR4IVEIADPhNb9pePurXChFHGq7kY90g+wh69rNVsi4uq8HwPSTaQe\n" + "YhsTebk71irMquoSMwIDAQABo2QwYjAdBgNVHQ4EFgQUeZ640SK+L1/GPQIis8mz\n" + "bHOOQvYwHwYDVR0jBBgwFoAUeZ640SK+L1/GPQIis8mzbHOOQvYwCwYDVR0PBAQD\n" + "AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBNinqE\n" + "9Xltwk+khvbRmkF/AIbXMIIFpgGjUWmlg42aUmba+OdQKjHbChiSZHpsue6o/Abj\n" + "AgPpb4xH9AacQVM2yFTh/o9UeRwAJtjHrSzIgkBTy2YOM6TFXi2M6a6fBWuEuYQC\n" + "jB0std0HNK0ln2MqFKJn3IMk6oiX3XslTXbcTOP8S/T2fj4bc3C4kBZWjUj3qreD\n" + "QqzvaWOpVUt7a/slICZ5fVII0vn7EnaNvjsZq9ilBs9MuBH92LNJ0nIO9rhw94TQ\n" + "xYyJ1RUBugQrcnpx6xMW3cIUuv/IXu14X+5wEOw21udKaafen5WYVqEkVBW12bgP\n" + "0I8c8C6x8S6P4eDO\n" + "-----END CERTIFICATE-----\n";
    public static final String WRONG_CLIENT_PRIVATE_KEY_AS_STRING = "-----BEGIN PRIVATE KEY-----\n" + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+3d+8dTW9WhkW\n" + "7mlXncheNI/sWhGLqYHbtEBLI5NdkYJ0pOZFnGWBQXvKsyOx733OTKwZHhyw8Tra\n" + "/EMHlIeJot0JUNYVQ2a8Q0n46bq/hKdStWO7/U5QO2GxMFd7q3s3Q66KE/E3m1kq\n" + "6Z0NoHnp2MheQR+Y8UVz/u9EL1ypghJa8q0VPZuQHDM2RxTNOVHTlYvybmdql2Xx\n" + "JDf8bNr6JWMO2QEO8qzieUb5CaFPRTj7kHW9qHV2gp+/5KfYIB+hOzRogy4cBx0C\n" + "ktHghUQgAM+E1v2l4+6tcKEUcaruRj3SD7CHr2s1WyLi6rwfA9JNpB5iGxN5uTvW\n" + "Ksyq6hIzAgMBAAECggEBAKXa/ZGxNHqPMWAo2idFt5iNCkey2K5JJMu67WedyW+0\n" + "gu1DYco5pkbUlXLFig4T83lyTNYiwYHMjX0/WivbGJA0kuiGcxHVGRAdVMlUqW/F\n" + "IPURJFJ2Qjgb8b9cJ5kSoSabzK61t5W/i5Nrn4r42ReoxiyJYKCxf83VSSsyEM5F\n" + "9C+qcjux8+tkF7NlBWXwl2/qqcbuqDuhsTFNmq5Fngx6Xwv7hk1gU0Ibglyo7KmO\n" + "75EGcN3T2QWMPMc9C027h3260ROlNOWMNexJZ4vtrWR8GNFi0wOnjaHUW2eilrrg\n" + "XGhuzzYFO2ikAPXsJo/+fqfhrqms8ujRlExYqECMkDkCgYEA8xbkZ5UvnXT9uthL\n" + "/nJe2Ax1rYOOK7VLsYHciNxkoDmJwRufIK7MUw2qGVKpBB5jAjXBDiYf5cVlyLDJ\n" + "tB/5Qh7PkTWTTOMlcY9QsV+nYklf4IYvaURoSKqreotx0PsGQq0R6kpVy2MWn3xs\n" + "R4aWmMoCTzVMLVgE2Ibtuv14tIUCgYEAyQDyo7865bssHzFRN52Mq5Ls2WMC0H/q\n" + "Owk2NzJoSqNecyzpOvt3hM71IAdOo/xQQdJ7dNMh/B/etbKW3sJNhyVCb1XPVhKk\n" + "+ixd4slensXlJvHoXiugmkbIhoEYx8c+2fhxQSP7PXdCanFtCL/M4Ey9MkaUymyK\n" + "E/7kAafPpVcCgYEAiWg2QYrluFZqGhSrmC+kBvG8DxGe6nv3RmZGd6JEywDbKinn\n" + "3/yOiJ/ft6Ku4SIgCx7BerL4MtRK/Y9Y5JVyOvrZj5Y+Jib7gl5lWW3dWsRpCqwu\n" + "3o0JeZHnjkSGWH+cgVH9H3dXWbkwD4SwXBnqxIDjn0xcPAFV8+MJPDqM4VUCgYBz\n" + "cV/qPAKPvxhwMdr7njkUsaXmlL8hENZuYbQJr6HGfF3auIibn6HdXR/b7VZ1SIyv\n" + "wTu2tSxnqcY3hQKxndb5L6UgXKBgRwUJykGB5zW46t/ZpkZXD6eF8/Fnju20j/LB\n" + "LbeeOhQqETzL9akxxTbd/DUNkwwR1pTXNyWs7byMsQKBgGW6QkazJ5iFHZrwKlgS\n" + "lJG//bnbUU1ZPITh25RihWa78l5tnUAK4iJwBmOPwjtSC+4qG35xCt1TSBHPR/yy\n" + "hMlv7rBUPwS1UHzvVifQwE5D2NHyselZYdhxyqqJ2hlq4ykjZZJ+vc01FRl2Wfd/\n" + "SQO2OwXQkrajbcSXGpQg/aQs\n" + "-----END PRIVATE KEY-----\n";

    public static final String CLIENT_P7B_CERTIFICATE_AS_STRING = "-----BEGIN PKCS7-----\n" + "MIIDyQYJKoZIhvcNAQcCoIIDujCCA7YCAQExADALBgkqhkiG9w0BBwGgggOcMIID\n" + "mDCCAoCgAwIBAgIUdWY83fnUuYRDmDnHi34wkeG+yA4wDQYJKoZIhvcNAQELBQAw\n" + "UjEPMA0GA1UEAwwGY2xpZW50MQswCQYDVQQGEwJFUzEPMA0GA1UECAwGTWFkcmlk\n" + "MQ8wDQYDVQQHDAZNYWRyaWQxEDAOBgNVBAoMB0phdmFsaW4wIBcNMjMwMTEwMTEw\n" + "NTE0WhgPMjEyMjEyMTcxMTA1MTRaMFIxDzANBgNVBAMMBmNsaWVudDELMAkGA1UE\n" + "BhMCRVMxDzANBgNVBAgMBk1hZHJpZDEPMA0GA1UEBwwGTWFkcmlkMRAwDgYDVQQK\n" + "DAdKYXZhbGluMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCUtUOTW\n" + "xQ3zbVXK8FPFh4DsDCphoUt/k6v8n4miZWxfw45VqsSk5JktmFhqSsmerh0NcQZ7\n" + "rji69LK/dr4wfZJjWLGlyNDJnT1W/PP3HaGErJxDl/NqLjl+xULXsp7+/SP7Jz6Q\n" + "cEKmDYOyQND79MaYXlhkCLtt/RslfIP1YQ4AFCGcw4z/cGERuMtcLY8FFT+NU4OD\n" + "26AZX4fAQ+fQRAdALzp63wCnWiYyQ+0Nqeq4wDM+HYlAsUbwSwiJSseIVn2unn1k\n" + "Qq45TUcL8HUuVGr9CF8PyvkOLxbdzC0q43MfPDck7CgqR2YG9XHrca9cT6c+zE+B\n" + "GhjzOjlAxUCYqwIDAQABo2QwYjAdBgNVHQ4EFgQU3MAhBUHI6S9obysrX38vHiGL\n" + "mIcwHwYDVR0jBBgwFoAU3MAhBUHI6S9obysrX38vHiGLmIcwCwYDVR0PBAQDAgeA\n" + "MBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBVjsXwP4Zb\n" + "Ut5XqN8Iy30YqBi90OtfcmWxVnuc7O/HU2ue+PLM3rRyKYVgwY6G/HoRAibqHsLn\n" + "Ga/2jT+qzri68CKfjE/wmBIAgzaKF4XmhOxIxQjTUuxbVd4BmrDmGqsMgWoQ5XnY\n" + "vyBQJ9LTnvvxPk4UvhUjm1/6RbPFqqxVenTUpYS4U3JTv1c9ddu9VSA8ebT4BGBV\n" + "q2iwgTm38xN9C6eS/xGCdLXGIaEQvmfgAPi1Nmw32KrLJfL3oz9bWdYhp9HgfZg2\n" + "Pug5bLDqy8ktyTDdM+q4d+wd3XpKzuLvCIr2q03vrT9j+dMIEOTaqxWQAYiHCYGX\n" + "rU6Ry61UJSeroQAxAA==\n" + "-----END PKCS7-----\n";

    public static final String KEYSTORE_PASSWORD = "password";

    public static final String CLIENT_PEM_FILE_NAME = "client/cert.pem";
    public static final String CLIENT_P7B_FILE_NAME = "client/cert.p7b";
    public static final String CLIENT_DER_FILE_NAME = "client/cert.der";
    public static final String CLIENT_P12_FILE_NAME = "client/cert.p12";
    public static final String CLIENT_JKS_FILE_NAME = "client/cert.jks";

    public static final String CLIENT_PEM_PATH;
    public static final String CLIENT_P7B_PATH;
    public static final String CLIENT_DER_PATH;
    public static final String CLIENT_P12_PATH;
    public static final String CLIENT_JKS_PATH;


    static {
        try {
            CLIENT_PEM_PATH = Path.of(ClassLoader.getSystemResource(Client.CLIENT_PEM_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            CLIENT_P7B_PATH = Path.of(ClassLoader.getSystemResource(Client.CLIENT_P7B_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            CLIENT_DER_PATH = Path.of(ClassLoader.getSystemResource(Client.CLIENT_DER_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            CLIENT_P12_PATH = Path.of(ClassLoader.getSystemResource(Client.CLIENT_P12_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            CLIENT_JKS_PATH = Path.of(ClassLoader.getSystemResource(Client.CLIENT_JKS_FILE_NAME).toURI()).toAbsolutePath().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static final Supplier<InputStream> CLIENT_PEM_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return new FileInputStream(CLIENT_PEM_PATH);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    };
    public static final Supplier<InputStream> CLIENT_P7B_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return new FileInputStream(CLIENT_P7B_PATH);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    };

    public static final Supplier<InputStream> CLIENT_DER_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return new FileInputStream(CLIENT_DER_PATH);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    };

    public static final Supplier<InputStream> CLIENT_P12_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return new FileInputStream(CLIENT_P12_PATH);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    };
    public static final Supplier<InputStream> CLIENT_JKS_INPUT_STREAM_SUPPLIER = () -> {
        try {
            return new FileInputStream(CLIENT_JKS_PATH);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    };
}
