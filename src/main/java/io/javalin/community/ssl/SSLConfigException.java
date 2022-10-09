package io.javalin.community.ssl;

/**
 * Exception thrown when the SSLConfig is invalid.
 */
public class SSLConfigException extends RuntimeException {
    public SSLConfigException(String message) {
        super(message);
    }

    public SSLConfigException(Types type) {
        super(type.getMessage());
    }
    public SSLConfigException(Types type, String extraInformation) {
        super(type.getMessage() + ": " + extraInformation);
    }

    public enum Types {
        INVALID_HOST("Invalid host provided"),
        INVALID_SSL_PORT("Invalid SSL port provided"),
        INVALID_INSECURE_PORT("Invalid insecure port provided"),
        INVALID_HTTP3_PORT("Invalid HTTP3 port provided"),
        MISSING_CERT_AND_KEY_FILE("There is no certificate or key file provided"),
        MULTIPLE_IDENTITY_LOADING_OPTIONS("Both the certificate and key must be provided using the same method");

        private final String message;

        Types(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }
}
