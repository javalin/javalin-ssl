package io.javalin.community.ssl

/**
 * Exception thrown when the SSLConfig is invalid.
 */
class SSLConfigException : RuntimeException {
    constructor(message: String?) : super(message)
    constructor(type: Types) : super(type.message)
    constructor(type: Types, extraInformation: String) : super(type.message + ": " + extraInformation)

    /**
     * Types of errors that can occur when configuring SSL.
     */
    enum class Types(val message: String) {
        INVALID_HOST("Invalid host provided"),
        INVALID_SSL_PORT("Invalid SSL port provided"),
        INVALID_INSECURE_PORT("Invalid insecure port provided"),
        INVALID_HTTP3_PORT("Invalid HTTP3 port provided"),
        MISSING_CERT_AND_KEY_FILE("There is no certificate or key file provided"),
        MULTIPLE_IDENTITY_LOADING_OPTIONS("Both the certificate and key must be provided using the same method")

    }
}
