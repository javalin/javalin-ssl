# About Javalin [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Chat at https://discord.gg/sgak4e5NKv](https://img.shields.io/badge/chat-on%20Discord-%234cb697)](https://discord.gg/sgak4e5NKv)

* [:heart: Sponsor Javalin](https://github.com/sponsors/tipsy)
* The main project webpage is [javalin.io](https://javalin.io)
* Chat on Discord: https://discord.gg/sgak4e5NKv
* License summary: https://tldrlegal.com/license/apache-license-2.0-(apache-2.0)

# SSL Plugin [![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/javalin/javalin-ssl/Test%20all%20JDKs%20on%20all%20OSes%20and%20Publish/main?label=main&logo=githubactions&logoColor=white)](https://github.com/javalin/javalin-ssl/actions?query=branch%3Amain) [![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/javalin/javalin-ssl/Test%20all%20JDKs%20on%20all%20OSes%20and%20Publish/dev?label=dev&logo=githubactions&logoColor=white)](https://github.com/javalin/javalin-ssl/actions?query=branch%3Adev) [![Coverage](https://codecov.io/gh/javalin/javalin-ssl/branch/dev/graphs/badge.svg)](https://app.codecov.io/gh/javalin/javalin-ssl)

Straightforward SSL and HTTP/2 Configuration for Javalin!

## Getting started

[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/javalin/javalin-ssl?label=Latest%20Release)](https://github.com/javalin/javalin-ssl/releases) ![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/javalin/javalin-ssl?include_prereleases&label=Latest%20Snapshot)

As simple as adding a dependency:
### Maven

```xml
<dependency>
  <groupId>io.javalin.community.ssl</groupId>
  <artifactId>ssl-plugin</artifactId>
  <version>5.0.0</version>
</dependency>
```
### Gradle

```kotlin
implementation('io.javalin.community.ssl:ssl-plugin:5.0.0')
```


## Configuration

You can pass a config object when registering the plugin

### Java

```java
Javalin.create(config->{
    ...  // your Javalin config here
    config.plugins.register(new SSLPlugin(ssl->{
        ... // your SSL configuration here
        ssl.loadPemFromPath("/path/to/cert.pem","/path/to/key.pem");
    }));
});
```

### Kotlin

```kotlin
Javalin.create { config ->
    ... // your Javalin config here
    config.plugins.register(SSLPlugin { ssl ->
        ... // your SSL configuration here
        ssl.loadPemFromPath("/path/to/cert.pem", "/path/to/key.pem")
    })
}
```

### Available config options

```java
// Connection options
host=null;                                                            // Host to bind to, by default it will bind to all interfaces.
insecure=true;                                                        // Toggle the default http (insecure) connector.
secure=true;                                                          // Toggle the default https (secure) connector.
http2=true;                                                           // Toggle HTTP/2 Support

securePort=443;                                                       // Port to use on the SSL (secure) connector.
insecurePort=80;                                                      // Port to use on the http (insecure) connector.

sniHostCheck=true;                                                    // Enable SNI hostname verification.
tlsConfig=TLSConfig.INTERMEDIATE;                                     // Set the TLS configuration. (by default it uses Mozilla's intermediate configuration)


// PEM loading options (mutually exclusive)
pemFromPath("/path/to/cert.pem","/path/to/key.pem");                   // load from the given paths.
pemFromPath("/path/to/cert.pem","/path/to/key.pem","keyPassword");    // load from the given paths with the given key password.
pemFromClasspath("certName.pem","keyName.pem");                        // load from the given paths in the classpath.
pemFromClasspath("certName.pem","keyName.pem","keyPassword");         // load from the given paths in the classpath with the given key password.
pemFromInputStream(certInputStream,keyInputStream);                    // load from the given input streams.
pemFromInputStream(certInputStream,keyInputStream,"keyPassword");     // load from the given input streams with the given key password.
pemFromString(certString,keyString);                                   // load from the given strings.
pemFromString(certString,keyString,"keyPassword");                    // load from the given strings with the given key password.

// Keystore loading options (PKCS#12/JKS) (mutually exclusive)
keystoreFromPath("/path/to/keystore.jks","keystorePassword");          // load the keystore from the given path
keystoreFromClasspath("keyStoreName.p12","keystorePassword");          // load the keystore from the given path in the classpath.
keystoreFromInputStream(keystoreInputStream,"keystorePassword");       // load the keystore from the given input stream.

```

## Notes

- HTTP/2 **can** be used over an insecure connection.
- HTTP/3 is **not** yet supported because of some issues with Jetty's implementation.
- Client-side X.509 authentication is **not** supported.
- If Jetty responds with an `HTTP ERROR 400 Invalid SNI`, you can disable SNI verification by
  setting `sniHostCheck = false`.

## Depends on

| Package                                       | Version | License                                                                                                              |
|-----------------------------------------------|---------|----------------------------------------------------------------------------------------------------------------------|
| [Javalin](https://github.com/javalin/javalin) | `5.0.0` | [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) |
 | [SSLContext Kickstart](https://github.com/Hakky54/sslcontext-kickstart) | `7.4.6` | [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) |

## Contributing

Contributions are welcome! Open an issue or pull request if you have a suggestion or bug report.

All development is carried out on the dev branch, main is only used for releases.


## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details




