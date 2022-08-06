
[![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/javalin/javalin-ssl/Test%20all%20JDKs%20on%20all%20OSes%20and%20Publish/main?label=main&logo=githubactions&logoColor=white)](https://github.com/javalin/javalin-ssl/actions?query=branch%3Amain)
[![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/javalin/javalin-ssl/Test%20all%20JDKs%20on%20all%20OSes%20and%20Publish/dev?label=dev&logo=githubactions&logoColor=white)](https://github.com/javalin/javalin-ssl/actions?query=branch%3Adev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/javalin/javalin-ssl?label=Latest%20Release)](https://github.com/javalin/javalin-ssl/releases)
![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/javalin/javalin-ssl?include_prereleases&label=Latest%20Snapshot)

# About Javalin [![Chat at https://discord.gg/sgak4e5NKv](https://img.shields.io/badge/chat-on%20Discord-%234cb697)](https://discord.gg/sgak4e5NKv)

* [:heart: Sponsor Javalin](https://github.com/sponsors/tipsy)
* The main project webpage is [javalin.io](https://javalin.io)
* Chat on Discord: https://discord.gg/sgak4e5NKv
* License summary: https://tldrlegal.com/license/apache-license-2.0-(apache-2.0)

# SSL Plugin
Straightforward SSL and HTTP/2 Configuration for Javalin!

## Getting started

<details>
  <summary>Maven</summary>

#### Add the desired repository

<!--- 
Releases:
```xml
<repository>
  <id>zugazagoitia-repo-releases</id>
  <name>Zugazagoitia Repository</name>
  <url>https://repo.zugazagoitia.com/releases</url>
</repository>
```
--->

Snapshots:
```xml
<repository>
  <id>zugazagoitia-repo-snapshots</id>
  <name>Zugazagoitia Repository</name>
  <url>https://repo.zugazagoitia.com/snapshots</url>
</repository>
```

#### And the dependency

<!--- Latest release:
```xml
<dependency>
  <groupId>io.javalin</groupId>
  <artifactId>javalin-ssl</artifactId>
  <version>1.0.0</version>
</dependency>
``` --->
Latest snapshot:
```xml
<dependency>
  <groupId>io.javalin</groupId>
  <artifactId>javalin-ssl</artifactId>
  <version>5.0.0-SNAPSHOT</version>
</dependency>
```
</details>
<br>
<details>
  <summary>Gradle</summary>

#### Add the desired repository
<!---
```groovy
maven {
    url "https://repo.zugazagoitia.com/releases" //Repo for releases
}
```
--->

```groovy
maven {
    url "https://repo.zugazagoitia.com/snapshots" //Repo for snapshots
}
```

#### And dependency
<!---
```groovy
implementation('io.javalin:javalin-ssl:1.0.0') //Latest Release
```
--->
```groovy
implementation('io.javalin:javalin-ssl:5.0.0-SNAPSHOT') //Latest snapshot
```

</details>



## Configuration

You can pass a config object when registering the plugin

<details>
  <summary>Java</summary>

```java
Javalin.create(config ->  { 
	...  // your Javalin config here
	config.plugins.register(new SSLPlugin(ssl-> {  
            ... // your SSL configuration here
            ssl.loadPemFromPath("/path/to/cert.pem", "/path/to/key.pem"); 
	}));
});
```
</details>

<br>

<details>
  <summary>Kotlin</summary>

```kotlin
Javalin.create { config ->
    ... // your Javalin config here
    config.plugins.register(SSLPlugin { ssl ->
        ... // your SSL configuration here
        ssl.loadPemFromPath("/path/to/cert.pem", "/path/to/key.pem")
    })
}
```

</details>

### Available config options

```java
// Connection options
host = null;                                                                // Host to bind to, by default it will bind to all interfaces.
disableInsecure = false;                                                    // Disable the default http (insecure) connector.
disableSecure = false;                                                      // Disable the default https (secure) connector.
sslPort = 443;                                                              // Port to use on the SSL (secure) connector.
insecurePort = 80;                                                          // Port to use on the http (insecure) connector.
disableHttp2 = false;                                                       // Disables HTTP/2 Support

// PEM loading options (mutually exclusive)
pemFromPath("/path/to/cert.pem", "/path/to/key.pem");                   // Loads the cert and keys from the given paths.
pemFromPath("/path/to/cert.pem", "/path/to/key.pem", "keyPassword");    // Loads the cert and keys from the given paths with the given key password.
pemFromClasspath("certName.pem", "keyName.pem");                        // Loads the cert and keys from the given paths in the classpath.
pemFromClasspath("certName.pem", "keyName.pem", "keyPassword");         // Loads the cert and keys from the given paths in the classpath with the given key password.
pemFromInputStream(certInputStream, keyInputStream);                    // Loads the cert and keys from the given input streams.
pemFromInputStream(certInputStream, keyInputStream, "keyPassword");     // Loads the cert and keys from the given input streams with the given key password.
pemFromString(certString, keyString);                                   // Loads the cert and keys from the given strings.
pemFromString(certString, keyString, "keyPassword");                    // Loads the cert and keys from the given strings with the given key password.

// Keystore loading options (PKCS#12/JKS) (mutually exclusive)
keystoreFromPath("/path/to/keystore.jks", "keystorePassword");          // Loads the keystore from the given path
keystoreFromClasspath("keyStoreName.p12", "keystorePassword");          // Loads the keystore from the given path in the classpath.
keystoreFromInputStream(keystoreInputStream, "keystorePassword");       // Loads the keystore from the given input stream.

```

### Notes

- HTTP/2 **can** be used over an insecure connection.
- HTTP/3 is **not** yet supported because of some issues with Jetty's implementation.
- Client-side X.509 authentication is **not** supported.

## Contributing

Contributions are welcome! Open an issue or pull request if you have a suggestion or bug report. 

All development is done on the dev branch, main is used for releases.




