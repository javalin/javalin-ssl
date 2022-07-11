
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
Straightforward SSL Configuration for Javalin!

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
  <version>1.0.0-SNAPSHOT-1</version>
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
implementation('io.javalin:javalin-ssl:1.0.0-SNAPSHOT-1') //Latest snapshot
```

</details>



## Configuration

You can pass a config object when registering the plugin

```java
Javalin.create(config ->  { 
	...  // your javalin config here
	config.plugins.register(new SSLPlugin(sslConf-> {  // Your SSL config inside this block
	    sslConf.loadPemFromPath("...", "..."); 
	}));
});
```

### Available config options

```java
// Connection options
host = null;                                                                // Host to bind to, by default it will bind to all interfaces.
disableInsecure = false;                                                    // Disable the default http (insecure) connector.
disableSecure = false;                                                      // Disable the default https (secure) connector.
sslPort = 443;                                                              // Port to use on the SSL (secure) connector.
insecurePort = 80;                                                          // Port to use on the http (insecure) connector.
disableHttp2 = false;                                                       // Disables HTTP/2 Support

// PEM-Encoded file loading options
loadPemFromPath("certPath", "keyPath");                                     // Loads the cert and keys from the given paths.
loadPemFromPath("certPath", "keyPath", "keyPassword");                      // Loads the cert and keys from the given paths with the given key password.
loadPemFromClasspath("certPath", "keyPath");                                // Loads the cert and keys from the given paths in the classpath.
loadPemFromClasspath("certPath", "keyPath", "keyPassword");                 // Loads the cert and keys from the given paths in the classpath with the given key password.
loadPemFromInputStream(certInputStream, keyInputStream);                    // Loads the cert and keys from the given input streams.
loadPemFromInputStream(certInputStream, keyInputStream, "keyPassword");     // Loads the cert and keys from the given input streams with the given key password.
loadPemFromString(certString, keyString);                                   // Loads the cert and keys from the given strings.
loadPemFromString(certString, keyString, "keyPassword");                    // Loads the cert and keys from the given strings with the given key password.
```

### Notes

- For browser use the certificate should be a full chain, with the leaf certificate signed by a trusted root CA.
- Currently, only the PEM-Encoded files are supported.
- The PEM-Encoded Certificate loading options are mutually exclusive.
- HTTP3 is not yet supported because of some issues with the Jetty implementation.

## Contributing

Contributions are welcome! Open an issue or pull request if you have a suggestion or bug report. 





