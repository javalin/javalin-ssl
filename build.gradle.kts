import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("java-library")
    id("maven-publish")
    id("jacoco")
    id("signing")
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    val kotlinVersion = "1.9.22"
    kotlin("jvm") version kotlinVersion
    kotlin("kapt") version kotlinVersion
    id("org.jetbrains.dokka") version "1.9.10"

}

group = "io.javalin.community.ssl"
//Must be formatted following the RegEx: /version\s*=\s*"\S+"/g
version = "6.1.1-SNAPSHOT"

jacoco {
    toolVersion = "0.8.8"
}

repositories {
    mavenLocal()
    mavenCentral()
    maven("https://maven.reposilite.com/snapshots") {
        mavenContent {
            snapshotsOnly()
        }
    }
}

dependencies {
    val javalin = "6.1.1-SNAPSHOT"
    val sslContextKickstart = "8.3.1"

    val annotations = "24.1.0"
    val kotlinVersion = "1.9.0"

    val junit = "5.10.2"
    val slf4j = "2.0.12"
    val okhttp = "4.12.0"

    compileOnly("org.jetbrains:annotations:$annotations")
    compileOnly("io.javalin:javalin:$javalin")

    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:$kotlinVersion")
    implementation(platform("io.javalin:javalin-parent:$javalin")) //Javalin BOM
    implementation("org.eclipse.jetty.http2:http2-server")
    implementation("org.eclipse.jetty:jetty-alpn-conscrypt-server")
    implementation("org.eclipse.jetty:jetty-alpn-java-server")
    implementation("io.github.hakky54:sslcontext-kickstart:$sslContextKickstart")
    implementation("io.github.hakky54:sslcontext-kickstart-for-jetty:$sslContextKickstart")
    implementation("io.github.hakky54:sslcontext-kickstart-for-pem:$sslContextKickstart")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junit")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junit")
    testImplementation("io.javalin:javalin:$javalin")
    testImplementation("org.slf4j:slf4j-simple:$slf4j")
    testImplementation("com.squareup.okhttp3:okhttp:$okhttp")
    testImplementation("com.squareup.okhttp3:okhttp-tls:$okhttp")

}

val javadocJar by tasks.registering(Jar::class) {
    group = "documentation"
    description = "Generates a jar file containing the generated Javadoc API documentation."
    dependsOn(tasks.dokkaHtml)
    archiveClassifier.set("javadoc")
    from(tasks.dokkaHtml.flatMap { it.outputDirectory })
}

publishing {
    repositories {
        maven {
            name = "reposilite"

            val releasesRepoUrl = uri("https://maven.reposilite.com/releases")
            val snapshotsRepoUrl = uri("https://maven.reposilite.com/snapshots")

            url = if ((version as String).contains("SNAPSHOT"))  snapshotsRepoUrl else releasesRepoUrl

            credentials {
                username = System.getenv("MAVEN_NAME") ?: property("mavenUser").toString()
                password = System.getenv("MAVEN_TOKEN") ?: property("mavenPassword").toString()
            }
        }
    }
    publications {
        create<MavenPublication>("maven") {
            groupId = project.group as String
            artifactId = rootProject.name
            version = project.version as String

            from(components.getByName("java"))
            artifact(javadocJar.get())

            pom {
                name.set("Javalin SSL Plugin")
                description.set("Straightforward SSL Configuration for Javalin!")
                url.set("https://javalin.io/plugins/ssl-helpers")

                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("zugazagoitia")
                        name.set("Alberto Zugazagoitia")
                        email.set("alberto@zugazagoitia.com")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/javalin/javalin-ssl.git")
                    developerConnection.set("scm:git:ssh://github.com:javalin/javalin-ssl.git")
                    url.set("https://github.com/javalin/javalin-ssl")
                }
            }
        }
    }
}

signing {
    project.findProperty("signingKey")?.let {
        useInMemoryPgpKeys(
            findProperty("signingKeyId") as String,
            it as String,
            findProperty("signingPassword") as String)
    } ?: run {
        useGpgCmd()
    }

    sign(publishing.publications["maven"])
}

nexusPublishing {
    repositories {
        sonatype()
    }
}

tasks.register<Jar>("dokkaJavadocJar") {
    group = "documentation"
    description = "Generates a jar file containing the generated Javadoc API documentation."
    dependsOn(tasks.dokkaJavadoc)
    from(tasks.dokkaJavadoc.flatMap { it.outputDirectory })
    archiveClassifier.set("javadoc")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
    //withJavadocJar()
    modularity.inferModulePath.set(true)
}

tasks.compileJava {
    options.compilerArgumentProviders.add(CommandLineArgumentProvider {
        // Provide compiled Kotlin classes to javac – needed for Java/Kotlin mixed sources to work
        listOf("--patch-module", "io.javalin.community.ssl=${sourceSets["main"].output.asPath}")
    })
}

kotlin {
    compilerOptions{
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

tasks.jacocoTestReport{
    description = "Generates code coverage report for the test task."
    group = "verification"

    dependsOn("test")
    executionData.from(fileTree(project.projectDir).include("/jacoco/*.exec"))
    executionData("test")
    mustRunAfter("test")

    reports {
        xml.required.set(true)
    }

}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)

    testLogging {
        exceptionFormat = TestExceptionFormat.FULL
        showStackTraces = true
    }
}


