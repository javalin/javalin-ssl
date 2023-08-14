import org.gradle.api.tasks.testing.logging.TestExceptionFormat

plugins {
    id("java-library")
    id("maven-publish")
    id("jacoco")
    id("io.freefair.lombok") version "8.1.0"
    id("signing")
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    val kotlinVersion = "1.9.0"
    kotlin("jvm") version kotlinVersion
    kotlin("kapt") version kotlinVersion
}

group = "io.javalin.community.ssl"
//Must be formatted following the RegEx: /version\s*=\s*"\S+"/g
version = "5.6.2"

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

sourceSets {
    create("intTest") {
        compileClasspath += sourceSets.main.get().output
        runtimeClasspath += sourceSets.main.get().output
    }
}

val intTestImplementation: Configuration by configurations.getting {
    extendsFrom(configurations.implementation.get())
}
val intTestRuntimeOnly: Configuration by configurations.getting

configurations["intTestRuntimeOnly"].extendsFrom(configurations.runtimeOnly.get())

dependencies {
    val javalin = "5.6.2"
    val junit = "5.10.0"
    val sslContextKickstart = "8.1.5"
    val okhttp = "4.11.0"
    val annotations = "24.0.1"
    val kotlinVersion = "1.9.0"

    compileOnly("org.jetbrains:annotations:$annotations")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:$kotlinVersion")

    compileOnly("io.javalin:javalin:$javalin")
    implementation(platform("io.javalin:javalin-parent:$javalin")) //Javalin BOM

    implementation("org.eclipse.jetty.http2:http2-server")
    implementation("org.eclipse.jetty:jetty-alpn-conscrypt-server")
    implementation("org.eclipse.jetty:jetty-alpn-java-server")
    //implementation("org.eclipse.jetty.http3:http3-server")

    implementation("io.github.hakky54:sslcontext-kickstart:$sslContextKickstart")
    implementation("io.github.hakky54:sslcontext-kickstart-for-jetty:$sslContextKickstart")
    implementation("io.github.hakky54:sslcontext-kickstart-for-pem:$sslContextKickstart")

    testImplementation("org.junit.jupiter:junit-jupiter-api:$junit")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junit")

    intTestImplementation("io.javalin:javalin:$javalin")
    intTestImplementation(platform("io.javalin:javalin-parent:$javalin"))

    intTestImplementation("io.github.hakky54:sslcontext-kickstart:$sslContextKickstart")
    intTestImplementation("io.github.hakky54:sslcontext-kickstart-for-jetty:$sslContextKickstart")
    intTestImplementation("io.github.hakky54:sslcontext-kickstart-for-pem:$sslContextKickstart")

    intTestImplementation("org.slf4j:slf4j-simple")
    intTestImplementation("org.eclipse.jetty.http2:http2-server")
    intTestImplementation("org.eclipse.jetty:jetty-alpn-java-server")
    intTestImplementation("org.eclipse.jetty:jetty-alpn-conscrypt-server")

    intTestImplementation("com.squareup.okhttp3:okhttp:$okhttp")
    intTestImplementation("com.squareup.okhttp3:okhttp-tls:$okhttp")
    intTestImplementation("org.junit.jupiter:junit-jupiter-api:$junit")

    intTestRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junit")
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

/* TODO: Replace with kdoc
tasks.withType(Javadoc) {
    failOnError false
    options.addStringOption("Xdoclint:none", "-quiet")
    options.addStringOption("encoding", "UTF-8")
    options.addStringOption("charSet", "UTF-8")
} */

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
    withJavadocJar()
}



val integrationTests = task<Test>("integrationTests") {
    description = "Runs the integration tests."
    group = "verification"

    testClassesDirs = sourceSets["intTest"].output.classesDirs
    classpath = sourceSets["intTest"].runtimeClasspath

    shouldRunAfter("test")

    outputs.upToDateWhen { false }

    testLogging {
        exceptionFormat = TestExceptionFormat.FULL
        showStackTraces = true
    }

    useJUnitPlatform {
        includeTags("integration")
    }

    finalizedBy("integrationTestsCoverageReport")

}

tasks.register<JacocoReport>("integrationTestsCoverageReport") {
    description = "Generates code coverage report for the integrationTest task."
    group = "verification"

    dependsOn("integrationTests")

    sourceSets(sourceSets.main.get())
    executionData("integrationTests")
    mustRunAfter("integrationTests")

   reports {
        xml.required.set(true)
    }

}

tasks.register<JacocoReport>("unitTestsCoverageReport") {
    description = "Generates code coverage report for the test task."
    group = "verification"

    dependsOn("test")

    sourceSets(sourceSets.main.get())
    executionData("test")
    mustRunAfter("test")

    reports {
        xml.required.set(true)
    }

}

tasks.test {
    useJUnitPlatform()
    finalizedBy("unitTestsCoverageReport")

    testLogging {
        exceptionFormat = TestExceptionFormat.FULL
        showStackTraces = true
    }
}

tasks.check{
    dependsOn(integrationTests)
}


