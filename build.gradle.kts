import org.gradle.api.tasks.testing.logging.TestExceptionFormat

plugins {
    id("java-library")
    id("maven-publish")
    id("jacoco")
    id("signing")
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    val kotlinVersion = "1.9.0"
    kotlin("jvm") version kotlinVersion
    kotlin("kapt") version kotlinVersion
    id("org.jetbrains.dokka") version "1.9.0"

}

group = "io.javalin.community.ssl"
//Must be formatted following the RegEx: /version\s*=\s*"\S+"/g
version = "6.0.0-SNAPSHOT"

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
    val javalin = "6.0.0-SNAPSHOT"
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
    implementation("org.eclipse.jetty.http3:http3-server")

    implementation("io.github.hakky54:sslcontext-kickstart:$sslContextKickstart")
    implementation("io.github.hakky54:sslcontext-kickstart-for-jetty:$sslContextKickstart")
    implementation("io.github.hakky54:sslcontext-kickstart-for-pem:$sslContextKickstart")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junit")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junit")
    testImplementation("io.javalin:javalin:$javalin")
    testImplementation("org.slf4j:slf4j-simple")
    testImplementation("com.squareup.okhttp3:okhttp:$okhttp")
    testImplementation("com.squareup.okhttp3:okhttp-tls:$okhttp")

}

val javadocJar by tasks.registering(Jar::class) {
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

/* TODO: Replace with kdoc
tasks.withType(Javadoc) {
    failOnError false
    options.addStringOption("Xdoclint:none", "-quiet")
    options.addStringOption("encoding", "UTF-8")
    options.addStringOption("charSet", "UTF-8")
} */



tasks.register<Jar>("dokkaJavadocJar") {
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


