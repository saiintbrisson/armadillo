plugins {
    java
}

group = "rs.luiz.hytale.offline-mode"
version = "0.1.0"

val javaVersion = 25

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    compileOnly(files("libs/HytaleServer.jar"))
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(javaVersion))
    }
}

tasks.processResources {
    filesMatching("manifest.json") {
        expand(mapOf(
            "version" to version,
            "group" to group
        ))
    }
}
