import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val secretsFile = rootProject.file("secrets.properties")
if (!secretsFile.exists()) {
    throw GradleException("Нет android-tv/secrets.properties")
}
val secrets = Properties().apply { secretsFile.inputStream().use { load(it) } }

fun quote(value: String): String {
    val escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
    return "\"$escaped\""
}

android {
    namespace = "app.proxyhub.tv"
    compileSdk = 34

    defaultConfig {
        applicationId = "app.proxyhub.tv"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        buildConfigField("String", "PROXY_HOST", quote(secrets.getProperty("host") ?: ""))
        buildConfigField("int", "PROXY_PORT", secrets.getProperty("port") ?: "3128")
        buildConfigField("String", "PROXY_USER", quote(secrets.getProperty("user") ?: ""))
        buildConfigField("String", "PROXY_PASS", quote(secrets.getProperty("pass") ?: ""))
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    lint {
        checkReleaseBuilds = false
    }
}
