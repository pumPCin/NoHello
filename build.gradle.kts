import com.android.build.gradle.AppExtension
import java.io.ByteArrayOutputStream

plugins {
    alias(libs.plugins.agp.app) apply false
}

fun String.execute(currentWorkingDir: File = layout.projectDirectory.asFile): String {
    return try {
        providers.exec {
            workingDir = currentWorkingDir
            commandLine = this@execute.split("\\s".toRegex())
        }.standardOutput.asText.get().trim()
    } catch (e: Exception) {
        ""
    }
}

val localProperties = java.util.Properties()
val localPropertiesFile = file("local.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(localPropertiesFile.inputStream())
}

val sdkDir: String by extra(
    localProperties.getProperty("sdk.dir")
        ?: System.getenv("ANDROID_HOME")
        ?: System.getenv("ANDROID_SDK_ROOT")
        ?: ""
)

val zygDir: File by extra(
    localProperties.getProperty("zyg.dir")?.let { File(it) }
        ?: layout.projectDirectory.dir(".github/updates").asFile
)

val gitCommitCountStr = "git rev-list HEAD --count".execute()
val gitCommitCount = gitCommitCountStr.toIntOrNull() ?: 0

val gitCommitHashRaw = "git rev-parse --verify --short HEAD".execute()
val gitCommitHash = if (gitCommitHashRaw.isEmpty()) "unknown" else gitCommitHashRaw

// also the soname
val moduleId by extra("zygisk_nohello")
val moduleName by extra("Nohello")
val verName by extra("v0.0.7")
val verCode by extra(gitCommitCount)
val commitHash by extra(gitCommitHash)
val abiList by extra(listOf("arm64-v8a", "armeabi-v7a"))

val androidMinSdkVersion by extra(26)
val androidTargetSdkVersion by extra(34)
val androidCompileSdkVersion by extra(34)
val androidBuildToolsVersion by extra("34.0.0")
val androidCompileNdkVersion by extra("26.0.10792818")
val androidSourceCompatibility by extra(JavaVersion.VERSION_21)
val androidTargetCompatibility by extra(JavaVersion.VERSION_21)

tasks.register("Delete", Delete::class) {
    delete(layout.buildDirectory)
}

fun Project.configureBaseExtension() {
    extensions.findByType(AppExtension::class)?.run {
        namespace = "io.github.mhmrdd.zygisk.module.nohello"
        compileSdkVersion(androidCompileSdkVersion)
        ndkVersion = androidCompileNdkVersion
        buildToolsVersion = androidBuildToolsVersion

        defaultConfig {
            minSdk = androidMinSdkVersion
        }

        compileOptions {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }
}

subprojects {
    plugins.withId("com.android.application") {
        configureBaseExtension()
    }
    plugins.withType(JavaPlugin::class.java) {
        extensions.configure(JavaPluginExtension::class.java) {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }
}
