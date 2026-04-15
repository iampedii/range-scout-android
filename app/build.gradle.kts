import java.io.File
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        file.inputStream().use(::load)
    }
}

fun resolveGoExecutable(): String {
    val explicitCandidates = listOfNotNull(
        localProperties.getProperty("go.bin")?.trim()?.takeIf { it.isNotEmpty() },
        System.getenv("GO_BIN")?.trim()?.takeIf { it.isNotEmpty() },
        "/usr/local/go/bin/go",
        "/opt/homebrew/bin/go",
    )

    explicitCandidates.firstOrNull { path ->
        File(path).canExecute()
    }?.let { return it }

    val pathCandidate = System.getenv("PATH")
        ?.split(File.pathSeparatorChar)
        ?.asSequence()
        ?.map { File(it, "go") }
        ?.firstOrNull { it.canExecute() }

    return pathCandidate?.absolutePath
        ?: error(
            "Go toolchain not found. Set go.bin=/absolute/path/to/go in local.properties " +
                "or export GO_BIN before running Gradle.",
        )
}

val dnsttHelperDir = rootProject.layout.projectDirectory.dir("dnstt-helper")
val generatedDnsttJniLibsDir = layout.buildDirectory.dir("generated/jniLibs/dnstt")
val goBuildCacheDir = layout.buildDirectory.dir("go-build-cache")
val goExecutable = resolveGoExecutable()

data class DnsttHelperAbiTarget(
    val abi: String,
    val goArch: String,
    val goArm: String? = null,
    val taskSuffix: String,
)

// Go's android/arm, android/386, and android/amd64 targets require Android NDK
// cgo linkers. Keep the packaged helper arm64-only until an NDK-backed build is
// added; this keeps local and CI builds reproducible without committing APKs.
val dnsttHelperAbiTargets = listOf(
    DnsttHelperAbiTarget(
        abi = "arm64-v8a",
        goArch = "arm64",
        taskSuffix = "Arm64",
    ),
)

android {
    namespace = "com.pedrammarandi.androidscanner"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.pedrammarandi.androidscanner"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a")
            isUniversalApk = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }

    sourceSets.getByName("main").jniLibs.srcDir(generatedDnsttJniLibsDir)
}

val buildDnsttHelperTasks = dnsttHelperAbiTargets.map { target ->
    tasks.register<Exec>("buildDnsttHelper${target.taskSuffix}") {
        val outputFile = generatedDnsttJniLibsDir.map {
            it.dir(target.abi).file("libandroidscanner_dnstt.so").asFile
        }

        workingDir = dnsttHelperDir.asFile
        executable = goExecutable
        environment("GOCACHE", goBuildCacheDir.get().asFile.absolutePath)
        environment("GOOS", "android")
        environment("GOARCH", target.goArch)
        target.goArm?.let { environment("GOARM", it) }
        environment("CGO_ENABLED", "0")
        args(
            "build",
            "-trimpath",
            "-ldflags",
            "-s -w",
            "-o",
            outputFile.get().absolutePath,
            "./cmd/androidscanner-dnstt",
        )

        inputs.dir(dnsttHelperDir)
        outputs.file(outputFile)

        doFirst {
            outputFile.get().parentFile.mkdirs()
            goBuildCacheDir.get().asFile.mkdirs()
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn(buildDnsttHelperTasks)
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.compose.ui:ui:1.6.8")
    implementation("androidx.compose.ui:ui-tooling-preview:1.6.8")
    implementation("androidx.compose.foundation:foundation:1.6.8")
    implementation("androidx.compose.material3:material3:1.2.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("dnsjava:dnsjava:3.6.4")
    implementation("org.slf4j:slf4j-nop:2.0.16")

    testImplementation("junit:junit:4.13.2")

    debugImplementation("androidx.compose.ui:ui-tooling:1.6.8")
    debugImplementation("androidx.compose.ui:ui-test-manifest:1.6.8")
}
