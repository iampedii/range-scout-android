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
val androidMinSdk = 26
val androidNdkVersion = "26.3.11579264"

fun configValue(name: String): String? {
    return localProperties.getProperty(name)?.trim()?.takeIf { it.isNotEmpty() }
        ?: System.getenv(name)?.trim()?.takeIf { it.isNotEmpty() }
}

fun signingValue(name: String): String? = configValue(name)

fun projectOrAbsoluteFile(path: String): File {
    val file = File(path)
    return if (file.isAbsolute) file else rootProject.file(path)
}

fun resolveAndroidNdkDir(): File {
    val explicitCandidates = listOfNotNull(
        configValue("ndk.dir"),
        configValue("ANDROID_NDK_HOME"),
        configValue("ANDROID_NDK_ROOT"),
        configValue("NDK_HOME"),
    )

    explicitCandidates.firstOrNull { path ->
        File(path).isDirectory
    }?.let { return File(it) }

    val sdkCandidates = listOfNotNull(
        configValue("sdk.dir"),
        configValue("ANDROID_HOME"),
        configValue("ANDROID_SDK_ROOT"),
    )

    sdkCandidates.firstOrNull { sdkPath ->
        File(sdkPath, "ndk/$androidNdkVersion").isDirectory
    }?.let { return File(it, "ndk/$androidNdkVersion") }

    error(
        "Android NDK $androidNdkVersion not found. Install it with " +
            "sdkmanager \"ndk;$androidNdkVersion\" or set ndk.dir/ANDROID_NDK_HOME.",
    )
}

fun androidNdkHostTags(): List<String> {
    val osName = System.getProperty("os.name").lowercase()
    val osArch = System.getProperty("os.arch").lowercase()
    return when {
        osName.contains("mac") && (osArch.contains("aarch64") || osArch.contains("arm64")) ->
            listOf("darwin-arm64", "darwin-x86_64")
        osName.contains("mac") -> listOf("darwin-x86_64", "darwin-arm64")
        osName.contains("windows") -> listOf("windows-x86_64")
        else -> listOf("linux-x86_64")
    }
}

fun resolveAndroidClangExecutable(targetPrefix: String): File {
    val compilerName = "$targetPrefix$androidMinSdk-clang"
    val llvmPrebuiltDir = resolveAndroidNdkDir().resolve("toolchains/llvm/prebuilt")
    val candidates = androidNdkHostTags().flatMap { hostTag ->
        val binDir = llvmPrebuiltDir.resolve("$hostTag/bin")
        listOf(
            binDir.resolve(compilerName),
            binDir.resolve("$compilerName.cmd"),
        )
    }

    return candidates.firstOrNull { it.canExecute() }
        ?: error(
            "Android NDK clang executable $compilerName not found. Checked: " +
                candidates.joinToString { it.absolutePath },
        )
}

val releaseStoreFilePath = signingValue("RELEASE_STORE_FILE")
val releaseStorePassword = signingValue("RELEASE_STORE_PASSWORD")
val releaseKeyAlias = signingValue("RELEASE_KEY_ALIAS")
val releaseKeyPassword = signingValue("RELEASE_KEY_PASSWORD")
val releaseSigningValues = listOf(
    releaseStoreFilePath,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
)
val releaseSigningConfigured = releaseSigningValues.all { it != null }

if (releaseSigningValues.any { it != null } && !releaseSigningConfigured) {
    error(
        "Release signing is partially configured. Set RELEASE_STORE_FILE, " +
            "RELEASE_STORE_PASSWORD, RELEASE_KEY_ALIAS, and RELEASE_KEY_PASSWORD.",
    )
}

data class DnsttHelperAbiTarget(
    val abi: String,
    val goArch: String,
    val goArm: String? = null,
    val taskSuffix: String,
    val androidClangPrefix: String? = null,
)

val dnsttHelperAbiTargets = listOf(
    DnsttHelperAbiTarget(
        abi = "armeabi-v7a",
        goArch = "arm",
        goArm = "7",
        taskSuffix = "ArmeabiV7a",
        androidClangPrefix = "armv7a-linux-androideabi",
    ),
    DnsttHelperAbiTarget(
        abi = "arm64-v8a",
        goArch = "arm64",
        taskSuffix = "Arm64V8a",
    ),
    DnsttHelperAbiTarget(
        abi = "x86",
        goArch = "386",
        taskSuffix = "X86",
        androidClangPrefix = "i686-linux-android",
    ),
    DnsttHelperAbiTarget(
        abi = "x86_64",
        goArch = "amd64",
        taskSuffix = "X8664",
        androidClangPrefix = "x86_64-linux-android",
    ),
)

android {
    namespace = "com.pedrammarandi.androidscanner"
    compileSdk = 34
    ndkVersion = androidNdkVersion

    defaultConfig {
        applicationId = "com.pedrammarandi.androidscanner"
        minSdk = androidMinSdk
        targetSdk = 34
        versionCode = 2
        versionName = "0.1.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseSigningConfigured) {
            create("release") {
                storeFile = projectOrAbsoluteFile(releaseStoreFilePath!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfigs.findByName("release")?.let {
                signingConfig = it
            }
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
            include("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
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
        buildConfig = true
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
            if (target.androidClangPrefix == null) {
                environment("CGO_ENABLED", "0")
            } else {
                environment("CGO_ENABLED", "1")
                environment(
                    "CC",
                    resolveAndroidClangExecutable(target.androidClangPrefix).absolutePath,
                )
            }
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
