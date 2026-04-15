package com.pedrammarandi.androidscanner.scan.runtime

import android.content.Context
import android.os.Build
import com.pedrammarandi.androidscanner.scan.model.DnsttProgress
import com.pedrammarandi.androidscanner.scan.model.DnsttRuntimeRequest
import com.pedrammarandi.androidscanner.scan.model.DnsttTransport
import com.pedrammarandi.androidscanner.scan.model.ResolverRecord
import com.pedrammarandi.androidscanner.scan.model.ScanTransport
import java.io.File
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.job
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

sealed interface DnsttEvent {
    data class Progress(val value: DnsttProgress) : DnsttEvent
    data class ResolverChecked(val value: ResolverRecord) : DnsttEvent
}

fun interface DnsttRunner {
    suspend fun run(
        request: DnsttRuntimeRequest,
        emit: suspend (DnsttEvent) -> Unit,
    )
}

private const val helperLibraryName = "libandroidscanner_dnstt.so"

class GoDnsttRunner(
    private val context: Context,
) : DnsttRunner {
    override suspend fun run(
        request: DnsttRuntimeRequest,
        emit: suspend (DnsttEvent) -> Unit,
    ) = withContext(Dispatchers.IO) {
        val binary = prepareHelperBinary()
        val process = ProcessBuilder(binary.absolutePath)
            .redirectErrorStream(false)
            .start()

        currentCoroutineContext().ensureActive()
        currentCoroutineContext().job.invokeOnCompletion {
            if (process.isAlive) {
                process.destroy()
                if (process.isAlive) {
                    process.destroyForcibly()
                }
            }
        }

        val stderrReader = async(start = CoroutineStart.DEFAULT) {
            process.errorStream.bufferedReader().use { it.readText().trim() }
        }

        process.outputStream.bufferedWriter().use { writer ->
            writer.write(buildRequestPayload(request).toString())
            writer.flush()
        }

        process.inputStream.bufferedReader().use { reader ->
            while (true) {
                currentCoroutineContext().ensureActive()
                val line = reader.readLine() ?: break
                if (line.isBlank()) {
                    continue
                }
                handleResponseLine(line = line, request = request, emit = emit)
            }
        }

        val exitCode = process.waitFor()
        val stderr = stderrReader.await()
        if (exitCode != 0) {
            val message = stderr.ifBlank { "DNSTT helper exited with status $exitCode." }
            error(message)
        }
    }

    private fun prepareHelperBinary(): File {
        val supportedAbis = Build.SUPPORTED_ABIS?.toList().orEmpty()
        val nativeLibraryDir = context.applicationInfo.nativeLibraryDir
            ?: error("DNSTT helper directory is unavailable for this build.")
        val helperFile = File(nativeLibraryDir, helperLibraryName)
        require(helperFile.exists()) {
            val abiList = supportedAbis.joinToString().ifBlank { "unknown" }
            "DNSTT helper is missing from the packaged native libraries for this device ABI. Supported ABIs: $abiList."
        }
        require(helperFile.canExecute()) {
            "DNSTT helper is packaged but not executable."
        }
        return helperFile
    }

    private fun buildRequestPayload(request: DnsttRuntimeRequest): JSONObject {
        return JSONObject()
            .put(
                "config",
                JSONObject()
                    .put("workers", request.dnsttConfig.workers)
                    .put("timeout_ms", request.dnsttConfig.timeoutMillis)
                    .put("e2e_timeout_s", request.dnsttConfig.e2eTimeoutSeconds)
                    .put("port", request.scanConfig.port)
                    .put("transport", request.dnsttConfig.transport.name)
                    .put("domain", request.dnsttConfig.domain)
                    .put("pubkey", request.dnsttConfig.pubkey)
                    .put("query_size", request.scanConfig.querySize)
                    .put("e2e_url", request.dnsttConfig.e2eUrl)
                    .put("socks_username", request.dnsttConfig.socksUsername)
                    .put("socks_password", request.dnsttConfig.socksPassword)
                    .put("score_threshold", request.scanConfig.scoreThreshold)
                    .put("test_nearby_ips", request.dnsttConfig.testNearbyIps)
                    .put("base_prefixes", JSONArray(request.basePrefixes)),
            )
            .put(
                "resolvers",
                JSONArray().apply {
                    request.resolvers.forEach { resolver ->
                        put(
                            JSONObject()
                                .put("ip", resolver.ip)
                                .put("transport", resolver.transport.name)
                                .put("prefix", resolver.prefix)
                                .put("tunnel_score", resolver.tunnelScore)
                                .put("dnstt_nearby", resolver.dnsttNearby),
                        )
                    }
                },
            )
    }

    private suspend fun handleResponseLine(
        line: String,
        request: DnsttRuntimeRequest,
        emit: suspend (DnsttEvent) -> Unit,
    ) {
        val json = JSONObject(line)
        when (json.optString("type")) {
            "resolver" -> {
                val resolverJson = json.optJSONObject("resolver") ?: return
                emit(
                    DnsttEvent.ResolverChecked(
                        resolverFromJson(resolverJson, request.dnsttConfig.transport),
                    ),
                )
                json.optJSONObject("summary")?.let { summary ->
                    emit(DnsttEvent.Progress(progressFromJson(summary)))
                }
            }

            "progress", "complete" -> {
                json.optJSONObject("summary")?.let { summary ->
                    emit(DnsttEvent.Progress(progressFromJson(summary)))
                }
            }

            "error" -> {
                error(json.optString("message").ifBlank { "DNSTT helper reported an error." })
            }
        }
    }

    private fun progressFromJson(json: JSONObject): DnsttProgress {
        return DnsttProgress(
            checked = json.optLong("checked"),
            total = json.optLong("candidates"),
            tunnelOk = json.optLong("tunnel_ok"),
            e2eOk = json.optLong("e2e_ok"),
        )
    }

    private fun resolverFromJson(
        json: JSONObject,
        fallbackTransport: DnsttTransport,
    ): ResolverRecord {
        return ResolverRecord(
            ip = json.optString("ip"),
            transport = parseScanTransport(json.optString("transport"), fallbackTransport),
            prefix = json.optString("prefix"),
            dnsReachable = json.optBoolean("dns_reachable"),
            scanStatus = json.optString("scan_status"),
            scanError = json.optString("scan_error").ifBlank { null },
            recursionAdvertised = json.optBoolean("recursion_advertised"),
            qualifiedForTunnel = json.optInt("tunnel_score") > 0,
            stable = json.optBoolean("stable"),
            responseCode = json.optString("response_code"),
            latencyMillis = json.optLong("latency_ms"),
            tunnelScore = json.optInt("tunnel_score"),
            tunnelNsSupport = json.optBoolean("tunnel_ns_support"),
            tunnelTxtSupport = json.optBoolean("tunnel_txt_support"),
            tunnelRandomSub = json.optBoolean("tunnel_random_sub"),
            tunnelRealism = json.optBoolean("tunnel_realism"),
            tunnelEdns0Support = json.optBoolean("tunnel_edns0_support"),
            tunnelEdnsMaxPayload = json.optInt("tunnel_edns_max_payload"),
            tunnelNxdomain = json.optBoolean("tunnel_nxdomain"),
            dnsttNearby = json.optBoolean("dnstt_nearby"),
            dnsttChecked = json.optBoolean("dnstt_checked"),
            dnsttTunnelOk = json.optBoolean("dnstt_tunnel_ok"),
            dnsttE2eOk = json.optBoolean("dnstt_e2e_ok"),
            dnsttTunnelMillis = json.optLong("dnstt_tunnel_ms"),
            dnsttE2eMillis = json.optLong("dnstt_e2e_ms"),
            dnsttError = json.optString("dnstt_error"),
        )
    }

    private fun parseScanTransport(value: String, fallback: DnsttTransport): ScanTransport {
        return when (value.uppercase()) {
            ScanTransport.UDP.name -> ScanTransport.UDP
            ScanTransport.TCP.name -> ScanTransport.TCP
            ScanTransport.BOTH.name -> ScanTransport.BOTH
            else -> when (fallback) {
                DnsttTransport.UDP -> ScanTransport.UDP
                DnsttTransport.TCP -> ScanTransport.TCP
            }
        }
    }
}
