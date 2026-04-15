package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.input.HostWalker
import com.pedrammarandi.androidscanner.scan.model.FailureRecord
import com.pedrammarandi.androidscanner.scan.model.ResolverRecord
import com.pedrammarandi.androidscanner.scan.model.ScanProgress
import com.pedrammarandi.androidscanner.scan.model.ScanRuntimeRequest
import com.pedrammarandi.androidscanner.scan.model.ScanTransport
import java.io.IOException
import java.time.Duration
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.max
import kotlin.random.Random
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.NSRecord
import org.xbill.DNS.OPTRecord
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record as DnsRecord
import org.xbill.DNS.Section
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.TextParseException
import org.xbill.DNS.Type

private const val progressIntervalMillis = 500L
private const val resultBatchSize = 1
private const val maxProbeQueryTimeoutMillis = 1_500
private const val defaultTunnelScoreThreshold = 2
private const val statusWorking = "WORKING"
private val transparentProxyTestIps = listOf("192.0.2.1", "198.51.100.1", "203.0.113.1")

private data class ScanTarget(
    val ip: String,
    val prefix: String,
)

private data class ProbeResponse(
    val message: Message,
    val latencyMillis: Long,
)

private data class DnsQueryResult(
    val response: ProbeResponse? = null,
    val failureReason: String? = null,
)

private data class ProbeOutcome(
    val resolver: ResolverRecord? = null,
    val failureReason: String? = null,
)

private data class TunnelTestResult(
    val nsSupport: Boolean = false,
    val txtSupport: Boolean = false,
    val randomSub: Boolean = false,
    val tunnelRealism: Boolean = false,
    val edns0Support: Boolean = false,
    val ednsMaxPayload: Int = 0,
    val nxdomainCorrect: Boolean = false,
) {
    fun score(): Int {
        return listOf(
            nsSupport,
            txtSupport,
            randomSub,
            tunnelRealism,
            edns0Support,
            nxdomainCorrect,
        ).count { it }
    }
}

class DnsScanEngine(
    private val hostWalker: HostWalker,
) : ScanEngine {
    override suspend fun run(
        request: ScanRuntimeRequest,
        emit: suspend (ScanEvent) -> Unit,
    ) = coroutineScope {
        val emitMutex = Mutex()
        val serialEmit: suspend (ScanEvent) -> Unit = { event ->
            emitMutex.withLock {
                emit(event)
            }
        }

        val domain = ensureFqdn(request.config.probeDomain)
        val port = request.config.port
        val threshold = normalizeScoreThreshold(request.config.scoreThreshold)
        val totalTargets = request.totalTargets

        if (totalTargets > 0 &&
            protocolUsesUdp(request.config.protocol) &&
            detectTransparentProxy(domain = domain, timeoutMillis = 2_000)
        ) {
            serialEmit(ScanEvent.TransparentProxyDetected)
            serialEmit(ScanEvent.Warning("Transparent DNS proxy detected; results may be inaccurate."))
        }

        val jobs = Channel<ScanTarget>(capacity = max(request.config.workers * 4, 16))
        val scanned = AtomicLong(0)
        val working = AtomicLong(0)
        val compatible = AtomicLong(0)
        val qualified = AtomicLong(0)

        val progressJob = launch(start = CoroutineStart.UNDISPATCHED) {
            while (currentCoroutineContext().isActive) {
                emitProgress(scanned, working, compatible, qualified, totalTargets, serialEmit)
                delay(progressIntervalMillis)
            }
        }

        val workers = List(request.config.workers) {
            launch {
                val resolverBatch = mutableListOf<ResolverRecord>()
                val failureBatch = mutableListOf<FailureRecord>()

                try {
                    for (target in jobs) {
                        currentCoroutineContext().ensureActive()

                        val resolver = safeProbeResolver(
                            target = target,
                            timeoutMillis = request.config.timeoutMillis,
                            port = port,
                            protocol = request.config.protocol,
                            domain = domain,
                            querySize = request.config.querySize,
                            threshold = threshold,
                        )

                        scanned.incrementAndGet()

                        val resolved = resolver.resolver
                        if (resolved != null) {
                            if (resolved.tunnelScore > 0) {
                                compatible.incrementAndGet()
                            }
                            if (resolved.qualifiedForTunnel) {
                                working.incrementAndGet()
                                qualified.incrementAndGet()
                                resolverBatch += resolved
                                if (resolverBatch.size >= resultBatchSize) {
                                    flushResolverBatch(resolverBatch, serialEmit)
                                }
                            } else {
                                failureBatch += FailureRecord(
                                    ip = target.ip,
                                    prefix = target.prefix,
                                    reason = belowScoreThresholdReason(resolved, threshold),
                                )
                                if (failureBatch.size >= resultBatchSize) {
                                    flushFailureBatch(failureBatch, serialEmit)
                                }
                            }
                        } else {
                            failureBatch += FailureRecord(
                                ip = target.ip,
                                prefix = target.prefix,
                                reason = resolver.failureReason ?: "No DNS response",
                            )
                            if (failureBatch.size >= resultBatchSize) {
                                flushFailureBatch(failureBatch, serialEmit)
                            }
                        }
                    }
                } finally {
                    flushResolverBatch(resolverBatch, serialEmit)
                    flushFailureBatch(failureBatch, serialEmit)
                }
            }
        }

        try {
            hostWalker.walk(request.targets, request.totalTargets) { address, prefix ->
                currentCoroutineContext().ensureActive()
                jobs.send(ScanTarget(ip = address, prefix = prefix))
                true
            }
            jobs.close()
            workers.joinAll()
        } finally {
            jobs.close()
            workers.forEach { worker ->
                if (worker.isActive) {
                    worker.cancel()
                }
            }
            progressJob.cancelAndJoin()
        }

        emitProgress(scanned, working, compatible, qualified, totalTargets, serialEmit)
    }

    private suspend fun safeProbeResolver(
        target: ScanTarget,
        timeoutMillis: Int,
        port: Int,
        protocol: ScanTransport,
        domain: String,
        querySize: Int,
        threshold: Int,
    ): ProbeOutcome {
        return try {
            probeResolver(
                target = target,
                timeoutMillis = timeoutMillis,
                port = port,
                protocol = protocol,
                domain = domain,
                querySize = querySize,
                threshold = threshold,
            )
        } catch (error: CancellationException) {
            throw error
        } catch (error: VirtualMachineError) {
            throw error
        } catch (error: Throwable) {
            ProbeOutcome(
                failureReason = error.message
                    ?.takeIf { it.isNotBlank() }
                    ?.let { "Probe error: $it" }
                    ?: "Probe error: ${error::class.java.simpleName}",
            )
        }
    }

    private suspend fun emitProgress(
        scanned: AtomicLong,
        working: AtomicLong,
        compatible: AtomicLong,
        qualified: AtomicLong,
        totalTargets: Long,
        emit: suspend (ScanEvent) -> Unit,
    ) {
        emit(
            ScanEvent.Progress(
                ScanProgress(
                    scanned = scanned.get(),
                    total = totalTargets,
                    working = working.get(),
                    compatible = compatible.get(),
                    qualified = qualified.get(),
                ),
            ),
        )
    }

    private suspend fun flushResolverBatch(
        batch: MutableList<ResolverRecord>,
        emit: suspend (ScanEvent) -> Unit,
    ) {
        if (batch.isEmpty()) {
            return
        }

        emit(ScanEvent.ResolversFound(batch.toList()))
        batch.clear()
    }

    private suspend fun flushFailureBatch(
        batch: MutableList<FailureRecord>,
        emit: suspend (ScanEvent) -> Unit,
    ) {
        if (batch.isEmpty()) {
            return
        }

        emit(ScanEvent.FailuresRecorded(batch.toList()))
        batch.clear()
    }

    private suspend fun detectTransparentProxy(
        domain: String,
        timeoutMillis: Int,
    ): Boolean = coroutineScope {
        transparentProxyTestIps.map { ip ->
            async {
                dnsQuery(
                    ip = ip,
                    port = 53,
                    protocol = ScanTransport.UDP,
                    name = "${randomLabel(8)}.$domain",
                    queryType = Type.A,
                    timeoutMillis = timeoutMillis,
                    ednsPayload = 0,
                ) != null
            }
        }.awaitAll().any { it }
    }

    private suspend fun probeResolver(
        target: ScanTarget,
        timeoutMillis: Int,
        port: Int,
        protocol: ScanTransport,
        domain: String,
        querySize: Int,
        threshold: Int,
    ): ProbeOutcome {
        return when (protocol) {
            ScanTransport.BOTH -> {
                val udpResolver = probeResolverOnce(
                    target = target,
                    timeoutMillis = timeoutMillis,
                    port = port,
                    protocol = ScanTransport.UDP,
                    domain = domain,
                    querySize = querySize,
                    threshold = threshold,
                )
                val tcpResolver = probeResolverOnce(
                    target = target,
                    timeoutMillis = timeoutMillis,
                    port = port,
                    protocol = ScanTransport.TCP,
                    domain = domain,
                    querySize = querySize,
                    threshold = threshold,
                )

                when {
                    udpResolver.resolver != null && tcpResolver.resolver != null -> ProbeOutcome(
                        resolver = combineProtocolResolvers(udpResolver.resolver, tcpResolver.resolver),
                    )
                    udpResolver.resolver != null -> udpResolver
                    tcpResolver.resolver != null -> tcpResolver
                    else -> ProbeOutcome(
                        failureReason = "No DNS response over UDP or TCP",
                    )
                }
            }

            else -> probeResolverOnce(
                target = target,
                timeoutMillis = timeoutMillis,
                port = port,
                protocol = protocol,
                domain = domain,
                querySize = querySize,
                threshold = threshold,
            )
        }
    }

    private suspend fun probeResolverOnce(
        target: ScanTarget,
        timeoutMillis: Int,
        port: Int,
        protocol: ScanTransport,
        domain: String,
        querySize: Int,
        threshold: Int,
    ): ProbeOutcome = coroutineScope {
        val deepProbeTimeoutMillis = minOf(timeoutMillis, maxProbeQueryTimeoutMillis)
        val parentDomain = getParentDomain(domain)

        val warmupResult = dnsQueryDetailed(
            ip = target.ip,
            port = port,
            protocol = protocol,
            name = domain,
            queryType = Type.A,
            timeoutMillis = timeoutMillis,
            ednsPayload = 0,
        )
        val warmupResponse = warmupResult.response ?: return@coroutineScope ProbeOutcome(
            failureReason = warmupResult.failureReason
                ?.let { "${protocol.name} probe failed: $it" }
                ?: "No DNS response over ${protocol.name}",
        )

        var resolver = ResolverRecord(
            transport = protocol,
            ip = target.ip,
            prefix = target.prefix,
            dnsReachable = true,
            scanStatus = statusWorking,
            responseCode = Rcode.string(warmupResponse.message.header.rcode),
            latencyMillis = warmupResponse.latencyMillis,
            recursionAdvertised = warmupResponse.message.header.getFlag(Flags.RA.toInt()),
        )

        val ednsResult = testEdns0(target.ip, port, protocol, domain, deepProbeTimeoutMillis)
        val tunnel = TunnelTestResult(
            nsSupport = testNs(target.ip, port, protocol, parentDomain, deepProbeTimeoutMillis),
            txtSupport = testTxt(target.ip, port, protocol, domain, deepProbeTimeoutMillis),
            randomSub = testRandomSubdomain(target.ip, port, protocol, domain, deepProbeTimeoutMillis),
            tunnelRealism = testTunnelRealism(target.ip, port, protocol, domain, deepProbeTimeoutMillis, querySize),
            edns0Support = ednsResult.first,
            ednsMaxPayload = ednsResult.second,
            nxdomainCorrect = testNxdomain(target.ip, port, protocol, deepProbeTimeoutMillis),
        )

        resolver = applyTunnelResult(resolver, tunnel, threshold)
        ProbeOutcome(resolver = resolver)
    }

    private fun combineProtocolResolvers(
        left: ResolverRecord,
        right: ResolverRecord,
    ): ResolverRecord {
        val preferred = if (preferResolver(right, left)) right else left
        return preferred.copy(
            transport = ScanTransport.BOTH,
            dnsReachable = left.dnsReachable || right.dnsReachable,
        )
    }

    private fun preferResolver(candidate: ResolverRecord, current: ResolverRecord): Boolean {
        return when {
            candidate.tunnelScore != current.tunnelScore -> candidate.tunnelScore > current.tunnelScore
            candidate.latencyMillis > 0 && (current.latencyMillis <= 0 || candidate.latencyMillis < current.latencyMillis) -> true
            candidate.latencyMillis != current.latencyMillis -> false
            else -> candidate.transport == ScanTransport.UDP && current.transport != ScanTransport.UDP
        }
    }

    private fun applyTunnelResult(
        resolver: ResolverRecord,
        tunnel: TunnelTestResult,
        threshold: Int,
    ): ResolverRecord {
        val score = tunnel.score()
        return resolver.copy(
            tunnelNsSupport = tunnel.nsSupport,
            tunnelTxtSupport = tunnel.txtSupport,
            tunnelRandomSub = tunnel.randomSub,
            tunnelRealism = tunnel.tunnelRealism,
            tunnelEdns0Support = tunnel.edns0Support,
            tunnelEdnsMaxPayload = tunnel.ednsMaxPayload,
            tunnelNxdomain = tunnel.nxdomainCorrect,
            tunnelScore = score,
            qualifiedForTunnel = score >= threshold,
            stable = score == 6,
        )
    }

    private fun belowScoreThresholdReason(
        resolver: ResolverRecord,
        threshold: Int,
    ): String {
        return "DNS score ${resolver.tunnelScore}/6 is below min score $threshold"
    }

    private suspend fun testNs(
        ip: String,
        port: Int,
        protocol: ScanTransport,
        parentDomain: String,
        timeoutMillis: Int,
    ): Boolean {
        val nsResponse = dnsQuery(
            ip = ip,
            port = port,
            protocol = protocol,
            name = parentDomain,
            queryType = Type.NS,
            timeoutMillis = timeoutMillis,
            ednsPayload = 0,
        ) ?: return false

        val nsHost = firstNsHost(nsResponse.message) ?: return false
        return dnsQuery(
            ip = ip,
            port = port,
            protocol = protocol,
            name = nsHost,
            queryType = Type.A,
            timeoutMillis = timeoutMillis,
            ednsPayload = 0,
        ) != null
    }

    private fun firstNsHost(message: Message): String? {
        for (section in listOf(Section.ANSWER, Section.AUTHORITY)) {
            for (record in message.getSection(section)) {
                if (record is NSRecord) {
                    return record.target.toString()
                }
            }
        }
        return null
    }

    private suspend fun testTxt(
        ip: String,
        port: Int,
        protocol: ScanTransport,
        domain: String,
        timeoutMillis: Int,
    ): Boolean {
        val name = "${randomLabel(8)}.${getParentDomain(domain)}"
        return dnsQuery(
            ip = ip,
            port = port,
            protocol = protocol,
            name = name,
            queryType = Type.TXT,
            timeoutMillis = timeoutMillis,
            ednsPayload = 0,
        ) != null
    }

    private suspend fun testRandomSubdomain(
        ip: String,
        port: Int,
        protocol: ScanTransport,
        domain: String,
        timeoutMillis: Int,
    ): Boolean {
        repeat(2) {
            val name = "${randomLabel(8)}.${randomLabel(8)}.${domain.trimEnd('.')}"
            val response = dnsQuery(
                ip = ip,
                port = port,
                protocol = protocol,
                name = name,
                queryType = Type.A,
                timeoutMillis = timeoutMillis,
                ednsPayload = 0,
            )
            if (response != null) {
                return true
            }
        }
        return false
    }

    private suspend fun testTunnelRealism(
        ip: String,
        port: Int,
        protocol: ScanTransport,
        domain: String,
        timeoutMillis: Int,
        querySize: Int,
    ): Boolean {
        val payloadBytes = ByteArray(tunnelRealismPayload(querySize, domain))
        Random.Default.nextBytes(payloadBytes)
        val encoded = Base32NoPadding.encode(payloadBytes)
        val queryName = "${splitLabels(encoded, 57).joinToString(".")}.${domain.trimEnd('.')}"
        return dnsQuery(
            ip = ip,
            port = port,
            protocol = protocol,
            name = queryName,
            queryType = Type.TXT,
            timeoutMillis = timeoutMillis,
            ednsPayload = 0,
        ) != null
    }

    private suspend fun testEdns0(
        ip: String,
        port: Int,
        protocol: ScanTransport,
        domain: String,
        timeoutMillis: Int,
    ): Pair<Boolean, Int> {
        var anyOk = false
        var maxPayload = 0
        val parentDomain = getParentDomain(domain)

        for (payload in listOf(512, 900, 1232)) {
            val response = dnsQuery(
                ip = ip,
                port = port,
                protocol = protocol,
                name = "${randomLabel(8)}.$parentDomain",
                queryType = Type.A,
                timeoutMillis = timeoutMillis,
                ednsPayload = payload,
            ) ?: break

            if (response.message.header.rcode == Rcode.FORMERR) {
                break
            }

            if (response.message.getOPT() != null) {
                anyOk = true
                maxPayload = payload
                continue
            }

            break
        }

        return anyOk to maxPayload
    }

    private suspend fun testNxdomain(
        ip: String,
        port: Int,
        protocol: ScanTransport,
        timeoutMillis: Int,
    ): Boolean {
        var good = 0
        repeat(3) {
            val response = dnsQuery(
                ip = ip,
                port = port,
                protocol = protocol,
                name = "${randomLabel(12)}.invalid",
                queryType = Type.A,
                timeoutMillis = timeoutMillis,
                ednsPayload = 0,
            )
            if (response != null && response.message.header.rcode == Rcode.NXDOMAIN) {
                good += 1
            }
        }
        return good >= 2
    }

    private suspend fun dnsQuery(
        ip: String,
        port: Int,
        protocol: ScanTransport,
        name: String,
        queryType: Int,
        timeoutMillis: Int,
        ednsPayload: Int,
    ): ProbeResponse? {
        return dnsQueryDetailed(
            ip = ip,
            port = port,
            protocol = protocol,
            name = name,
            queryType = queryType,
            timeoutMillis = timeoutMillis,
            ednsPayload = ednsPayload,
        ).response
    }

    private suspend fun dnsQueryDetailed(
        ip: String,
        port: Int,
        protocol: ScanTransport,
        name: String,
        queryType: Int,
        timeoutMillis: Int,
        ednsPayload: Int,
    ): DnsQueryResult = withContext(Dispatchers.IO) {
        currentCoroutineContext().ensureActive()

        val queryName = try {
            Name.fromString(ensureFqdn(name))
        } catch (_: TextParseException) {
            return@withContext DnsQueryResult(failureReason = "Invalid DNS query name: $name")
        }

        val message = Message.newQuery(DnsRecord.newRecord(queryName, queryType, DClass.IN))
        message.header.setFlag(Flags.RD.toInt())
        if (ednsPayload > 0) {
            message.addRecord(OPTRecord(ednsPayload, 0, 0), Section.ADDITIONAL)
        }

        val resolver = SimpleResolver(ip)
        resolver.setPort(port)
        resolver.setTCP(protocol == ScanTransport.TCP)
        resolver.setIgnoreTruncation(protocol == ScanTransport.UDP)
        resolver.setTimeout(Duration.ofMillis(timeoutMillis.toLong()))

        val startedAt = System.nanoTime()
        val response = try {
            resolver.send(message)
        } catch (error: IOException) {
            return@withContext DnsQueryResult(failureReason = formatQueryFailure(error))
        } catch (error: RuntimeException) {
            return@withContext DnsQueryResult(failureReason = formatQueryFailure(error))
        }

        val latencyMillis = max(
            1L,
            (System.nanoTime() - startedAt) / 1_000_000L,
        )
        DnsQueryResult(response = ProbeResponse(response, latencyMillis))
    }

    private fun formatQueryFailure(error: Throwable): String {
        val message = error.message?.takeIf { it.isNotBlank() }
        return if (message == null) {
            error::class.java.simpleName
        } else {
            "${error::class.java.simpleName}: $message"
        }
    }

    private fun protocolUsesUdp(protocol: ScanTransport): Boolean {
        return protocol == ScanTransport.UDP || protocol == ScanTransport.BOTH
    }

    private fun normalizeScoreThreshold(value: Int): Int {
        return when {
            value <= 0 -> defaultTunnelScoreThreshold
            value > 6 -> 6
            else -> value
        }
    }

    private fun ensureFqdn(value: String): String {
        val trimmed = value.trim().trimEnd('.')
        return if (trimmed.endsWith('.')) trimmed else "$trimmed."
    }

    private fun getParentDomain(domain: String): String {
        val trimmed = domain.trim().trimEnd('.')
        val parts = trimmed.split('.', limit = 2)
        return if (parts.size >= 2 && parts[1].contains('.')) parts[1] else trimmed
    }

    private fun randomLabel(length: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        return buildString(length) {
            repeat(length) {
                append(alphabet[Random.Default.nextInt(alphabet.length)])
            }
        }
    }

    private fun splitLabels(value: String, maxLength: Int): List<String> {
        if (maxLength <= 0 || value.length <= maxLength) {
            return listOf(value)
        }
        return buildList {
            var index = 0
            while (index < value.length) {
                val end = minOf(index + maxLength, value.length)
                add(value.substring(index, end))
                index = end
            }
        }
    }

    private fun tunnelRealismPayload(querySize: Int, domain: String): Int {
        if (querySize < 50) {
            return 100
        }
        val suffixLength = domain.trimEnd('.').length + 2
        val overhead = 12 + 4 + suffixLength
        val available = max(10, querySize - overhead)
        val raw = available * 5 / 9
        return raw.coerceIn(5, 100)
    }
}

private object Base32NoPadding {
    private const val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(bytes: ByteArray): String {
        if (bytes.isEmpty()) {
            return ""
        }

        val output = StringBuilder((bytes.size * 8 + 4) / 5)
        var buffer = 0
        var bitsLeft = 0

        for (byte in bytes) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                val index = (buffer shr (bitsLeft - 5)) and 0x1F
                output.append(alphabet[index])
                bitsLeft -= 5
            }
        }

        if (bitsLeft > 0) {
            val index = (buffer shl (5 - bitsLeft)) and 0x1F
            output.append(alphabet[index])
        }

        return output.toString()
    }
}
