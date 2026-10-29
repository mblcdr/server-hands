package com.samsaz.serverhands

import android.app.Application
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.samsaz.serverhands.keys.ApprovalKey
import com.samsaz.serverhands.keys.KeySecurityException
import com.samsaz.serverhands.keys.KeystoreDeviceSigner
import com.samsaz.serverhands.keys.VaultKey
import com.samsaz.serverhands.net.WakeOnLan
import com.samsaz.serverhands.vault.AuthCancelled
import com.samsaz.serverhands.vault.AuthFailed
import com.samsaz.serverhands.vault.Biometrics
import com.samsaz.serverhands.vault.EnrolledDrive
import com.samsaz.serverhands.vault.PairingRecord
import com.samsaz.serverhands.vault.PairingStore
import com.samsaz.serverhands.vault.VaultFormat
import dev.serverhands.crypto.PasswordEntry
import dev.serverhands.crypto.ProtocolException
import dev.serverhands.protocol.DriveResult
import dev.serverhands.protocol.PairingUri
import dev.serverhands.protocol.RequestView
import dev.serverhands.protocol.ScriptView
import dev.serverhands.protocol.Scripts
import dev.serverhands.protocol.ServerClient
import dev.serverhands.protocol.ServerException
import dev.serverhands.protocol.ServerStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import javax.net.ssl.SSLException

data class UiState(
    val pairing: PairingRecord? = null,
    val requests: List<RequestView> = emptyList(),
    val sas: String? = null,
    val busy: String? = null,
    val message: String? = null,
    val results: List<DriveResult> = emptyList(),
    val scripts: Scripts? = null,
    /** null until the first check; true when the last call reached the pinned server, false when it did not. */
    val connected: Boolean? = null,
    /** Latest machine and drive status; refreshed every few seconds while the app is in the foreground. */
    val status: ServerStatus? = null,
)

class AppViewModel(app: Application) : AndroidViewModel(app) {
    private companion object {
        const val STATUS_INTERVAL_MS = 5_000L
    }

    private val store = PairingStore(app.filesDir)
    private val allowSoftware = BuildConfig.ALLOW_SOFTWARE_KEYS
    private val _state = MutableStateFlow(UiState(pairing = store.load()))
    val state = _state.asStateFlow()

    private fun client(p: PairingRecord): ServerClient {
        val signer = KeystoreDeviceSigner.load(p.keyAlias) ?: throw KeySecurityException("device key is gone; pair again")
        return ServerClient(p.pin, signer)
    }

    /** Runs [block] with a busy label, turning every failure into a user message that never carries secrets. */
    private fun op(label: String, revocable: Boolean = true, block: suspend () -> Unit) {
        viewModelScope.launch {
            connectionIssue = false
            _state.update { it.copy(busy = label, message = null) }
            try {
                block()
            } catch (e: AuthCancelled) {
                _state.update { it.copy(message = "Cancelled.") }
            } catch (e: Exception) {
                if (!(revocable && forgetIfRevoked(e))) {
                    _state.update { it.copy(message = describe(e)) }
                    connectionIssue = e is IOException && e !is ServerException
                }
            } finally {
                _state.update { it.copy(busy = null, sas = null) }
            }
        }
    }

    private fun describe(e: Exception): String = when (e) {
        is ServerException -> when (e.code) {
            "unauthorized" -> "The server does not accept this phone (not paired, or revoked)."
            "rate_limited" -> "Too many failed attempts. Wait a few minutes."
            "not_unlocked" -> "That script needs the drives unlocked first."
            "busy" -> "That script is already running."
            "approval_required" -> "The server did not accept the biometric approval. Try again."
            "conflict" -> "The server already has a different approval key for this phone. On the server run: sudo handsctl reset-approval-key <device-id>"
            "unknown_script" -> "The server no longer has that script. Refresh."
            "expired" -> "That request expired. Refresh."
            "replayed" -> "That request was already used. Refresh."
            else -> "The server refused the request (${e.code})."
        }
        is ProtocolException -> "The server's reply could not be verified. Nothing was sent."
        is SSLException -> "This is not the server you paired with (identity mismatch). Nothing was sent."
        is IOException -> "Cannot reach the server on the local network."
        is KeyPermanentlyInvalidatedException -> {
            VaultKey.delete()
            store.clearVault()
            store.load()?.let { store.save(it.withDrives(emptyList())) }
            _state.update { it.copy(pairing = store.load()) }
            "Biometrics changed, so the vault key was destroyed. Enter the drive passphrases again."
        }
        is KeySecurityException -> e.message ?: "Key error."
        is AuthFailed -> "Authentication failed: ${e.reason}"
        else -> "Unexpected error."
    }

    fun pair(text: String, deviceName: String) = op("Pairing with server...", revocable = false) {
        val uri = try {
            PairingUri.parse(text)
        } catch (_: ProtocolException) {
            _state.update { it.copy(message = "That is not a Server Hands pairing code.") }
            return@op
        }
        val alias = PairingRecord.aliasFor(uri.pin.serverPub)
        val signer = KeystoreDeviceSigner.create(alias, allowSoftware)
        try {
            withContext(Dispatchers.IO) {
                ServerClient(uri.pin, signer).pair(uri.token, deviceName) { sas -> _state.update { it.copy(sas = sas) } }
            }
        } catch (e: Exception) {
            KeystoreDeviceSigner.delete(alias)
            throw e
        }
        val rec = PairingRecord(uri.pin.host, uri.pin.port, dev.serverhands.crypto.Codec.b64e(uri.pin.spkiSha256),
            dev.serverhands.crypto.Codec.b64e(uri.pin.serverPub), alias, deviceName)
        store.clear()
        store.save(rec)
        _state.update { it.copy(pairing = rec, message = "Paired.") }
    }

    fun refresh() = op("Connecting to server...") {
        val p = _state.value.pairing ?: return@op
        val c = client(p)
        try {
            val listing = withContext(Dispatchers.IO) { c.list() }
            val scripts = withContext(Dispatchers.IO) { c.scripts() }
            val status = try { withContext(Dispatchers.IO) { c.status() } } catch (_: ServerException) { null } catch (_: java.io.IOException) { null }
            _state.update { it.copy(requests = listing.requests, scripts = scripts, status = status ?: it.status, connected = true) }
        } catch (e: Exception) {
            // A refusal means the server answered; anything else (timeout, wrong identity, bad reply) means it did not count.
            _state.update { it.copy(connected = e is ServerException) }
            throw e
        }
    }

    private var lastCheck = 0L

    private var pollJob: Job? = null

    /** The last failure was "cannot reach the server": the poll clears it and loads what the failed check missed. */
    private var connectionIssue = false

    /**
     * Called when the app comes to the foreground: (re)connects or confirms the connection, unless something is
     * running, and starts refreshing the server status every few seconds until [onPause].
     */
    fun onResume() {
        val now = System.currentTimeMillis()
        val s = _state.value
        if (s.pairing != null && s.busy == null && now - lastCheck >= 3_000) {
            lastCheck = now
            refresh()
        }
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            while (isActive) {
                pollStatus()
                delay(STATUS_INTERVAL_MS)
            }
        }
    }

    fun onPause() {
        pollJob?.cancel()
        pollJob = null
    }

    /** Quiet: no busy spinner and no message, so it never gets in the way of an unlock. */
    private suspend fun pollStatus() {
        val p = _state.value.pairing ?: return
        if (_state.value.busy != null) return
        try {
            val c = client(p)
            val st = withContext(Dispatchers.IO) { c.status() }
            _state.update { it.copy(status = st, connected = true) }
            // Connected but nothing loaded yet (just paired, or the first refresh failed): load the scripts without a click.
            if ((_state.value.scripts == null || connectionIssue) && _state.value.busy == null) {
                val listing = withContext(Dispatchers.IO) { c.list() }
                val scripts = withContext(Dispatchers.IO) { c.scripts() }
                _state.update { it.copy(requests = listing.requests, scripts = scripts, message = if (connectionIssue) null else it.message) }
                connectionIssue = false
            }
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            if (forgetIfRevoked(e)) return
            _state.update { it.copy(connected = e is ServerException) }
        }
    }

    /**
     * Starts a script the server lists, then polls until nothing is queued or running. A `biometricProtection`
     * script first gets a challenge from the server, which the biometric-bound approval key signs; that prompt
     * is the confirmation, so the UI shows no extra dialog for it.
     */
    fun runScript(activity: FragmentActivity, script: ScriptView) = op("Running script...") {
        val p = _state.value.pairing ?: return@op
        val c = client(p)
        if (script.biometricProtection) {
            Biometrics.unavailableReason(activity)?.let { throw KeySecurityException(it) }
            val challenge = try {
                withContext(Dispatchers.IO) { c.scriptChallenge(script.name) }
            } catch (e: ServerException) {
                if (e.code != "approval_required") throw e
                // First protected script on this phone: register the biometric-bound key, then ask again.
                val spki = ApprovalKey.spki(allowSoftware)
                withContext(Dispatchers.IO) { c.registerApprovalKey(spki) }
                withContext(Dispatchers.IO) { c.scriptChallenge(script.name) }
            }
            val signature = try {
                ApprovalKey.signature()
            } catch (_: KeyPermanentlyInvalidatedException) {
                ApprovalKey.delete()
                throw KeySecurityException("Biometrics changed, so the approval key was destroyed. On the server run: sudo handsctl reset-approval-key <device-id>, then try again.")
            }
            val authorised = Biometrics.authenticate(activity, signature, "Run ${script.label}", p.host)
            authorised.update(challenge.message)
            val sig = authorised.sign()
            withContext(Dispatchers.IO) { c.runScript(script.name, challenge, sig) }
        } else {
            withContext(Dispatchers.IO) { c.runScript(script.name) }
        }
        repeat(120) {
            val s = withContext(Dispatchers.IO) { c.scripts() }
            _state.update { it.copy(scripts = s) }
            if (s.scripts.none { sc -> sc.busy }) return@op
            kotlinx.coroutines.delay(2_000)
        }
    }

    /** Stores [passphrases] (uuid -> raw bytes, taken over and wiped) in the vault behind a biometric. */
    fun enroll(activity: FragmentActivity, drives: List<dev.serverhands.protocol.DriveInfo>, passphrases: Map<String, ByteArray>) = op("Saving passphrases...") {
        val p = _state.value.pairing ?: return@op
        val fresh = passphrases.map { (u, pw) -> PasswordEntry(ServerClient.parseUuid(u), pw) }
        var existing = emptyList<PasswordEntry>()
        try {
            Biometrics.unavailableReason(activity)?.let { throw KeySecurityException(it) }
            VaultKey.getOrCreate(allowSoftware)
            val blob = store.readVault()
            if (blob != null) {
                val c = Biometrics.authenticate(activity, VaultKey.decryptCipher(VaultFormat.ivOf(blob)), "Unlock vault", "Add drives to ${p.host}")
                existing = VaultFormat.open(c, p.serverPub, blob)
            }
            val merged = existing.filter { e -> fresh.none { it.uuid.contentEquals(e.uuid) } } + fresh
            val c = Biometrics.authenticate(activity, VaultKey.encryptCipher(allowSoftware), "Save passphrases", "Stored for ${p.host}")
            store.writeVault(VaultFormat.seal(c, p.serverPub, merged))
            val enrolled = (p.drives.filter { d -> drives.none { it.luksUuid == d.uuid } } +
                drives.filter { d -> passphrases.containsKey(d.luksUuid) }.map { EnrolledDrive(it.luksUuid, it.label) })
            val rec = p.withDrives(enrolled)
            store.save(rec)
            _state.update { it.copy(pairing = rec, message = "Saved.") }
        } finally {
            (existing + fresh).forEach { it.wipe() }
            passphrases.values.forEach { it.fill(0) }
        }
    }

    fun unlock(activity: FragmentActivity, request: RequestView) = op("Unlocking drives...") {
        val p = _state.value.pairing ?: return@op
        val client = client(p)
        // Always act on a fresh, verified listing: its nonce is what the approval is bound to.
        val listing = withContext(Dispatchers.IO) { client.list() }
        val req = listing.requests.find { it.reqId == request.reqId }
        if (req == null) {
            _state.update { it.copy(requests = listing.requests, message = "That request is gone. Refreshed.") }
            return@op
        }
        val wanted = req.drives.filter { d -> p.drives.any { it.uuid == d.luksUuid } }
        if (wanted.isEmpty()) {
            _state.update { it.copy(requests = listing.requests, message = "No passphrase is saved for these drives.") }
            return@op
        }
        val blob = store.readVault() ?: throw KeySecurityException("Vault is empty. Enter the passphrases again.")
        val c = Biometrics.authenticate(
            activity, VaultKey.decryptCipher(VaultFormat.ivOf(blob)),
            "Unlock ${p.host}", wanted.joinToString { it.label },
        )
        val all = VaultFormat.open(c, p.serverPub, blob)
        // Release only passphrases for drives this request asks for AND that were enrolled for this server.
        val wantedRaw = wanted.map { ServerClient.parseUuid(it.luksUuid) }
        val chosen = all.filter { e -> wantedRaw.any { it.contentEquals(e.uuid) } }
        all.filter { it !in chosen }.forEach { it.wipe() }
        val result = try {
            withContext(Dispatchers.IO) { client.approve(listing, req, chosen) } // wipes `chosen`
        } finally {
            chosen.forEach { it.wipe() }
        }
        _state.update { it.copy(results = result.results) }
        val after = withContext(Dispatchers.IO) { client.list() }
        val scripts = withContext(Dispatchers.IO) { client.scripts() }
        _state.update { it.copy(requests = after.requests, scripts = scripts, message = null) }
    }

    /**
     * Saves a new address, port and Wake-on-LAN MAC (blank clears it). The pinned key is unchanged, so only the same server is accepted there.
     * Returns an error text when the input is invalid, null when saved.
     */
    fun updateServer(host: String, port: String, mac: String): String? {
        val h = host.trim()
        if (h.isEmpty() || h.any { it.isWhitespace() } || '/' in h) return "Enter the server's address."
        val p = port.trim().toIntOrNull()?.takeIf { it in 1..65535 } ?: return "The port must be between 1 and 65535."
        val m = mac.trim().let { if (it.isEmpty()) null else WakeOnLan.normalize(it) ?: return "That is not a MAC address (like aa:bb:cc:dd:ee:ff)." }
        val rec = _state.value.pairing?.withServer(h, p, m) ?: return null
        try { store.save(rec) } catch (_: java.io.IOException) { return "Could not save the changes." }
        _state.update { it.copy(pairing = rec, status = null, connected = null) }
        refresh()
        return null
    }

    /** Broadcasts a Wake-on-LAN packet; a [newMac] is validated and saved first. */
    fun wake(newMac: String? = null) = op("Sending Wake-on-LAN packet...") {
        var p = _state.value.pairing ?: return@op
        if (newMac != null) {
            val mac = WakeOnLan.normalize(newMac)
            if (mac == null) {
                _state.update { it.copy(message = "That is not a MAC address (like aa:bb:cc:dd:ee:ff).") }
                return@op
            }
            p = p.withMac(mac)
            store.save(p)
            _state.update { it.copy(pairing = p) }
        }
        val mac = p.mac ?: return@op
        withContext(Dispatchers.IO) { WakeOnLan.send(mac) }
        _state.update { it.copy(message = "Wake-on-LAN packet sent. The server may take a minute to start.") }
    }

    fun clearResults() = _state.update { it.copy(results = emptyList()) }

    /** The server answers "unauthorized" to a device it does not know (revoked or removed): drop the stale pairing. */
    private fun forgetIfRevoked(e: Exception): Boolean {
        if (_state.value.pairing == null || e !is ServerException || e.code != "unauthorized") return false
        forget()
        _state.update { it.copy(message = "The server removed this phone, so it was forgotten. Pair again to reconnect.") }
        return true
    }

    fun forget() {
        _state.value.pairing?.let { KeystoreDeviceSigner.delete(it.keyAlias) }
        VaultKey.delete()
        ApprovalKey.delete()
        store.clear()
        _state.value = UiState()
    }
}
