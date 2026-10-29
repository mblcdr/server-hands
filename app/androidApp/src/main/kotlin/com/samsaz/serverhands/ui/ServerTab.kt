package com.samsaz.serverhands.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.samsaz.serverhands.UiState
import com.samsaz.serverhands.vault.PairingRecord
import dev.serverhands.protocol.DriveInfo
import dev.serverhands.protocol.DriveStatus
import dev.serverhands.protocol.PoolStatus
import dev.serverhands.protocol.RequestView
import dev.serverhands.protocol.ServerStatus

@Composable
fun ServerTab(
    ui: UiState,
    pairing: PairingRecord,
    onRefresh: () -> Unit,
    onUnlock: (RequestView) -> Unit,
    onEnroll: (RequestView) -> Unit,
    onForget: () -> Unit,
    onWake: () -> Unit,
    onEdit: () -> Unit,
) {
    val idle = ui.busy == null
    val enrolled = pairing.drives.map { it.uuid }.toSet()
    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { Header("Server Hands") }
        item { StatusStrip(ui) }
        item { ConnectionPanel(ui, pairing, idle, onWake, onEdit, onForget) }
        ui.status?.let { s -> item { MachinePanel(s) } }

        // Only while connected, and only when something is waiting or a drive is still locked.
        val drives = ui.status?.drives
        val stillLocked = drives != null && !(drives.isNotEmpty() && drives.all { it.state == "mounted" || it.state == "open" })
        if (ui.connected == true && (ui.requests.isNotEmpty() || stillLocked)) {
            item {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    SectionTitle("Unlock requests")
                    FilledTonalButton(onClick = onRefresh, enabled = idle) { Text("Check") }
                }
            }
            if (ui.requests.isEmpty()) {
                item { Text("No drives waiting to be unlocked.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 4.dp)) }
            }
            ui.requests.forEach { r ->
                items(r.drives, key = { "${r.reqId}/${it.luksUuid}" }) { d -> RequestDriveItem(d, saved = d.luksUuid in enrolled) }
                item(key = r.reqId) {
                    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        val big = Modifier.widthIn(max = 420.dp).fillMaxWidth().height(52.dp)
                        if (r.drives.any { it.luksUuid in enrolled }) Button(onClick = { onUnlock(r) }, enabled = idle, modifier = big) { Text("Unlock", style = MaterialTheme.typography.titleMedium) }
                        if (r.drives.any { it.luksUuid !in enrolled }) FilledTonalButton(onClick = { onEnroll(r) }, enabled = idle, modifier = big) { Text("Save passphrases", style = MaterialTheme.typography.titleMedium) }
                    }
                }
            }
        }

        val unlocked = ui.status?.drives.orEmpty().filter { it.state == "mounted" || it.state == "open" }
        if (unlocked.isNotEmpty()) {
            item { SectionTitle("Drives") }
            items(unlocked, key = { it.luksUuid }) { DriveUsageItem(it) }
        }
        val pools = ui.status?.pools.orEmpty()
        if (pools.isNotEmpty()) {
            item { SectionTitle(if (pools.size == 1) "Pool" else "Pools") }
            items(pools, key = { it.mountPoint }) { PoolItem(it) }
        }

        item { Column(Modifier.padding(bottom = 16.dp)) {} }
    }
}

/** Server status; tap to show the pairing details and the forget button. */
@Composable
private fun ConnectionPanel(ui: UiState, pairing: PairingRecord, idle: Boolean, onWake: () -> Unit, onEdit: () -> Unit, onForget: () -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Panel(Modifier.clickable { expanded = !expanded }) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            val tint = if (ui.connected == false) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
            IconBadge(AppIcons.Server, tint, tint.copy(alpha = 0.12f))
            Column(Modifier.weight(1f)) {
                Text(ui.status?.hostname?.ifEmpty { null } ?: pairing.host, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text("${pairing.host}:${pairing.port}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            when (ui.connected) {
                true -> Pill("Connected", MaterialTheme.colorScheme.primary)
                false -> Pill("Offline", MaterialTheme.colorScheme.error)
                null -> Pill(if (ui.busy != null) "Connecting" else "Not checked", MaterialTheme.colorScheme.outline)
            }
        }
        if (ui.connected == false) {
            FilledTonalButton(onClick = onWake, enabled = idle, modifier = Modifier.fillMaxWidth()) { Text("Wake (Wake-on-LAN)") }
        }
        AnimatedVisibility(expanded, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Key fingerprint", modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(pairing.pin.fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                Text("This phone: ${pairing.deviceName}", style = MaterialTheme.typography.bodySmall)
                Text("Saved passphrases: ${pairing.drives.joinToString { it.label }.ifEmpty { "none" }}", style = MaterialTheme.typography.bodySmall)
                pairing.mac?.let { Text("MAC address: $it", style = MaterialTheme.typography.bodySmall) }
                OutlinedButton(onClick = onEdit, enabled = idle, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Edit server details") }
                Button(
                    onClick = onForget,
                    enabled = idle,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError),
                    modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                ) { Text("Forget this server") }
            }
        }
    }
}

@Composable
private fun MachinePanel(s: ServerStatus) = Panel {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text("Up ${formatUptime(s.uptimeSecs)}", style = MaterialTheme.typography.titleSmall)
        Text(s.kernel, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    Meter("CPU", fraction = (s.cpuPercent / 100).toFloat(), detail = "${s.cpuPercent.toInt()}% of ${s.cpus} ${if (s.cpus == 1) "core" else "cores"}")
    val memUsed = (s.memTotal - s.memAvailable).coerceAtLeast(0)
    Meter("Memory", fraction(memUsed, s.memTotal), "${formatBytes(memUsed)} of ${formatBytes(s.memTotal)}")
    if (s.swapTotal > 0) {
        val swapUsed = (s.swapTotal - s.swapFree).coerceAtLeast(0)
        Meter("Swap", fraction(swapUsed, s.swapTotal), "${formatBytes(swapUsed)} of ${formatBytes(s.swapTotal)}")
    }
    if (s.load.size == 3) {
        Text("Load  ${"%.2f".format(s.load[0])}  ${"%.2f".format(s.load[1])}  ${"%.2f".format(s.load[2])}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun Meter(title: String, fraction: Float, detail: String) = Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(title, style = MaterialTheme.typography.labelLarge)
        Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    UsageBar(fraction)
}

/** One locked drive in an unlock request. */
@Composable
private fun RequestDriveItem(d: DriveInfo, saved: Boolean) = Panel {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        IconBadge(AppIcons.HardDrive, MaterialTheme.colorScheme.tertiary, MaterialTheme.colorScheme.tertiaryContainer)
        Column(Modifier.weight(1f)) {
            Text(d.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(formatBytes(d.size), style = MaterialTheme.typography.bodyMedium)
            Text(d.luksUuid, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Pill("Locked", MaterialTheme.colorScheme.error)
            Pill(if (saved) "Passphrase saved" else "No passphrase", if (saved) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline)
        }
    }
}

/** An unlocked drive with how full it is. */
@Composable
private fun DriveUsageItem(d: DriveStatus) = Panel {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        IconBadge(AppIcons.HardDrive, MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.primaryContainer)
        Column(Modifier.weight(1f)) {
            Text(d.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(formatBytes(if (d.total > 0) d.total else d.size), style = MaterialTheme.typography.bodyMedium)
        }
        if (d.state == "mounted") Pill(percent(fraction(d.used, d.total)), MaterialTheme.colorScheme.primary) else Pill("Not mounted", MaterialTheme.colorScheme.outline)
    }
    if (d.state == "mounted") {
        UsageBar(fraction(d.used, d.total))
        Text("${formatBytes(d.used)} used  ·  ${formatBytes(d.avail)} free", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** The merged pool (for example mergerfs). */
@Composable
private fun PoolItem(p: PoolStatus) = Panel {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        IconBadge(AppIcons.Layers, MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.primaryContainer)
        Column(Modifier.weight(1f)) {
            Text(p.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(p.mountPoint, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (p.mounted) Pill(p.fstype.removePrefix("fuse.").ifEmpty { "pool" }, MaterialTheme.colorScheme.primary) else Pill("Not mounted", MaterialTheme.colorScheme.outline)
    }
    if (p.mounted) {
        Text(formatBytes(p.total), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        UsageBar(fraction(p.used, p.total))
        Text("${formatBytes(p.used)} used  ·  ${formatBytes(p.avail)} free  ·  ${percent(fraction(p.used, p.total))}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
