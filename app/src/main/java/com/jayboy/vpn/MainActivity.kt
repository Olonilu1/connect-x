package com.jayboy.vpn

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

class MainActivity : AppCompatActivity() {

    companion object {
        const val VPN_REQUEST_CODE = 42
        const val NOTIF_REQUEST_CODE = 43
        const val IMPORT_REQUEST_CODE = 44
    }

    private lateinit var profileList: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var connectBtn: Button
    private lateinit var disconnectBtn: Button
    private val profiles = mutableListOf<JSONObject>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        profileList = findViewById(R.id.profileList)
        statusText = findViewById(R.id.statusText)
        connectBtn = findViewById(R.id.connectBtn)
        disconnectBtn = findViewById(R.id.disconnectBtn)
        val addBtn = findViewById<Button>(R.id.addProfileBtn)
        val importBtn = findViewById<Button>(R.id.importBtn)

        addBtn.setOnClickListener { showProfileDialog(null) }
        importBtn.setOnClickListener { importNpvt() }
        connectBtn.setOnClickListener { startVpnFlow() }
        disconnectBtn.setOnClickListener { stopVpn() }

        JayboyVpnService.stateCallback = { state ->
            runOnUiThread {
                statusText.text = when (state) {
                    "connecting" -> "connecting..."
                    "connected" -> "connected"
                    "disconnecting" -> "disconnecting..."
                    "disconnected" -> "disconnected"
                    "error" -> "error - check your config"
                    else -> state
                }
                connectBtn.isEnabled = state != "connected" && state != "connecting"
                disconnectBtn.isEnabled = state == "connected" || state == "connecting"
            }
        }

        loadProfiles()
        renderProfiles()

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIF_REQUEST_CODE)
        }
    }

    private fun prefs() = getSharedPreferences("jayboyvpn", MODE_PRIVATE)

    private fun loadProfiles() {
        profiles.clear()
        try {
            val arr = JSONArray(prefs().getString("profiles", "[]"))
            for (i in 0 until arr.length()) profiles.add(arr.getJSONObject(i))
        } catch (e: Exception) { }
    }

    private fun saveProfiles() {
        val arr = JSONArray()
        profiles.forEach { arr.put(it) }
        prefs().edit().putString("profiles", arr.toString()).apply()
    }

    /** Connection mode of a profile: "tls" (SSH-TLS-Payload), "plain" (direct SSH)
     *  or "dnstt" (SlowDNS tunnel, with or without SSH). Derived when missing so
     *  older saved profiles keep working. */
    private fun modeOf(p: JSONObject): String {
        val m = p.optString("mode")
        if (m == "tls" || m == "plain" || m == "dnstt") return m
        return when {
            p.optString("sni").isNotEmpty() || p.optString("payload").isNotEmpty() -> "tls"
            p.optString("tunnelDomain").isNotEmpty() && p.optString("publicKey").isNotEmpty() -> "dnstt"
            p.optString("sshUser").isNotEmpty() -> "plain"
            else -> "dnstt"
        }
    }

    private fun modeTag(p: JSONObject): String = when (modeOf(p)) {
        "tls" -> "+tls"
        "plain" -> "+ssh"
        else -> "+slowdns"
    }

    private fun renderProfiles() {
        profileList.removeAllViews()
        profiles.forEachIndexed { idx, p ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                setPadding(0, 16, 0, 16)
            }
            val box = CheckBox(this).apply {
                isChecked = p.optBoolean("selected", false)
                setOnCheckedChangeListener { _, checked -> p.put("selected", checked) }
                layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            }
            val label = TextView(this).apply {
                val ssh = if (p.optString("sshUser").isNotEmpty()) "+ssh" else ""
                text = "${p.optString("name")} $ssh${modeTag(p)}\n${if (p.optString("sshHost").isNotEmpty()) p.optString("sshHost") + ":" + p.optInt("sshPort", 22) else p.optString("tunnelDomain")}"
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            }
            val editBtn = Button(this).apply {
                text = "edit"
                setOnClickListener { showProfileDialog(idx) }
            }
            val delBtn = Button(this).apply {
                text = "del"
                setOnClickListener {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("Delete profile")
                        .setMessage("Remove ${p.optString("name")}?")
                        .setPositiveButton("Delete") { _, _ -> profiles.removeAt(idx); saveProfiles(); renderProfiles() }
                        .setNegativeButton("Cancel", null)
                        .show()
                }
            }
            row.addView(box); row.addView(label); row.addView(editBtn); row.addView(delBtn)
            profileList.addView(row)
        }
        if (profiles.isEmpty()) {
            val empty = TextView(this).apply {
                text = "no profiles yet. add one or import a netmod .npvt config file."
                setPadding(0, 16, 0, 16)
            }
            profileList.addView(empty)
        }
    }

    private fun showProfileDialog(editIndex: Int?) {
        val container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val pad = (24 * resources.displayMetrics.density).toInt()
        container.setPadding(pad, pad / 2, pad, 0)

        val nameIn = EditText(this).apply { hint = "profile name" }
        val dnsIn = EditText(this).apply { hint = "dns resolver ip, e.g. 8.8.8.8" }
        val domainIn = EditText(this).apply { hint = "slowdns nameserver, e.g. ns-fr1.vpnjantit.com" }
        val keyIn = EditText(this).apply { hint = "slowdns public key" }
        val sniIn = EditText(this).apply { hint = "sni (tls mode)" }
        val payloadIn = EditText(this).apply { hint = "payload, [crlf] = new line" }
        val mtuIn = EditText(this).apply { hint = "mtu (default 1400)"; setText("1400") }
        val sshHostIn = EditText(this).apply { hint = "ssh host (e.g. fr1.vpnjantit.com)" }
        val sshPortIn = EditText(this).apply { hint = "ssh port (22, 443, 444...)" }
        val sshUserIn = EditText(this).apply { hint = "ssh username" }
        val sshPassIn = EditText(this).apply { hint = "ssh password" }

        if (editIndex != null) {
            val p = profiles[editIndex]
            nameIn.setText(p.optString("name"))
            dnsIn.setText(p.optString("dnsServer"))
            domainIn.setText(p.optString("tunnelDomain"))
            keyIn.setText(p.optString("publicKey"))
            sniIn.setText(p.optString("sni"))
            payloadIn.setText(p.optString("payload"))
            mtuIn.setText(p.optInt("mtu", 1400).toString())
            sshHostIn.setText(p.optString("sshHost"))
            sshPortIn.setText(if (p.optString("sshPort").isEmpty()) "" else p.optInt("sshPort", 22).toString())
            sshUserIn.setText(p.optString("sshUser"))
            sshPassIn.setText(p.optString("sshPass"))
        }

        listOf(nameIn, dnsIn, domainIn, keyIn, sniIn, payloadIn, mtuIn, sshHostIn, sshPortIn, sshUserIn, sshPassIn).forEach { container.addView(it) }

        AlertDialog.Builder(this)
            .setTitle(if (editIndex == null) "Add profile" else "Edit profile")
            .setView(container)
            .setPositiveButton("Save") { _, _ ->
                val obj = if (editIndex != null) profiles[editIndex] else JSONObject()
                try {
                    obj.put("name", nameIn.text.toString().ifEmpty { "profile" })
                    obj.put("dnsServer", dnsIn.text.toString().trim().ifEmpty { "8.8.8.8" })
                    obj.put("tunnelDomain", domainIn.text.toString().trim())
                    obj.put("publicKey", keyIn.text.toString().trim())
                    obj.put("sni", sniIn.text.toString().trim())
                    obj.put("payload", payloadIn.text.toString().trim())
                    obj.put("mtu", mtuIn.text.toString().toIntOrNull() ?: 1400)
                    obj.put("sshHost", sshHostIn.text.toString().trim())
                    obj.put("sshPort", sshPortIn.text.toString().toIntOrNull() ?: 22)
                    obj.put("sshUser", sshUserIn.text.toString().trim())
                    obj.put("sshPass", sshPassIn.text.toString())
                    obj.put("mode", modeOf(obj))
                    if (editIndex == null) { obj.put("selected", false); profiles.add(obj) }
                    saveProfiles(); renderProfiles()
                } catch (e: Exception) { Toast.makeText(this, "could not save", Toast.LENGTH_SHORT).show() }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ---- netmod .npvt import ----

    private var pendingLockPassword: String? = null

    private fun importNpvt() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        startActivityForResult(Intent.createChooser(intent, "pick your .npvt config"), IMPORT_REQUEST_CODE)
    }

    private fun needsLockPassword(text: String): Boolean {
        return try {
            val arr = JSONArray(text)
            (0 until arr.length()).any { i ->
                val lock = arr.getJSONObject(i).optJSONObject("lockConfig")
                lock != null && lock.optBoolean("isLocked", false) && lock.optString("password", "").isNotEmpty()
            }
        } catch (e: Exception) { false }
    }

    /** Best-effort expiryDate parse: unix epoch seconds/millis first, then the common
     *  netmod/vpnjantit formats. Null when it cannot be read, so nothing gets blocked. */
    private fun lockExpiryMillis(lock: JSONObject): Long? {
        val raw = lock.optString("expiryDate", "").trim()
        if (raw.isEmpty()) return null
        raw.toLongOrNull()?.let { secs -> return if (secs > 100000000000L) secs else secs * 1000L }
        val formats = listOf(
            "yyyy-MM-dd'T'HH:mm:ssXXX",
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd",
            "dd/MM/yyyy HH:mm",
            "dd/MM/yyyy"
        )
        for (f in formats) {
            try {
                val fmt = SimpleDateFormat(f, Locale.US)
                fmt.timeZone = if (f.endsWith("'Z'")) TimeZone.getTimeZone("UTC") else TimeZone.getTimeZone("GMT+7")
                val d = fmt.parse(raw)
                if (d != null) return d.time
            } catch (e: ParseException) { continue }
        }
        return null
    }

    private fun importNpvtText(text: String) {
        val arr = JSONArray(text.trim())
        var added = 0
        var skippedExpired = 0
        var skippedLocked = 0
        var skippedOther = 0
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val ssh = o.optJSONObject("sshConfig")
            if (ssh == null) { skippedOther++; continue }
            val lock = o.optJSONObject("lockConfig")
            if (lock != null && lock.optBoolean("isLocked", false)) {
                val exp = lockExpiryMillis(lock)
                if (exp != null && exp < System.currentTimeMillis()) { skippedExpired++; continue }
                val lockPass = lock.optString("password", "")
                if (lockPass.isNotEmpty()) {
                    val entered = pendingLockPassword ?: ""
                    if (entered != lockPass) { skippedLocked++; continue }
                }
            }
            val sni = ssh.optString("sni").trim()
            val payload = ssh.optString("payload").trim()
            val nameserver = ssh.optString("nameserver").trim()
            val pubkey = ssh.optString("publicKey").trim()
            val p = JSONObject()
            p.put("name", ssh.optString("remarks").ifEmpty { o.optString("name", "config") })
            p.put("sshHost", ssh.optString("sshHost").trim())
            p.put("sshPort", (ssh.optString("sshPort").trim().toIntOrNull() ?: 22).let { if (it in 1..65535) it else 22 })
            p.put("sshUser", ssh.optString("sshUsername").trim())
            p.put("sshPass", ssh.optString("sshPassword"))
            p.put("sni", sni)
            p.put("payload", payload)
            p.put("dnsServer", ssh.optString("dnsServer").trim().ifEmpty { "8.8.8.8" })
            p.put("tunnelDomain", nameserver)
            p.put("publicKey", pubkey)
            p.put("mtu", 1400)
            p.put("selected", false)
            p.put("mode", when {
                sni.isNotEmpty() || payload.isNotEmpty() -> "tls"
                nameserver.isNotEmpty() && pubkey.isNotEmpty() -> "dnstt"
                else -> "plain"
            })
            profiles.add(p)
            added++
        }
        saveProfiles(); renderProfiles()
        val msg = StringBuilder("imported $added profiles")
        if (skippedExpired > 0) msg.append(", $skippedExpired expired")
        if (skippedLocked > 0) msg.append(", $skippedLocked wrong password")
        if (skippedOther > 0) msg.append(", $skippedOther unsupported")
        Toast.makeText(this, msg.toString(), Toast.LENGTH_LONG).show()
    }

    private fun askLockPassword(text: String) {
        val input = EditText(this).apply { hint = "config lock password" }
        AlertDialog.Builder(this)
            .setTitle("Locked config")
            .setMessage("this config file is locked, enter its password")
            .setView(input)
            .setPositiveButton("Import") { _, _ ->
                pendingLockPassword = input.text.toString()
                try { importNpvtText(text) } catch (e: Exception) {
                    Toast.makeText(this, "bad config file: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun startVpnFlow() {
        val selected = profiles.filter { it.optBoolean("selected", false) }
        if (selected.isEmpty()) {
            Toast.makeText(this, "tick at least one profile first", Toast.LENGTH_SHORT).show()
            return
        }
        val arr = JSONArray()
        selected.forEach { arr.put(it) }
        pendingTunnelsJson = arr.toString()
        pendingMtu = selected.firstOrNull()?.optInt("mtu", 1400) ?: 1400
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            onVpnReady()
        }
    }

    private var pendingTunnelsJson: String = "[]"
    private var pendingMtu: Int = 1400

    private fun onVpnReady() {
        val intent = Intent(this, JayboyVpnService::class.java).apply {
            action = JayboyVpnService.ACTION_CONNECT
            putExtra(JayboyVpnService.EXTRA_TUNNELS, pendingTunnelsJson)
            putExtra(JayboyVpnService.EXTRA_MTU, pendingMtu)
        }
        ContextCompat.startForegroundService(this, intent)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) onVpnReady()
        if (requestCode == IMPORT_REQUEST_CODE && resultCode == RESULT_OK && data?.data != null) {
            try {
                val text = contentResolver.openInputStream(data.data!!)?.bufferedReader()?.use { it.readText() } ?: ""
                if (text.isBlank()) {
                    Toast.makeText(this, "empty file", Toast.LENGTH_SHORT).show()
                    return
                }
                if (needsLockPassword(text)) {
                    askLockPassword(text)
                } else {
                    pendingLockPassword = null
                    importNpvtText(text)
                }
            } catch (e: Exception) {
                Toast.makeText(this, "could not read file: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun stopVpn() {
        val intent = Intent(this, JayboyVpnService::class.java).apply {
            action = JayboyVpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }
}
