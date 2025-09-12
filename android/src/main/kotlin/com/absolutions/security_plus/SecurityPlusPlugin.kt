package com.absolutions.security_plus

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.Debug
import android.os.Process
import android.provider.Settings
import androidx.core.content.ContextCompat
import com.scottyab.rootbeer.RootBeer
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/** SecurityPlusPlugin (fixed) */
class SecurityPlusPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var context: Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "security_plus")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "isRooted" -> result.success(isRooted())
            "isEmulator" -> result.success(isEmulator())
            "isOnExternalStorage" -> result.success(isOnExternalStorage(context))
            "isDevelopmentModeEnable" -> result.success(developmentModeCheck(context))
            "isMockLocationEnabled" -> result.success(isMockLocationEnabled(context))
            // Optional: expose which signals fired for debugging in QA builds
            "getRootSignals" -> {
                val s = collectRootSignals()
                result.success(
                    mapOf(
                        "rootBeer" to s.rootBeer,
                        "fridaLibs" to s.fridaLibs,
                        "fridaProcs" to s.fridaProcs,
                        "suspiciousFiles" to s.suspiciousFiles,
                        "suInPath" to s.suInPath,
                        "suApps" to s.suApps,
                        "debuggerAttached" to s.debuggerAttached
                    )
                )
            }
            else -> result.notImplemented()
        }
    }

    // ---- Public checks ----

    fun isRooted(): Boolean {
        val s = collectRootSignals()
        return s.isRootedLike()
    }

    private fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk", true) ||
                Build.MODEL.contains("Emulator", true) ||
                Build.MODEL.contains("Android SDK built for x86", true) ||
                Build.MANUFACTURER.contains("Genymotion", true) ||
                Build.MODEL.startsWith("sdk_", true) ||
                Build.DEVICE.startsWith("emulator", true) ||
                (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
                Build.PRODUCT == "google_sdk")
    }

    private fun developmentModeCheck(ctx: Context): Boolean {
        return when {
            Build.VERSION.SDK_INT == 16 -> {
                @Suppress("DEPRECATION")
                Settings.Secure.getInt(
                    ctx.contentResolver,
                    Settings.Secure.DEVELOPMENT_SETTINGS_ENABLED,
                    0
                ) != 0
            }
            Build.VERSION.SDK_INT >= 17 -> {
                @Suppress("DEPRECATION")
                Settings.Secure.getInt(
                    ctx.contentResolver,
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                    0
                ) != 0
            }
            else -> false
        }
    }

    fun isMockLocationEnabled(ctx: Context): Boolean {
        // 1) AppOps check (best-effort)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val aom = ctx.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            try {
                if (aom != null) {
                    val mode = aom.checkOp(
                        AppOpsManager.OPSTR_MOCK_LOCATION,
                        Process.myUid(),
                        ctx.packageName
                    )
                    if (mode == AppOpsManager.MODE_ALLOWED) return true
                }
            } catch (_: Exception) { /* ignore */ }
        } else {
            // 2) Legacy (pre-M) developer setting
            @Suppress("DEPRECATION")
            try {
                val s = Settings.Secure.getString(
                    ctx.contentResolver,
                    Settings.Secure.ALLOW_MOCK_LOCATION
                )
                if (!s.isNullOrEmpty()) return true
            } catch (_: Exception) { /* ignore */ }
        }

        // 3) Heuristic: last known location flagged as mock (needs location permission)
        val hasLocationPerm =
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED

        if (hasLocationPerm) {
            val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager ?: return false
            val providers = lm.allProviders ?: emptyList()
            for (p in providers) {
                if (p == LocationManager.GPS_PROVIDER || p == LocationManager.NETWORK_PROVIDER) {
                    try {
                        val loc = lm.getLastKnownLocation(p)
                        if (loc != null && loc.isFromMockProvider) return true
                    } catch (_: SecurityException) { /* ignore */ }
                }
            }
        }
        return false
    }

    private fun isOnExternalStorage(ctx: Context): Boolean {
        val pm = ctx.packageManager ?: return false

        // Prefer getApplicationInfo for SDK 33+; safe fallback for older
        val appInfo: ApplicationInfo? = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(
                    ctx.packageName,
                    PackageManager.ApplicationInfoFlags.of(0)
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(ctx.packageName, 0)
            }
        }.getOrNull()

        if (appInfo != null) {
            val onExternal = (appInfo.flags and ApplicationInfo.FLAG_EXTERNAL_STORAGE) == ApplicationInfo.FLAG_EXTERNAL_STORAGE
            if (onExternal) return true
        }

        // Fallback by inspecting filesDir path (best-effort)
        return try {
            val path = ctx.filesDir?.absolutePath ?: return false
            when {
                path.startsWith("/data/") -> false
                path.contains("/mnt/") || path.contains("/sdcard/") -> true
                else -> false
            }
        } catch (_: Throwable) {
            false
        }
    }

    // ---- Root & hook signals (fixed) ----

    private fun isDebuggerAttached(): Boolean = Debug.isDebuggerConnected()

    private fun checkFridaProcesses(): Boolean {
        val suspicious = arrayOf(
            "frida", "frida-server", "frida-helper", "frida-agent",
            "magisk", "magiskd"
        )
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("sh", "-c", "ps -A || ps"))
            BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line!!.lowercase()
                    if (suspicious.any { token -> l.contains(token) }) return true
                }
            }
            false
        } catch (_: Exception) {
            // Treat failure as unknown, not positive
            false
        }
    }

    private fun checkSuspiciousFiles(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu",
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su"
        )
        return paths.any { p -> File(p).exists() }
    }

    private fun checkSuPaths(): Boolean {
        val env = System.getenv("PATH") ?: return false
        return env.split(':').any { p ->
            File("$p/su").let { it.exists() && it.canExecute() }
        }
    }

    private fun checkFridaLibraries(): Boolean {
        val libs = arrayOf("frida-agent", "frida-gadget", "frida")
        return try {
            File("/proc/self/maps").useLines { seq ->
                seq.any { line -> libs.any { token -> line.contains(token, ignoreCase = true) } }
            }
        } catch (_: Exception) {
            // Treat failure as unknown, not positive
            false
        }
    }

    private fun isSuperuserAppInstalled(ctx: Context): Boolean {
        val pm = ctx.packageManager ?: return false
        val apps: List<ApplicationInfo> = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
            }
        }.getOrDefault(emptyList())

        val suPkgs = setOf(
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot"
        )
        for (ai in apps) {
            val pkg = ai.packageName
            if (pkg != null && pkg in suPkgs) return true
        }
        return false
    }

    // ---- Diagnostics ----

    private data class RootSignals(
        val rootBeer: Boolean,
        val fridaLibs: Boolean,
        val fridaProcs: Boolean,
        val suspiciousFiles: Boolean,
        val suInPath: Boolean,
        val suApps: Boolean,
        val debuggerAttached: Boolean
    ) {
        fun isRootedLike(): Boolean =
            rootBeer || fridaLibs || fridaProcs || suspiciousFiles || suInPath || suApps
    }

    private fun collectRootSignals(): RootSignals {
        val rootBeer = RootBeer(context).isRooted
        return RootSignals(
            rootBeer = rootBeer,
            fridaLibs = checkFridaLibraries(),
            fridaProcs = checkFridaProcesses(),
            suspiciousFiles = checkSuspiciousFiles(),
            suInPath = checkSuPaths(),
            suApps = isSuperuserAppInstalled(context),
            debuggerAttached = isDebuggerAttached()
        )
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}
