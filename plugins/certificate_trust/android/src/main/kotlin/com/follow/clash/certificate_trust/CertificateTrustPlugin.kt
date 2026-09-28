package com.follow.clash.certificate_trust

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.security.KeyChain
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry.ActivityResultListener
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class CertificateTrustPlugin :
    FlutterPlugin,
    MethodChannel.MethodCallHandler,
    ActivityAware {
    private lateinit var channel: MethodChannel
    private var context: Context? = null
    private var activity: Activity? = null
    private var activityBinding: ActivityPluginBinding? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var pendingInstall: PendingInstall? = null

    private data class CertificateInput(
        val der: ByteArray,
        val fingerprint: String,
    )

    private data class PendingInstall(
        val input: CertificateInput,
        val result: MethodChannel.Result,
    )

    companion object {
        private const val CHANNEL_NAME = "certificate_trust"
        private const val METHOD_CHECK = "checkTrust"
        private const val METHOD_INSTALL = "requestInstall"
        private const val METHOD_SETTINGS = "openTrustSettings"
        private const val REQUEST_INSTALL = 39071
        private const val MAX_CERTIFICATE_BYTES = 64 * 1024
        private const val DEFAULT_NAME = "FlClash Local Inspection CA"
        private const val INSTALL_TRUST_POLL_ATTEMPTS = 8
        private const val INSTALL_TRUST_POLL_DELAY_MS = 125L
    }

    private val activityResultListener = ActivityResultListener { requestCode, resultCode, _ ->
        if (requestCode != REQUEST_INSTALL) {
            return@ActivityResultListener false
        }
        val pending = pendingInstall ?: return@ActivityResultListener false
        pendingInstall = null
        if (resultCode != Activity.RESULT_OK) {
            pending.result.success(mapOf("outcome" to "cancelled"))
            return@ActivityResultListener true
        }
        executor.execute {
            val trustStatus = awaitInstalledTrust(pending.input)
            mainHandler.post {
                pending.result.success(
                    mapOf(
                        "outcome" to if (trustStatus["state"] == "trusted") {
                            "installed"
                        } else {
                            "settingsOpened"
                        },
                        "trustStatus" to trustStatus,
                    ),
                )
            }
        }
        true
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        completePendingInstall("PLUGIN_DETACHED")
        context = null
        executor.shutdownNow()
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding?.removeActivityResultListener(activityResultListener)
        activityBinding = binding
        activity = binding.activity
        binding.addActivityResultListener(activityResultListener)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        detachActivity(cancelInstall = false)
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        onAttachedToActivity(binding)
    }

    override fun onDetachedFromActivity() {
        detachActivity(cancelInstall = true)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            METHOD_CHECK -> runBackground(result) {
                checkTrust(parseInput(call))
            }
            METHOD_INSTALL -> requestInstall(call, result)
            METHOD_SETTINGS -> result.success(openTrustSettings())
            else -> result.notImplemented()
        }
    }

    private fun requestInstall(call: MethodCall, result: MethodChannel.Result) {
        val input = try {
            parseInput(call)
        } catch (error: IllegalArgumentException) {
            result.error("INVALID_CERTIFICATE", error.message, null)
            return
        }
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("ACTIVITY_UNAVAILABLE", "Activity not available", null)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val opened = openTrustSettings()
            result.success(
                mapOf(
                    "outcome" to if (opened) "settingsOpened" else "failed",
                    "errorCode" to if (opened) "" else "SETTINGS_UNAVAILABLE",
                ),
            )
            return
        }
        if (pendingInstall != null) {
            result.error("IN_PROGRESS", "A certificate installation is already active", null)
            return
        }
        val displayName = call.argument<String>("displayName")
            ?.take(128)
            ?.ifBlank { DEFAULT_NAME }
            ?: DEFAULT_NAME
        val intent = KeyChain.createInstallIntent().apply {
            putExtra(KeyChain.EXTRA_CERTIFICATE, input.der)
            putExtra(KeyChain.EXTRA_NAME, displayName)
        }
        pendingInstall = PendingInstall(input, result)
        try {
            currentActivity.startActivityForResult(intent, REQUEST_INSTALL)
        } catch (error: RuntimeException) {
            pendingInstall = null
            result.error("INSTALL_UNAVAILABLE", error.javaClass.simpleName, null)
        }
    }

    private fun openTrustSettings(): Boolean {
        val target = activity ?: context ?: return false
        val intent = Intent(Settings.ACTION_SECURITY_SETTINGS).apply {
            if (target !is Activity) {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }
        return try {
            target.startActivity(intent)
            true
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun awaitInstalledTrust(input: CertificateInput): Map<String, Any> {
        var status = checkTrust(input)
        repeat(INSTALL_TRUST_POLL_ATTEMPTS - 1) {
            if (status["state"] == "trusted") {
                return status
            }
            try {
                Thread.sleep(INSTALL_TRUST_POLL_DELAY_MS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return status
            }
            status = checkTrust(input)
        }
        return status
    }

    private fun checkTrust(input: CertificateInput): Map<String, Any> {
        var user = false
        var system = false
        var unknown = false
        return try {
            val store = KeyStore.getInstance("AndroidCAStore")
            store.load(null)
            val aliases = store.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                val candidate = store.getCertificate(alias) ?: continue
                val candidateFingerprint = fingerprint(candidate.encoded)
                if (candidateFingerprint != input.fingerprint) {
                    continue
                }
                when {
                    alias.startsWith("user:", ignoreCase = true) -> user = true
                    alias.startsWith("system:", ignoreCase = true) -> system = true
                    else -> unknown = true
                }
            }
            statusMap(
                state = if (user || system || unknown) "trusted" else "notTrusted",
                store = when {
                    user && system -> "both"
                    user -> "user"
                    system -> "system"
                    unknown -> "unknown"
                    else -> "none"
                },
                fingerprint = input.fingerprint,
            )
        } catch (error: Exception) {
            statusMap(
                state = "unavailable",
                store = "unknown",
                fingerprint = input.fingerprint,
                errorCode = error.javaClass.simpleName,
            )
        }
    }

    private fun statusMap(
        state: String,
        store: String,
        fingerprint: String,
        errorCode: String = "",
    ): Map<String, Any> = mapOf(
        "platform" to "android",
        "state" to state,
        "store" to store,
        "installMode" to if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            "prompt"
        } else {
            "settings"
        },
        "verificationSupported" to true,
        "fingerprintSha256" to fingerprint,
        "platformVersion" to Build.VERSION.SDK_INT,
        "limitations" to listOf(
            "android-user-ca-opt-in",
            "certificate-pinning-may-block",
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                "manual-settings-install-required"
            } else {
                "user-confirmation-required"
            },
        ),
        "errorCode" to errorCode,
        "checkedAtEpochMs" to System.currentTimeMillis(),
    )

    private fun parseInput(call: MethodCall): CertificateInput {
        val der = call.argument<ByteArray>("certificateDer")
            ?: throw IllegalArgumentException("certificateDer is required")
        if (der.isEmpty() || der.size > MAX_CERTIFICATE_BYTES) {
            throw IllegalArgumentException("certificateDer exceeds its supported bounds")
        }
        val expected = canonicalFingerprint(
            call.argument<String>("fingerprintSha256")
                ?: throw IllegalArgumentException("fingerprintSha256 is required"),
        )
        val certificateStream = ByteArrayInputStream(der)
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(certificateStream) as? X509Certificate
            ?: throw IllegalArgumentException("certificateDer is not an X.509 certificate")
        if (certificateStream.available() != 0) {
            throw IllegalArgumentException("certificateDer contains trailing data")
        }
        val actual = fingerprint(certificate.encoded)
        if (actual != expected) {
            throw IllegalArgumentException("certificate fingerprint does not match")
        }
        try {
            certificate.checkValidity()
            if (certificate.subjectX500Principal != certificate.issuerX500Principal) {
                throw IllegalArgumentException("certificate is not self-issued")
            }
            certificate.verify(certificate.publicKey)
        } catch (error: IllegalArgumentException) {
            throw error
        } catch (error: Exception) {
            throw IllegalArgumentException("certificate is not a valid self-signed authority", error)
        }
        val keyUsage = certificate.keyUsage
        if (
            certificate.basicConstraints != 0 ||
            keyUsage == null ||
            keyUsage.size <= 5 ||
            !keyUsage[5]
        ) {
            throw IllegalArgumentException("certificate is not a constrained signing authority")
        }
        return CertificateInput(der.copyOf(), actual)
    }

    private fun canonicalFingerprint(value: String): String {
        val compact = value.replace(":", "").uppercase()
        if (compact.length != 64 || compact.any { it !in "0123456789ABCDEF" }) {
            throw IllegalArgumentException("invalid SHA-256 fingerprint")
        }
        return compact.chunked(2).joinToString(":")
    }

    private fun fingerprint(value: ByteArray): String = MessageDigest
        .getInstance("SHA-256")
        .digest(value)
        .joinToString(":") { byte -> "%02X".format(byte.toInt() and 0xFF) }

    private fun runBackground(
        result: MethodChannel.Result,
        action: () -> Map<String, Any>,
    ) {
        executor.execute {
            val value = try {
                action()
            } catch (error: IllegalArgumentException) {
                mainHandler.post {
                    result.error("INVALID_CERTIFICATE", error.message, null)
                }
                return@execute
            } catch (error: Exception) {
                mainHandler.post {
                    result.error("TRUST_CHECK_FAILED", error.javaClass.simpleName, null)
                }
                return@execute
            }
            mainHandler.post { result.success(value) }
        }
    }

    private fun detachActivity(cancelInstall: Boolean) {
        activityBinding?.removeActivityResultListener(activityResultListener)
        activityBinding = null
        activity = null
        if (cancelInstall) {
            completePendingInstall("ACTIVITY_DETACHED")
        }
    }

    private fun completePendingInstall(code: String) {
        val pending = pendingInstall ?: return
        pendingInstall = null
        pending.result.success(
            mapOf(
                "outcome" to "cancelled",
                "errorCode" to code,
            ),
        )
    }
}
