package org.revengi.installed_apps

import android.content.Context
import android.content.Intent
import android.content.Intent.FLAG_ACTIVITY_NEW_TASK
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS
import android.util.Base64
import android.widget.Toast
import android.widget.Toast.LENGTH_LONG
import android.widget.Toast.LENGTH_SHORT
import com.android.apksig.ApkVerifier
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import org.revengi.installed_apps.Util.Companion.convertAppToMap
import org.revengi.installed_apps.Util.Companion.getPackageManager
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.Locale.ENGLISH
import java.util.zip.CRC32
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Arrays
import java.util.zip.ZipFile


class InstalledAppsPlugin : MethodCallHandler, FlutterPlugin, ActivityAware {

    private lateinit var channel: MethodChannel
    private var context: Context? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "installed_apps")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onAttachedToActivity(activityPluginBinding: ActivityPluginBinding) {
        context = activityPluginBinding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {}

    override fun onReattachedToActivityForConfigChanges(activityPluginBinding: ActivityPluginBinding) {
        context = activityPluginBinding.activity
    }

    override fun onDetachedFromActivity() {}

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        if (context == null) {
            result.error("ERROR", "Context is null", null)
            return
        }
        when (call.method) {
            "getInstalledApps" -> {
                val includeSystemApps = call.argument<Boolean>("exclude_system_apps") ?: true
                val withIcon = call.argument<Boolean>("with_icon") ?: false
                val packageNamePrefix = call.argument<String>("package_name_prefix") ?: ""
                val platformTypeName = call.argument<String>("platform_type") ?: ""

                Thread {
                    val apps: List<Map<String, Any?>> =
                        getInstalledApps(
                            includeSystemApps,
                            withIcon,
                            packageNamePrefix,
                            PlatformType.fromString(platformTypeName)
                        )
                    result.success(apps)
                }.start()
            }

            "startApp" -> {
                val packageName = call.argument<String>("package_name")
                result.success(startApp(packageName))
            }

            "openSettings" -> {
                val packageName = call.argument<String>("package_name")
                openSettings(packageName)
            }

            "toast" -> {
                val message = call.argument<String>("message") ?: ""
                val short = call.argument<Boolean>("short_length") ?: true
                toast(message, short)
            }

            "getAppInfo" -> {
                val packageName = call.argument<String>("package_name") ?: ""
                val platformTypeName = call.argument<String>("platform_type") ?: ""
                val platformType = PlatformType.fromString(platformTypeName)
                result.success(getAppInfo(getPackageManager(context!!), packageName, platformType))
            }

            "isSystemApp" -> {
                val packageName = call.argument<String>("package_name") ?: ""
                result.success(isSystemApp(getPackageManager(context!!), packageName))
            }

            "uninstallApp" -> {
                val packageName = call.argument<String>("package_name") ?: ""
                result.success(uninstallApp(packageName))
            }

            "isAppInstalled" -> {
                val packageName = call.argument<String>("package_name") ?: ""
                result.success(isAppInstalled(packageName))
            }

            "getSignatureSchemes" -> {
                Thread {
                    val apkPath = call.argument<String>("apk_path") ?: ""
                    result.success(getSignatureSchemes(apkPath))
                }.start()
            }

            "extractSignatureInfo" -> {
                Thread {
                    val apkPath = call.argument<String>("apk_path") ?: ""
                    result.success(extractSignatureInfo(apkPath))
                }.start()
            }

            else -> result.notImplemented()
        }
    }

    private fun getInstalledApps(
        excludeSystemApps: Boolean,
        withIcon: Boolean,
        packageNamePrefix: String,
        platformType: PlatformType?
    ): List<Map<String, Any?>> {
        val packageManager = getPackageManager(context!!)
        var installedApps = packageManager.getInstalledApplications(0)
        if (excludeSystemApps)
            installedApps =
                installedApps.filter { app -> !isSystemApp(packageManager, app.packageName) }
        if (packageNamePrefix.isNotEmpty())
            installedApps = installedApps.filter { app ->
                app.packageName.startsWith(
                    packageNamePrefix.lowercase(ENGLISH)
                )
            }
        return installedApps.map { app ->
            convertAppToMap(
                packageManager,
                app,
                withIcon,
                platformType
            )
        }
    }

    private fun startApp(packageName: String?): Boolean {
        if (packageName.isNullOrBlank()) return false
        return try {
            val launchIntent = getPackageManager(context!!).getLaunchIntentForPackage(packageName)
            context!!.startActivity(launchIntent)
            true
        } catch (e: Exception) {
            print(e)
            false
        }
    }

    private fun toast(text: String, short: Boolean) {
        Toast.makeText(context!!, text, if (short) LENGTH_SHORT else LENGTH_LONG)
            .show()
    }

    private fun isSystemApp(packageManager: PackageManager, packageName: String): Boolean {
        return try {
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun openSettings(packageName: String?) {
        if (!isAppInstalled(packageName)) {
            print("App $packageName is not installed on this device.")
            return;
        }
        val intent = Intent().apply {
            flags = FLAG_ACTIVITY_NEW_TASK
            action = ACTION_APPLICATION_DETAILS_SETTINGS
            data = Uri.fromParts("package", packageName, null)
        }
        context!!.startActivity(intent)
    }

    private fun getAppInfo(
        packageManager: PackageManager,
        packageName: String,
        platformType: PlatformType?
    ): Map<String, Any?>? {
        var installedApps = packageManager.getInstalledApplications(0)
        installedApps = installedApps.filter { app -> app.packageName == packageName }
        return if (installedApps.isEmpty()) null
        else convertAppToMap(packageManager, installedApps[0], true, platformType)
    }

    private fun uninstallApp(packageName: String): Boolean {
        return try {
            val intent = Intent(Intent.ACTION_DELETE)
            intent.data = Uri.parse("package:$packageName")
            context!!.startActivity(intent)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun isAppInstalled(packageName: String?): Boolean {
        val packageManager: PackageManager = context!!.packageManager
        return try {
            packageManager.getPackageInfo(packageName ?: "", PackageManager.GET_ACTIVITIES)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    //  https://github.com/MuntashirAkon/AppManager/blob/bdb29362606d7bf668d7e9c088cd0f172ef8abab/app/src/main/java/io/github/muntashirakon/AppManager/utils/PackageUtils.java#L830
    private fun getSignatureSchemes(apkPath: String): List<String> {
        val verifier = ApkVerifier.Builder(File(apkPath)).build()
        val result: ApkVerifier.Result = verifier.verify()
        val schemes = mutableListOf<String>()

        if (result.isVerifiedUsingV1Scheme) schemes.add("V1")
        if (result.isVerifiedUsingV2Scheme) schemes.add("V2")
        if (result.isVerifiedUsingV3Scheme) schemes.add("V3")
        if (result.isVerifiedUsingV31Scheme) schemes.add("V3.1")
        if (result.isVerifiedUsingV4Scheme) schemes.add("V4")

        return schemes
    }

    private fun getSignatureSchemes(result: ApkVerifier.Result): List<String> {
        val schemes = mutableListOf<String>()

        if (result.isVerifiedUsingV1Scheme) schemes.add("V1")
        if (result.isVerifiedUsingV2Scheme) schemes.add("V2")
        if (result.isVerifiedUsingV3Scheme) schemes.add("V3")
        if (result.isVerifiedUsingV31Scheme) schemes.add("V3.1")
        if (result.isVerifiedUsingV4Scheme) schemes.add("V4")

        return schemes
    }

    private fun extractSignatureInfo(apkPath: String): HashMap<String, Any?> {
        val resultMap = HashMap<String, Any?>()
        val digs = HashMap<String, String>()
        val issuer = StringBuilder()
        val algorithm = StringBuilder()
        val createDate = StringBuilder()
        val expireDate = StringBuilder()
        var baseData: String? = null
        var rawData: ByteArray? = null

        try {
            fun processCert(cert: X509Certificate?) {
                if (cert == null) {
                    val apkFile = File(apkPath)
                    if (apkFile.exists()) {  
                        ZipFile(apkFile).use { zip ->
                            val entry = zip.entries().asSequence().find {
                                it.name.startsWith("META-INF/") &&
                                        (it.name.endsWith(".RSA", true) || it.name.endsWith(
                                            ".DSA",
                                            true
                                        ))
                            }
                            if (entry != null) {
                                zip.getInputStream(entry).use { certStream ->
                                    val cf = CertificateFactory.getInstance("X.509")
                                    val certs = cf.generateCertificates(certStream)
                                    (certs.firstOrNull() as? X509Certificate)?.let { processCert(it) }
                                }
                            }
                        }
                    }
                    return
                }
                try {
                    issuer.append(cert.issuerX500Principal.name)
                    algorithm.append(cert.sigAlgName)
                    createDate.append(cert.notBefore)
                    expireDate.append(cert.notAfter)

                    val digests = arrayOf("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512")
                    for (algo in digests) {
                        val digest = try {
                            MessageDigest.getInstance(algo).digest(cert.encoded)
                        } catch (e: NoSuchAlgorithmException) {
                            ByteArray(0)
                        }
                        digs[algo] = digest.joinToString("") { "%02x".format(it) }
                    }

                    val crc32 = CRC32().apply { update(cert.encoded) }.value
                    val crcBytes = ByteArray(8) { i -> ((crc32 shr (8 * (7 - i))) and 0xFF).toByte() }
                    digs["CRC32"] = crcBytes.joinToString("") { "%02x".format(it) }
                    digs["HASH"] = Arrays.hashCode(cert.encoded).toString()
                    baseData = Base64.encode(cert.encoded, Base64.DEFAULT)
                        .toString(StandardCharsets.UTF_8)
                    rawData = cert.encoded
                } catch (e: CertificateEncodingException) {
                    e.printStackTrace()
                }
            }

            val verifier = ApkVerifier.Builder(File(apkPath)).build()
            val result = verifier.verify()

            resultMap["verified"] = result.isVerified
            resultMap["errors"] = result.errors.map { it.toString() }
            resultMap["warnings"] = result.warnings.map { it.toString() }

            val signers = when {
                result.signerCertificates.isNotEmpty() -> result.signerCertificates.map { it }
                result.v1SchemeSigners.isNotEmpty() -> result.v1SchemeSigners.map { it.certificate }
                result.v2SchemeSigners.isNotEmpty() -> result.v2SchemeSigners.map { it.certificate }
                result.v3SchemeSigners.isNotEmpty() -> result.v3SchemeSigners.map { it.certificate }
                result.v31SchemeSigners.isNotEmpty() -> result.v31SchemeSigners.map { it.certificate }
                result.v4SchemeSigners.isNotEmpty() -> result.v4SchemeSigners.map { it.certificate }
                else -> emptyList()
            }

            signers.forEach { processCert(it) }

            resultMap["issuer"] = issuer.toString()
            resultMap["algorithm"] = algorithm.toString()
            resultMap["digests"] = digs
            resultMap["schemes"] = getSignatureSchemes(result)
            resultMap["create_date"] = createDate.toString()
            resultMap["expire_date"] = expireDate.toString()
            resultMap["base64_data"] = baseData
            resultMap["rawData"] = rawData
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return resultMap
    }

}
