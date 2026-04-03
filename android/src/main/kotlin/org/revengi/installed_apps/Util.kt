package org.revengi.installed_apps

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build.VERSION.SDK_INT
import android.os.Build.VERSION_CODES.P
import android.os.Build.VERSION_CODES.LOLLIPOP
import android.os.Build.VERSION_CODES.R
import android.util.Log
import com.android.apksig.ApkVerifier
import java.io.File

class Util {
    companion object {
        fun convertAppToMap(
            packageManager: PackageManager,
            app: ApplicationInfo,
            withIcon: Boolean,
        ): HashMap<String, Any?> {
            val map = HashMap<String, Any?>()
            map["name"] = packageManager.getApplicationLabel(app)
            if (SDK_INT >= R) {
                map["installer"] =
                    packageManager.getInstallSourceInfo(app.packageName).installingPackageName
            } else {
                map["installer"] =
                    packageManager.getInstallerPackageName(app.packageName)
            }
            map["package_name"] = app.packageName
            map["icon"] =
                if (withIcon) DrawableUtil.drawableToByteArray(app.loadIcon(packageManager))
                else ByteArray(0)
            val packageInfo = packageManager.getPackageInfo(app.packageName, 0)
            map["version_name"] = packageInfo.versionName
            map["version_code"] = getVersionCode(packageInfo)
            map["installed_timestamp"] = packageInfo.firstInstallTime
            map["update_timestamp"] = packageInfo.lastUpdateTime
            // Add package size in bytes
            val packageFile = File(app.publicSourceDir ?: app.sourceDir)
            map["package_size"] = if (packageFile.exists()) packageFile.length() else 0L
            map["apk_path"] = app.sourceDir
            if (SDK_INT >= LOLLIPOP) map["split_source_dirs"] = app.splitSourceDirs?.toList()
            map["app_uid"] = app.uid
            map["data_dir"] = app.dataDir
            return map
        }

        fun getPackageManager(context: Context): PackageManager {
            return context.packageManager
        }

        @Suppress("DEPRECATION")
        private fun getVersionCode(packageInfo: PackageInfo): Long {
            return if (SDK_INT < P) packageInfo.versionCode.toLong()
            else packageInfo.longVersionCode
        }
    }
}