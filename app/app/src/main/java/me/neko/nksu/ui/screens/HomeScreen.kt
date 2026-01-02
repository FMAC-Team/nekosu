package me.neko.nksu.ui.screens

import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForwardIos
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.neko.nksu.KeyUtils
import me.neko.nksu.Native

enum class InstallStatus {
    CHECKING,  
    INSTALLED,   
    NOT_INSTALLED 
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen() {
private const val B32_SECRET = "P2U6KVKZKSFKXGXO7XN6S6X62X6M6NE7"
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    
    var showInstallSheet by remember { mutableStateOf(false) }
    var installStatus by remember { mutableStateOf(InstallStatus.CHECKING) }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
           val keypath = KeyUtils.getKeyFilePath(context)
            if (key != null) {
                val token = KeyUtils.getTotpToken(B32_SECRET)
                val result = Native().authenticate(keypath, token)
                installStatus = if (result == 0) InstallStatus.INSTALLED else InstallStatus.NOT_INSTALLED
            } else {
                installStatus = InstallStatus.NOT_INSTALLED
            }
        }
    }
    
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(
                        text = "nekosu",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
           
            StatusCard(
                status = installStatus,
                onClick = {
                    if (installStatus != InstallStatus.INSTALLED) {
                        showInstallSheet = true
                    } else {
                        Toast.makeText(context, "服务运行正常", Toast.LENGTH_SHORT).show()
                    }
                }
            )

            DeviceInfoCard(
                modifier = Modifier.fillMaxWidth(),
                onInfoCopy = { info ->
                    clipboardManager.setText(AnnotatedString(info))
                    Toast.makeText(context, "已复制到剪贴板", Toast.LENGTH_SHORT).show()
                }
            )
        }
    }
    
    if (showInstallSheet) {
         // TODO: 这里放入你的 InstallGuideSheet
         // InstallGuideSheet(onDismiss = { showInstallSheet = false })
    }
}

@Composable
fun StatusCard(
    status: InstallStatus,
    onClick: () -> Unit
) {
    val (containerColor, contentColor, iconVector, titleText, subText) = when (status) {
        InstallStatus.INSTALLED -> StatusConfig(
            MaterialTheme.colorScheme.primaryContainer,
            MaterialTheme.colorScheme.primary,
            Icons.Filled.CheckCircle,
            "已激活",
            "辅助服务正在运行"
        )
        InstallStatus.NOT_INSTALLED -> StatusConfig(
            MaterialTheme.colorScheme.errorContainer,
            MaterialTheme.colorScheme.error,
            Icons.Filled.SystemUpdate,
            "未安装",
            "点击安装辅助服务"
        )
        InstallStatus.CHECKING -> StatusConfig(
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.onSurfaceVariant,
            Icons.Filled.Refresh,
            "检查中...",
            "正在验证服务状态"
        )
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        colors = CardDefaults.cardColors(containerColor = containerColor),
        shape = RoundedCornerShape(20.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            if (status == InstallStatus.CHECKING) {
                CircularProgressIndicator(
                    modifier = Modifier.size(28.dp),
                    color = contentColor,
                    strokeWidth = 3.dp
                )
            } else {
                Icon(
                    imageVector = iconVector,
                    contentDescription = null,
                    tint = contentColor,
                    modifier = Modifier.size(28.dp)
                )
            }
            
            Column {
                Text(
                    text = titleText,
                    style = MaterialTheme.typography.titleMedium,
                    color = contentColor,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = subText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = contentColor.copy(alpha = 0.8f)
                )
            }
            Spacer(modifier = Modifier.weight(1f))
            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForwardIos,
                contentDescription = "操作",
                tint = contentColor.copy(alpha = 0.6f),
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

data class StatusConfig(
    val containerColor: androidx.compose.ui.graphics.Color,
    val contentColor: androidx.compose.ui.graphics.Color,
    val icon: ImageVector,
    val title: String,
    val subtitle: String
)

@Composable
fun DeviceInfoCard(
    modifier: Modifier = Modifier,
    onInfoCopy: (String) -> Unit = {}
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.PhoneAndroid,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Text(
                    text = "设备信息",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    DeviceInfoItem(Icons.Filled.PhoneAndroid, "设备型号", Build.MODEL, Modifier.weight(1f), onInfoCopy)
                    DeviceInfoItem(Icons.Filled.Build, "制造商", Build.MANUFACTURER, Modifier.weight(1f), onInfoCopy)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    DeviceInfoItem(Icons.Filled.Android, "Android 版本", "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})", Modifier.weight(1f), onInfoCopy)
                    DeviceInfoItem(Icons.Filled.Security, "安全补丁", Build.VERSION.SECURITY_PATCH, Modifier.weight(1f), onInfoCopy)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    DeviceInfoItem(Icons.Filled.DeviceHub, "硬件平台", Build.HARDWARE, Modifier.weight(1f), onInfoCopy)
                    DeviceInfoItem(Icons.Filled.Memory, "CPU 架构", Build.SUPPORTED_ABIS.firstOrNull() ?: "未知", Modifier.weight(1f), onInfoCopy)
                }
            }
        }
    }
}

@Composable
fun DeviceInfoItem(
    icon: ImageVector,
    title: String,
    value: String,
    modifier: Modifier = Modifier,
    onCopy: (String) -> Unit = {}
) {
    Card(
        modifier = modifier,
        onClick = { onCopy("$title: $value") },
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(imageVector = icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(16.dp))
                Text(text = title, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f))
            }
            Text(text = value, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}


@Preview(showBackground = true)
@Composable
fun HomeScreenPreview() {
    MaterialTheme {
        HomeScreen()
    }
}

@Preview(showBackground = true)
@Composable
fun DeviceInfoCardPreview() {
    MaterialTheme {
        DeviceInfoCard(
            modifier = Modifier.padding(16.dp)
        )
    }
}