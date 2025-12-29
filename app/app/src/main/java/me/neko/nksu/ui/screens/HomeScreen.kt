package me.neko.nksu.ui.screens

import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.material.icons.automirrored.filled.ArrowForwardIos
import me.neko.nksu.BuildConfig

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen() {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    var showInstallSheet by remember { mutableStateOf(false) }
    
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
            // 状态卡片 (MD3 风格) - 使用 onClick 自动适配圆角水波纹
            Card(
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                showInstallSheet = true
                    // TODO: 导航到安装页面
                },
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                ),
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
                    Icon(
                        imageVector = Icons.Filled.SystemUpdate,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(28.dp)
                    )
                    Column {
                        Text(
                            text = "未安装",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.error,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            text = "点击安装辅助服务",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                    Spacer(modifier = Modifier.weight(1f))
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowForwardIos,
                        contentDescription = "前往安装",
                        tint = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.6f),
                        modifier = Modifier.size(20.dp)
                    )
                }
            }

            // 设备信息卡片 - 优化版本
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
    InstallGuideSheet(
        onDismiss = { showInstallSheet = false }
    )
}

}

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
            // 标题栏
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
                Spacer(modifier = Modifier.weight(1f))
        
            }

            // 设备信息网格
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // 第一行：基本设备信息
                Row(
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    DeviceInfoItem(
                        icon = Icons.Filled.PhoneAndroid,
                        title = "设备型号",
                        value = Build.MODEL,
                        modifier = Modifier.weight(1f),
                        onCopy = onInfoCopy
                    )
                    DeviceInfoItem(
                        icon = Icons.Filled.Build,
                        title = "制造商",
                        value = Build.MANUFACTURER,
                        modifier = Modifier.weight(1f),
                        onCopy = onInfoCopy
                    )
                }

                // 第二行：系统版本信息
                Row(
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    DeviceInfoItem(
                        icon = Icons.Filled.Android,
                        title = "Android 版本",
                        value = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                        modifier = Modifier.weight(1f),
                        onCopy = onInfoCopy
                    )
                    DeviceInfoItem(
                        icon = Icons.Filled.Security,
                        title = "安全补丁",
                        value = Build.VERSION.SECURITY_PATCH,
                        modifier = Modifier.weight(1f),
                        onCopy = onInfoCopy
                    )
                }

                // 第三行：硬件信息
                Row(
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    DeviceInfoItem(
                        icon = Icons.Filled.DeviceHub,
                        title = "硬件平台",
                        value = Build.HARDWARE,
                        modifier = Modifier.weight(1f),
                        onCopy = onInfoCopy
                    )
                    DeviceInfoItem(
                        icon = Icons.Filled.Memory,
                        title = "CPU 架构",
                        value = Build.SUPPORTED_ABIS.firstOrNull() ?: "未知",
                        modifier = Modifier.weight(1f),
                        onCopy = onInfoCopy
                    )
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
        onClick = {  // 使用 onClick 自动适配圆角水波纹
          //  onCopy("$title: $value")
        },
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(16.dp)
                )
                Text(
                    text = title,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f),
                    fontWeight = FontWeight.Medium
                )
            }
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                fontWeight = FontWeight.Normal
            )
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