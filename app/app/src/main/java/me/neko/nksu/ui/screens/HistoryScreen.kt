package me.neko.nksu.ui.screens

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class AppInfo(
    val name: String,
    val packageName: String,
    val uid: Int,
    val isSystem: Boolean,
    val isLaunchable: Boolean
)

enum class FilterMode(val label: String) {
    ALL(R.string.all_app),
    LAUNCHABLE(R.string.can_launch_app),
    SYSTEM("系统应用"),
    USER("用户应用")
}

class AppViewModel(private val context: Context) : ViewModel() {

    var allApps by mutableStateOf<List<AppInfo>>(emptyList())
        private set

    var isLoaded by mutableStateOf(false)
        private set

    suspend fun loadApps() {
        if (isLoaded) return

        val pm = context.packageManager

        withContext(Dispatchers.IO) {
            val installed = pm.getInstalledPackages(PackageManager.GET_META_DATA)
                .mapNotNull { pkg ->
                    pkg.applicationInfo?.let { ai ->
                        AppInfo(
                            name = ai.loadLabel(pm).toString(),
                            packageName = pkg.packageName,
                            uid = ai.uid,
                            isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                            isLaunchable = pm.getLaunchIntentForPackage(pkg.packageName) != null
                        )
                    }
                }
                .sortedBy { it.name.lowercase() }

            allApps = installed
            isLoaded = true
        }
    }
}


// ----------------------------
// ViewModel Factory
// ----------------------------

class AppViewModelFactory(
    private val context: Context
) : ViewModelProvider.Factory {

    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return AppViewModel(context) as T
    }
}


// ----------------------------
// Composable 页面
// ----------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen() {

    // 正确：在 Composable 内读取 context
    val context = LocalContext.current.applicationContext

    val viewModel: AppViewModel = viewModel(
        factory = AppViewModelFactory(context)
    )

    var apps by remember { mutableStateOf<List<AppInfo>>(emptyList()) }
    var filterMode by remember { mutableStateOf(FilterMode.USER) }
    var searchQuery by remember { mutableStateOf("") }
    var menuExpanded by remember { mutableStateOf(false) }
    var isSearching by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        viewModel.loadApps()
    }

    LaunchedEffect(viewModel.allApps, filterMode, searchQuery) {
        val all = viewModel.allApps
        if (all.isNotEmpty()) {
            apps = all.filter { app ->
                val passFilter = when (filterMode) {
                    FilterMode.ALL -> true
                    FilterMode.LAUNCHABLE -> app.isLaunchable
                    FilterMode.SYSTEM -> app.isSystem
                    FilterMode.USER -> !app.isSystem
                }

                val q = searchQuery.trim().lowercase()
                val passSearch = q.isEmpty() ||
                    app.name.lowercase().contains(q) ||
                    app.packageName.lowercase().contains(q)

                passFilter && passSearch
            }
        }
    }

    val isLoading = !viewModel.isLoaded

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    if (isSearching) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            placeholder = { Text("搜索应用名或包名") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                    } else {
                        Text(filterMode.label)
                    }
                },
                navigationIcon = {
                    if (isSearching) {
                        IconButton(onClick = {
                            isSearching = false
                            searchQuery = ""
                        }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "关闭搜索")
                        }
                    }
                },
                actions = {
                    if (!isSearching) {
                        IconButton(onClick = { isSearching = true }) {
                            Icon(Icons.Default.Search, contentDescription = "搜索")
                        }
                    }

                    Box {
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(Icons.Default.FilterList, contentDescription = "过滤")
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false }
                        ) {
                            FilterMode.values().forEach { mode ->
                                DropdownMenuItem(
                                    text = { Text(mode.label) },
                                    onClick = {
                                        filterMode = mode
                                        menuExpanded = false
                                    }
                                )
                            }
                        }
                    }
                }
            )
        }
    ) { innerPadding ->

        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentAlignment = Alignment.Center
        ) {

            when {
                isLoading -> CircularProgressIndicator()

                apps.isEmpty() -> Text("没有找到应用")

                else -> {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(vertical = 8.dp)
                    ) {
                        items(apps) { app ->
                            ListItem(
                                headlineContent = { Text(app.name) },
                                supportingContent = {
                                    Column {
                                        Text(app.packageName)
                                        Text("UID: ${app.uid}")
                                    }
                                },
                                leadingContent = {
                                    val localContext = LocalContext.current
                                    var iconBitmap by remember(app.packageName) {
                                        mutableStateOf<ImageBitmap?>(null)
                                    }
                                    var isIconLoading by remember(app.packageName) {
                                        mutableStateOf(true)
                                    }

                                    LaunchedEffect(app.packageName) {
                                        withContext(Dispatchers.IO) {
                                            try {
                                                val drawable =
                                                    localContext.packageManager.getApplicationIcon(app.packageName)
                                                iconBitmap = drawable.toBitmap().asImageBitmap()
                                            } catch (_: Exception) {
                                            } finally {
                                                isIconLoading = false
                                            }
                                        }
                                    }

                                    Box(
                                        modifier = Modifier.size(40.dp),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        when {
                                            isIconLoading -> CircularProgressIndicator(Modifier.size(20.dp))
                                            iconBitmap != null -> Image(
                                                bitmap = iconBitmap!!,
                                                contentDescription = app.name,
                                                modifier = Modifier.size(40.dp)
                                            )
                                            else -> Icon(
                                                Icons.Default.Android,
                                                contentDescription = app.name,
                                                modifier = Modifier.size(40.dp)
                                            )
                                        }
                                    }
                                },
                                modifier = Modifier.clickable {
                                    // TODO: 点击后的行为
                                }
                            )
                            HorizontalDivider()
                        }
                    }
                }
            }
        }
    }
}


@Preview(showBackground = true)
@Composable
fun PreviewHistoryScreen() {
    HistoryScreen()
}