package me.neko.nksu.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import me.neko.nksu.KeyUtils
import me.neko.nksu.R
import me.neko.nksu.ui.util.BottomNavItem
import me.neko.nksu.ui.util.CheckUpdate

@Composable
fun BottomNavigationBar(navController: NavController) {
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    val topCornerRadius = 24.dp
    val navBarHeight = 110.dp

    NavigationBar(
        modifier =
        Modifier
            .clip(RoundedCornerShape(topStart = topCornerRadius, topEnd = topCornerRadius))
            .then(Modifier.height(navBarHeight))
    ) {
        BottomNavItem.Companion.items.forEach { item ->
            val selected = currentRoute == item.route
            NavigationBarItem(
                icon = {
                    Icon(
                        imageVector = if (selected) {
                            item.selectedIcon
                        } else {
                            item.unselectedIcon
                        },
                        contentDescription = item.title
                    )
                },
                label = {
                    if (selected) {
                        Text(text = item.title)
                    }
                },
                selected = selected,
                onClick = {
                    navController.navigate(item.route) {
                        launchSingleTop = true
                        restoreState = true
                        popUpTo(navController.graph.findStartDestination().id) {
                            saveState = true
                        }
                    }
                }
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen() {
    val navController = rememberNavController()
    val context = LocalContext.current
    val isKeyMissingInitial = !KeyUtils.checkKeyExists(context)
    var showDialog by remember { mutableStateOf(isKeyMissingInitial) }

    Scaffold(
        bottomBar = { BottomNavigationBar(navController) },
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = BottomNavItem.Home.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(
                route = BottomNavItem.Home.route,
                enterTransition = { fadeIn(animationSpec = tween(300)) },
                exitTransition = { fadeOut(animationSpec = tween(300)) },
                popEnterTransition = { fadeIn(animationSpec = tween(300)) },
                popExitTransition = { fadeOut(animationSpec = tween(300)) }
            ) { HomeScreen() }
            composable(
                route = BottomNavItem.History.route,
                enterTransition = { fadeIn(animationSpec = tween(300)) },
                exitTransition = { fadeOut(animationSpec = tween(300)) },
                popEnterTransition = { fadeIn(animationSpec = tween(300)) },
                popExitTransition = { fadeOut(animationSpec = tween(300)) }
            ) { HistoryScreen() }
            composable(
                route = BottomNavItem.Settings.route,
                enterTransition = { fadeIn(animationSpec = tween(300)) },
                exitTransition = { fadeOut(animationSpec = tween(300)) },
                popEnterTransition = { fadeIn(animationSpec = tween(300)) },
                popExitTransition = { fadeOut(animationSpec = tween(300)) }
            ) { SettingsScreen(navController) }
            composable(
                route = "about",
                enterTransition = { fadeIn(animationSpec = tween(300)) },
                exitTransition = { fadeOut(animationSpec = tween(300)) },
                popEnterTransition = { fadeIn(animationSpec = tween(300)) },
                popExitTransition = { fadeOut(animationSpec = tween(300)) }
            ) { AboutScreen(navController) }
            composable(
                route = "open_source",
                enterTransition = { fadeIn(animationSpec = tween(300)) },
                exitTransition = { fadeOut(animationSpec = tween(300)) },
                popEnterTransition = { fadeIn(animationSpec = tween(300)) },
                popExitTransition = { fadeOut(animationSpec = tween(300)) }
            ) { OpenSourceScreen(navController) }
        }

        val owner = "aqnya"
        val repo = "nekosu"
        CheckUpdate(owner = owner, repo = repo)
        if (showDialog) {
            KeyInputDialog(
                show = showDialog,
                onDismiss = { showDialog = false }
            )
        }
    }
}

@Composable
fun KeyInputDialog(show: Boolean, onDismiss: () -> Unit) {
    val context = LocalContext.current
    var inputText by remember { mutableStateOf("") }
    var errorType by remember { mutableIntStateOf(0) } // 0-none, 1-empty, 2-invalid
    val scrollState = rememberScrollState()

    AnimatedVisibility(
        visible = show,
        enter =
        fadeIn(animationSpec = tween(250)) +
            scaleIn(initialScale = 0.8f, animationSpec = tween(250)),
        exit =
        fadeOut(animationSpec = tween(200)) +
            scaleOut(targetScale = 0.8f, animationSpec = tween(200))
    ) {
        AlertDialog(
            onDismissRequest = { onDismiss() },
            title = {
                Text(
                    text = stringResource(R.string.dialog_key_set),
                    style = TextStyle(
                        fontSize = 16.sp
                    )
                )
            },
            text = {
                Column(
                    modifier =
                    Modifier
                        .verticalScroll(scrollState)
                        .fillMaxWidth()
                ) {
                    Text(stringResource(R.string.dialog_key_please_input))
                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = inputText,
                        onValueChange = {
                            inputText = it
                            errorType = 0
                        },
                        label = { Text("ECC Key (PEM/Base64)", style = TextStyle(fontSize = 14.sp)) },
                        placeholder = {
                            Text("-----BEGIN EC PRIVATE KEY-----...", style = TextStyle(fontSize = 14.sp))
                        },
                        singleLine = false,
                        modifier =
                        Modifier
                            .fillMaxWidth()
                            .heightIn(min = 120.dp, max = 240.dp),
                        isError = errorType != 0,
                        supportingText = {
                            when (errorType) {
                                1 -> Text(
                                    stringResource(R.string.dialog_key_input_no_empty),
                                    color = MaterialTheme.colorScheme.error
                                )
                                2 -> Text(
                                    stringResource(R.string.dialog_key_input_invalid),
                                    color = MaterialTheme.colorScheme.error
                                )
                            }
                        }
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val trimmedKey = inputText.trim()
                        errorType =
                            when {
                                trimmedKey.isBlank() -> 1
                                !KeyUtils.isValidECCKey(trimmedKey) -> 2
                                else -> 0
                            }
                        if (errorType == 0) {
                            KeyUtils.saveKey(context, trimmedKey)
                            onDismiss()
                        }
                    }
                ) { Text(stringResource(R.string.dialog_key_save)) }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.dialog_key_later))
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
    MainScreen()
}
