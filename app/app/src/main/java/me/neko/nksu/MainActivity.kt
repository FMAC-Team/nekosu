package me.neko.nksu

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import me.neko.nksu.ui.theme.NekosuTheme
import me.neko.nksu.ui.screens.MainScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val isKeyMissingInitial = !KeyUtils.checkKeyExists(this)

        setContent {
            NekosuTheme {
                var showDialog by remember { mutableStateOf(isKeyMissingInitial) }

                MainScreen()

                // Fix: Pass the 'showDialog' state to the 'show' parameter
                if (showDialog) {
                    KeyInputDialog(
                        show = showDialog, 
                        onDismiss = { showDialog = false }
                    )
                }
            }
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
        enter = fadeIn(animationSpec = tween(250)) + scaleIn(initialScale = 0.8f, animationSpec = tween(250)),
        exit = fadeOut(animationSpec = tween(200)) + scaleOut(targetScale = 0.8f, animationSpec = tween(200))
    ) {
        AlertDialog(
            onDismissRequest = { onDismiss() },
            title = { Text(stringResource(R.string.dialog_key_set)) },
            text = {
                Column(
                    modifier = Modifier
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
                        label = { Text("ECC Key (PEM/Base64)") },
                        placeholder = { Text("-----BEGIN EC PRIVATE KEY-----...") },
                        singleLine = false,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 120.dp, max = 240.dp),
                        isError = errorType != 0,
                        supportingText = {
                            when (errorType) {
                                1 -> Text(stringResource(R.string.dialog_key_input_no_empty), color = MaterialTheme.colorScheme.error)
                                2 -> Text(stringResource(R.string.dialog_key_input_invalid), color = MaterialTheme.colorScheme.error)
                            }
                        }
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val trimmedKey = inputText.trim()
                        errorType = when {
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
