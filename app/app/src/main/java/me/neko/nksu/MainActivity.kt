package me.neko.nksu

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import me.neko.nksu.ui.theme.NekosuTheme
import me.neko.nksu.ui.screens.MainScreen
import androidx.compose.ui.res.stringResource

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val isKeyMissingInitial = !KeyUtils.checkKeyExists(this)

        setContent {
            NekosuTheme {
                var showDialog by remember { mutableStateOf(isKeyMissingInitial) }

                MainScreen()

                if (showDialog) {
                    KeyInputDialog(onKeySaved = {  showDialog = false })
                }
            }
        }
    }
}


@Composable
fun KeyInputDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    var inputText by remember { mutableStateOf("") }
    var isError by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { onDismiss() },
        title = { Text(text = stringResource(id = R.string.dialog_key_title)) },
        text = {
            Column {
                Text(text = stringResource(id = R.string.dialog_key_desc))
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = inputText,
                    onValueChange = {
                        inputText = it
                        isError = false
                    },
                    label = { Text(stringResource(id = R.string.dialog_key_label)) },
                    singleLine = true,
                    isError = isError,
                    supportingText = {
                        if (isError)  {                          Text(stringResource(id = R.string.dialog_key_error))}
                    }
                )
            }
        },
        confirmButton = {
            Button(onClick = {
                if (inputText.isNotBlank()) {
                    KeyUtils.saveKey(context, inputText)
                    onDismiss()
                } else {
                    isError = true
                }
            }) {
                Text(stringResource(id = R.string.dialog_key_save))
            }
        },
        dismissButton = {
            TextButton(onClick = { onDismiss() }) {
                Text(stringResource(id = R.string.dialog_key_later))
            }
        }
    )
}
