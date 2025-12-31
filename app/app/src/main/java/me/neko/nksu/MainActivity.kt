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
                    KeyMissingDialog(onDismiss = { showDialog = false })
                }
            }
        }
    }
}

@Composable
fun KeyMissingDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = { },
        title = { Text(text = "缺失密钥") },
        text = { Text(text = "在应用私有目录中未找到必要的密钥文件，请检查后再试。") },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("确定")
            }
        }
    )
}
