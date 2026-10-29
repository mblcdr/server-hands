package com.samsaz.serverhands

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import com.samsaz.serverhands.ui.AmberDark
import com.samsaz.serverhands.ui.AmberLight
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.fragment.app.FragmentActivity
import com.samsaz.serverhands.ui.HomeScreen

/** FragmentActivity (not ComponentActivity) because BiometricPrompt needs a FragmentManager. */
class MainActivity : FragmentActivity() {
    private val vm: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no recents thumbnail: passphrases are typed on this screen.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            val dark = isSystemInDarkTheme()
            MaterialTheme(colorScheme = if (dark) AmberDark else AmberLight) {
                HomeScreen(vm, this)
            }
        }
    }
}
