package com.hotspotshade.demo

import android.os.Bundle
import android.view.Window
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import com.hotspotshade.demo.model.SecureWindow
import com.hotspotshade.demo.model.SecureWindowController
import com.hotspotshade.demo.ui.AppRoot
import com.hotspotshade.demo.ui.theme.HotspotShadeTheme
import com.hotspotshade.demo.ui.theme.rememberReducedMotion
import com.hotspotshade.source.PairingNotifications
import com.hotspotshade.source.PairingViewModel

class MainActivity : ComponentActivity() {
    private val pairingViewModel: PairingViewModel by viewModels()
    private val proxyViewModel: ProxyViewModel by viewModels()
    private val manualConnectionViewModel: ManualConnectionViewModel by viewModels()
    private val secureWindow by lazy {
        SecureWindowController(ActivitySecureWindow(window))
    }

    override fun onStart() {
        super.onStart()
        pairingViewModel.setVisible(true)
        pairingViewModel.start()
        proxyViewModel.setVisible(true)
        manualConnectionViewModel.refresh()
        // The token was hidden in onStop. End the hold and clear FLAG_SECURE now
        // that the visible state shows no token.
        secureWindow.onForeground(manualConnectionViewModel.state.tokenVisible)
    }

    override fun onStop() {
        // Hold FLAG_SECURE first. The system takes the recents snapshot after
        // onStop returns, and the last drawn frame can still show the token.
        // The flag stays set until onStart, so no recomposition after this
        // point can clear it early.
        secureWindow.onBackground()
        manualConnectionViewModel.onBackground()
        pairingViewModel.setVisible(false)
        pairingViewModel.stop()
        proxyViewModel.setVisible(false)
        super.onStop()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        PairingNotifications.ensureChannel(this)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.auto(
                lightScrim = android.graphics.Color.TRANSPARENT,
                darkScrim = android.graphics.Color.TRANSPARENT,
            ),
            navigationBarStyle = SystemBarStyle.auto(
                lightScrim = android.graphics.Color.TRANSPARENT,
                darkScrim = android.graphics.Color.TRANSPARENT,
            ),
        )
        setContent {
            HotspotShadeApp(
                pairingViewModel = pairingViewModel,
                proxyViewModel = proxyViewModel,
                manualConnectionViewModel = manualConnectionViewModel,
                onTokenReveal = secureWindow::update,
            )
        }
    }
}

@Composable
private fun HotspotShadeApp(
    pairingViewModel: PairingViewModel,
    proxyViewModel: ProxyViewModel,
    manualConnectionViewModel: ManualConnectionViewModel,
    onTokenReveal: (Boolean) -> Unit,
) {
    val tokenRevealed = manualConnectionViewModel.state.tokenVisible
    SideEffect { onTokenReveal(tokenRevealed) }
    val reduceMotion = rememberReducedMotion()
    HotspotShadeTheme(
        darkTheme = isSystemInDarkTheme(),
        reduceMotion = reduceMotion,
    ) {
        AppRoot(
            pairingViewModel = pairingViewModel,
            proxyViewModel = proxyViewModel,
            manualConnectionViewModel = manualConnectionViewModel,
        )
    }
}

/** Apply the screen-capture block to the activity window. */
private class ActivitySecureWindow(
    private val window: Window,
) : SecureWindow {
    override fun setSecure(secure: Boolean) {
        if (secure) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
