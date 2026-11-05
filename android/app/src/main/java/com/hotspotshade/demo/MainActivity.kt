package com.hotspotshade.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.compose.viewModel
import com.hotspotshade.demo.model.ThemeChoice
import com.hotspotshade.demo.ui.AppRoot
import com.hotspotshade.demo.ui.theme.HotspotShadeTheme
import com.hotspotshade.demo.ui.theme.rememberReducedMotion
import com.hotspotshade.source.PairingNotifications
import com.hotspotshade.source.PairingViewModel

class MainActivity : ComponentActivity() {
    private val pairingViewModel: PairingViewModel by viewModels()
    private val proxyViewModel: ProxyViewModel by viewModels()

    override fun onStart() {
        super.onStart()
        pairingViewModel.setVisible(true)
        pairingViewModel.start()
        proxyViewModel.setVisible(true)
    }

    override fun onStop() {
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
            HotspotShadeApp(pairingViewModel, proxyViewModel)
        }
    }
}

@Composable
private fun HotspotShadeApp(
    pairingViewModel: PairingViewModel,
    proxyViewModel: ProxyViewModel,
    viewModel: DemoViewModel = viewModel(),
) {
    val state = viewModel.state
    val systemDark = isSystemInDarkTheme()
    val dark = when (state.theme) {
        ThemeChoice.SYSTEM -> systemDark
        ThemeChoice.LIGHT -> false
        ThemeChoice.DARK -> true
    }
    val reduceMotion = rememberReducedMotion(state.reduceMotion)
    HotspotShadeTheme(
        darkTheme = dark,
        reduceMotion = reduceMotion,
    ) {
        AppRoot(
            viewModel = viewModel,
            pairingViewModel = pairingViewModel,
            proxyViewModel = proxyViewModel,
        )
    }
}
