package com.pedrammarandi.androidscanner

import android.app.Application
import com.pedrammarandi.androidscanner.di.AppContainer

class AndroidScannerApplication : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
    }
}

