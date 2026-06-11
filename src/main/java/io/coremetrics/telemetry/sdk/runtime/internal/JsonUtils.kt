package io.coremetrics.telemetry.sdk.runtime.internal

import kotlinx.serialization.json.Json

val AppJson = Json {
    ignoreUnknownKeys = true
    coerceInputValues = true
    encodeDefaults = true
    prettyPrint = true
    isLenient = true
    allowSpecialFloatingPointValues = true
    explicitNulls = false
}
