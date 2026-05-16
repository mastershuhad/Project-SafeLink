package com.safelink.ml

import android.content.Context
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName

data class ScalerParams(
    @SerializedName("n_features") val nFeatures: Int,
    @SerializedName("feature_names") val featureNames: List<String>,
    @SerializedName("mean") val mean: List<Double>,
    @SerializedName("scale") val scale: List<Double>,
)

class FeatureScaler(context: Context) {

    private val params: ScalerParams

    init {
        val json = context.assets.open("scaler_params.json").bufferedReader().readText()
        params = Gson().fromJson(json, ScalerParams::class.java)
        require(params.nFeatures == 22) {
            "scaler_params.json n_features must be 22, got ${params.nFeatures}"
        }
        require(params.mean.size == 22 && params.scale.size == 22) {
            "scaler mean/scale arrays must each have 22 elements"
        }
    }

    /**
     * Applies StandardScaler z = (x - mean) / scale.
     * Handles divide-by-zero for constant features (scale ≈ 0) by leaving value as-is.
     */
    fun scale(features: FloatArray): FloatArray {
        require(features.size == 22) { "Expected 22 features, got ${features.size}" }
        return FloatArray(22) { i ->
            val s = params.scale[i]
            if (s < 1e-8) features[i]
            else ((features[i] - params.mean[i]) / s).toFloat()
        }
    }
}
