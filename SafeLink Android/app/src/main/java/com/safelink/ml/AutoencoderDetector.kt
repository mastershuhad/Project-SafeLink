package com.safelink.ml

import android.content.Context
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import org.tensorflow.lite.Interpreter
import org.tensorflow.lite.support.common.FileUtil

data class AnomalyResult(
    val mse: Float,
    val isAnomaly: Boolean,
    val category: String,
    val threshold: Float,
)

private data class ThresholdData(
    @SerializedName("thresholds") val thresholds: Map<String, Double>,
    @SerializedName("short_max") val shortMax: Int,
    @SerializedName("long_min") val longMin: Int,
)

class AutoencoderDetector(context: Context) : AutoCloseable {

    companion object {
        private const val MODEL_FILE = "autoencoder.tflite"
        private const val THRESHOLD_FILE = "anomaly_threshold.json"
    }

    private val interpreter: Interpreter
    private val thresholds: Map<String, Float>
    private val shortMax: Int
    private val longMin: Int

    init {
        val buffer = FileUtil.loadMappedFile(context, MODEL_FILE)
        interpreter = Interpreter(buffer, Interpreter.Options().apply { numThreads = 2 })

        val json = context.assets.open(THRESHOLD_FILE).bufferedReader().readText()
        val data = Gson().fromJson(json, ThresholdData::class.java)
        thresholds = data.thresholds.mapValues { it.value.toFloat() }
        shortMax = data.shortMax
        longMin = data.longMin
    }

    /**
     * Runs autoencoder reconstruction and computes MSE.
     * [scaledFeatures] must already be StandardScaler-normalized (22 floats).
     * [urlLength] is the raw URL character length (before scaling) for category selection.
     */
    fun detect(scaledFeatures: FloatArray, urlLength: Float): AnomalyResult {
        require(scaledFeatures.size == 22)

        val input = arrayOf(scaledFeatures)
        val output = Array(1) { FloatArray(22) }

        interpreter.run(input, output)

        val recon = output[0]
        val mse = scaledFeatures.indices.sumOf { i ->
            val diff = (scaledFeatures[i] - recon[i]).toDouble()
            diff * diff
        }.toFloat() / 22f

        val category = when {
            urlLength < shortMax -> "short"
            urlLength <= longMin -> "medium"
            else -> "long"
        }
        val threshold = thresholds[category] ?: thresholds["medium"] ?: 0.01f

        return AnomalyResult(
            mse = mse,
            isAnomaly = mse > threshold,
            category = category,
            threshold = threshold,
        )
    }

    override fun close() = interpreter.close()
}
