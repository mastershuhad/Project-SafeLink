package com.safelink.ml

import android.content.Context
import org.tensorflow.lite.Interpreter
import org.tensorflow.lite.support.common.FileUtil

/**
 * CNN+Dense dual-stream TFLite classifier.
 * Inputs:  seq_input  IntArray(200)   — tokenized URL
 *          num_input  FloatArray(36)  — scaled feature vector
 * Output:  FloatArray(3)              — [p_safe, p_warning, p_malicious]
 */
class SafeLinkClassifier(context: Context) : AutoCloseable {

    private val interpreter: Interpreter

    init {
        val buffer = FileUtil.loadMappedFile(context, "safelink_model.tflite")
        val opts = Interpreter.Options().apply { numThreads = 2 }
        interpreter = Interpreter(buffer, opts)
    }

    /** Returns [p_safe, p_warning, p_malicious] with temperature-scaled confidence. */
    fun classify(seqInput: IntArray, numInput: FloatArray): FloatArray {
        require(seqInput.size == UrlTokenizer.SEQ_LEN)
        require(numInput.size == 36)

        val output = Array(1) { FloatArray(3) }

        interpreter.runSignature(
            mapOf(
                "seq_input" to arrayOf(seqInput),
                "num_input" to arrayOf(numInput),
            ),
            mapOf("output" to output),
        )
        val raw = output[0]
        val pMalCal  = temperatureScale(raw[2])
        val pSafeCal = 1f - pMalCal
        return floatArrayOf(pSafeCal, raw[1], pMalCal)
    }

    override fun close() = interpreter.close()

    companion object {
        private const val TEMPERATURE = 5.0f

        // Invert softmax → log-odds → divide by T → re-sigmoid.
        // Maps binary 0.000/1.000 outputs to calibrated probabilities:
        //   1.000 → 0.940   0.900 → 0.608   0.500 → 0.500
        private fun temperatureScale(pRaw: Float): Float {
            val eps = 1e-6f
            val p   = pRaw.coerceIn(eps, 1f - eps)
            val logit = kotlin.math.ln(p / (1f - p))
            return 1f / (1f + kotlin.math.exp(-logit / TEMPERATURE))
        }
    }
}
