package com.safelink.ml

import android.content.Context
import org.tensorflow.lite.Interpreter
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * CNN+Dense dual-stream TFLite classifier.
 * Inputs:  seq_input  IntArray(200)   — tokenized URL
 *          num_input  FloatArray(36)  — scaled feature vector
 * Output:  FloatArray(3)              — [p_safe, p_warning, p_malicious]
 */
class SafeLinkClassifier(context: Context) : AutoCloseable {

    private val interpreter: Interpreter

    init {
        val afd = context.assets.openFd("safelink_model.tflite")
        val buffer: ByteBuffer = afd.createInputStream().channel.use { ch ->
            ch.map(FileChannel.MapMode.READ_ONLY, afd.startOffset, afd.declaredLength)
        }
        val opts = Interpreter.Options().apply {
            numThreads = 2
        }
        interpreter = Interpreter(buffer, opts)
    }

    /** Returns [p_safe, p_warning, p_malicious]. */
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
        return output[0]
    }

    override fun close() = interpreter.close()
}
