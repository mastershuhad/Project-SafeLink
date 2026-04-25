package com.safelink.ml

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import java.nio.LongBuffer

/**
 * URLBert-tiny-v4 classifier backed by ONNX Runtime.
 * Model: urlbert.onnx  (~15MB float32, opset 18)
 * Input:  input_ids + attention_mask  — int64, shape [1, 64]
 * Output: logits [1, 2]  →  [p_benign, p_phishing]
 *
 * Tokenization mirrors HuggingFace BertTokenizer(do_lower_case=True):
 *   lowercase → basic-tokenize (split on punctuation/whitespace)
 *   → WordPiece greedy longest-match with ## continuation prefix
 *
 * Falls back to 0.5 (neutral) if model file is absent.
 */
class URLBertClassifier(context: Context) : AutoCloseable {

    companion object {
        const val MAX_LENGTH = 64
        private const val MODEL_FILE = "urlbert.onnx"
        private const val VOCAB_FILE  = "vocab.txt"

        private fun isPunct(ch: Char): Boolean {
            val c = ch.code
            return c in 33..47 || c in 58..64 || c in 91..96 || c in 123..126
        }

        private fun basicTokenize(text: String): List<String> {
            val tokens = mutableListOf<String>()
            val buf = StringBuilder()
            for (ch in text) {
                when {
                    ch.isWhitespace() -> {
                        if (buf.isNotEmpty()) { tokens.add(buf.toString()); buf.clear() }
                    }
                    isPunct(ch) -> {
                        if (buf.isNotEmpty()) { tokens.add(buf.toString()); buf.clear() }
                        tokens.add(ch.toString())
                    }
                    else -> buf.append(ch)
                }
            }
            if (buf.isNotEmpty()) tokens.add(buf.toString())
            return tokens
        }

        private fun wordpieceTokenize(word: String, vocab: Map<String, Int>): List<Int> {
            val unk = vocab["[UNK]"] ?: 1
            if (word in vocab) return listOf(vocab[word]!!)
            val ids = mutableListOf<Int>()
            var start = 0
            while (start < word.length) {
                var end = word.length
                var found = false
                val prefix = if (start == 0) "" else "##"
                while (end > start) {
                    val sub = prefix + word.substring(start, end)
                    val id = vocab[sub]
                    if (id != null) { ids.add(id); start = end; found = true; break }
                    end--
                }
                if (!found) return listOf(unk)
            }
            return ids
        }
    }

    private val env: OrtEnvironment = OrtEnvironment.getEnvironment()
    private val session: OrtSession?
    private val vocab: Map<String, Int>

    init {
        var sess: OrtSession? = null
        try {
            val bytes = context.assets.open(MODEL_FILE).readBytes()
            sess = env.createSession(bytes, OrtSession.SessionOptions())
        } catch (e: Exception) {
            android.util.Log.w("URLBertClassifier", "urlbert.onnx not found — neutral fallback")
        }
        session = sess
        vocab = loadVocab(context)
    }

    /** Returns p_phishing in [0, 1]. Returns 0.5 (neutral) if model unavailable. */
    fun classify(url: String): Float {
        if (session == null) return 0.5f

        val (inputIds, attentionMask) = tokenize(url.lowercase())

        return try {
            val shape = longArrayOf(1, MAX_LENGTH.toLong())
            val idTensor   = OnnxTensor.createTensor(env, LongBuffer.wrap(inputIds),   shape)
            val maskTensor = OnnxTensor.createTensor(env, LongBuffer.wrap(attentionMask), shape)

            val inputs = mapOf(
                "input_ids"      to idTensor,
                "attention_mask" to maskTensor,
            )
            val result = session.run(inputs)
            val logits = (result[0].value as Array<FloatArray>)[0]  // [p_benign, p_phishing]

            idTensor.close(); maskTensor.close(); result.close()

            val expB = Math.exp(logits[0].toDouble())
            val expP = Math.exp(logits[1].toDouble())
            (expP / (expB + expP)).toFloat()
        } catch (e: Exception) {
            android.util.Log.w("URLBertClassifier", "Inference failed: ${e.message}")
            0.5f
        }
    }

    private fun tokenize(url: String): Pair<LongArray, LongArray> {
        val inputIds      = LongArray(MAX_LENGTH) { 0L }   // [PAD] = 0
        val attentionMask = LongArray(MAX_LENGTH) { 0L }

        inputIds[0]      = (vocab["[CLS]"] ?: 2).toLong()
        attentionMask[0] = 1L
        var pos = 1

        for (word in basicTokenize(url)) {
            for (id in wordpieceTokenize(word, vocab)) {
                if (pos >= MAX_LENGTH - 1) break
                inputIds[pos]      = id.toLong()
                attentionMask[pos] = 1L
                pos++
            }
            if (pos >= MAX_LENGTH - 1) break
        }

        inputIds[pos]      = (vocab["[SEP]"] ?: 3).toLong()
        attentionMask[pos] = 1L

        return inputIds to attentionMask
    }

    private fun loadVocab(context: Context): Map<String, Int> {
        val map = HashMap<String, Int>()
        try {
            context.assets.open(VOCAB_FILE).bufferedReader().useLines { lines ->
                lines.forEachIndexed { idx, token -> map[token.trim()] = idx }
            }
        } catch (e: Exception) {
            // Fallback matches this model's special token IDs
            map["[PAD]"]  = 0; map["[UNK]"] = 1
            map["[CLS]"]  = 2; map["[SEP]"] = 3
        }
        return map
    }

    override fun close() {
        session?.close()
        env.close()
    }
}
