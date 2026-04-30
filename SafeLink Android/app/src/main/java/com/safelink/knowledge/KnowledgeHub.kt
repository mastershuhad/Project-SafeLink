package com.safelink.knowledge

data class BrandEntry(
    val id: String,
    val displayName: String,
    val domains: List<String>,
    val keywords: List<String>,
)

data class AttackPattern(
    val pattern: String,
    val type: String,
    val elderlyWarning: String,
)

data class XAIEnrichment(
    val brandId: String,
    val xaiReason: String,
)

data class KnowledgeHubVersion(
    val version: String,
    val released: String,
    val changelog: String,
)
