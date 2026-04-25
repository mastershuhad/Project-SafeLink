package com.safelink.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface ScanDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(record: ScanRecord)

    @Query("SELECT * FROM scan_records ORDER BY timestamp DESC")
    suspend fun getAll(): List<ScanRecord>

    @Query("""
        SELECT * FROM scan_records
        WHERE url LIKE '%' || :query || '%'
           OR verdict LIKE '%' || :query || '%'
           OR primaryReason LIKE '%' || :query || '%'
        ORDER BY timestamp DESC
    """)
    suspend fun search(query: String): List<ScanRecord>

    @Query("SELECT * FROM scan_records WHERE id = :id")
    suspend fun getById(id: Long): ScanRecord?

    @Query("DELETE FROM scan_records")
    suspend fun clearAll()

    @Query("SELECT COUNT(*) FROM scan_records")
    suspend fun count(): Int
}
