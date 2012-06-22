package net.google.safebrowsing2.db

import java.sql.Connection
import java.util.Date
import scala.collection.mutable
import javax.sql.DataSource
import util.JdbcTemplate
import util.LiteDataSource
import net.google.safebrowsing2.MacKey
import net.google.safebrowsing2.Hash
import net.google.safebrowsing2.Chunk
import net.google.safebrowsing2.Status
import org.joda.time.Period
import org.joda.time.ReadableInstant
import org.joda.time.DateTime
import net.google.safebrowsing2.Expression

/**
 * Base Storage class used to access the databse.
 * 
 * @see DBI
 */
class MySQL(jt: JdbcTemplate) extends DBI(jt) {
    def this(ds: () => Connection) = this(new JdbcTemplate(ds))
    def this(ds: LiteDataSource) = this(new JdbcTemplate(ds))
    def this(ds: DataSource) = this(new JdbcTemplate(ds))

  import jt._
    
  override def addChunks_s(chunknum: Int, hostkey: String, chunks: Seq[(Int,String)], list: String) = {
    logger.trace("Inserting subChunk: [chunknum={}, hostkey={}, chunks={}, list={}",
        Array[Object](chunknum: java.lang.Integer, hostkey, chunks, list))
     
    val addQuery = "INSERT IGNORE INTO s_chunks (hostkey, prefix, num, add_num, list) VALUES (?, ?, ?, ?, ?)"

    chunks foreach (tuple => {
      execute(addQuery, hostkey, tuple._2, chunknum, tuple._1, list)
    })

    if (chunks.isEmpty) { // keep empty chunks
      execute(addQuery, "", "", chunknum, 0, list)
    }
  }

  override def addChunks_a(chunknum: Int, hostkey: String, prefixes: Seq[String], list: String) = {
    logger.trace("Inserting addChunk: [chunknum={}, hostkey={}, prefixes={}, list={}",
        Array[Object](chunknum: java.lang.Integer, hostkey, prefixes, list))
        
    val addQuery = "INSERT IGNORE INTO a_chunks (hostkey, prefix, num, list) VALUES (?, ?, ?, ?)"

    prefixes foreach (prefix => {
      execute(addQuery, hostkey, prefix, chunknum, list)
    })

    if (prefixes.isEmpty) { // keep empty chunks
      execute(addQuery, "", "", chunknum, list)
    }
  }
}