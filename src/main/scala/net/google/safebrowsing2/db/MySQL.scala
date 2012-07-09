/* 
 * Copyright 2012 Simon Kelly
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
 * MySQL Storage class used to access the database.
 * 
 * @see DBI
 */
class MySQL(jt: JdbcTemplate, tablePrefix: String) extends DBI(jt, tablePrefix) {
  def this(ds: () => Connection, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)
  def this(ds: LiteDataSource, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)
  def this(ds: DataSource, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)

  import jt._
  
  override def addChunks_s(chunknum: Int, hostkeyChunks: Seq[(String,  Seq[(Int, String)])], list: String) = {
    logger.trace("Inserting subChunk: [chunknum={}, hostkeyChunks={}, list={}",
        Array[Object](chunknum: java.lang.Integer, hostkeyChunks, list))
     
    val addQuery = "INSERT IGNORE INTO "+TABLE_PREFIX+"SubChunks (sHostkey, sPrefix, iSubChunkNum, iAddChunkNum, sList) VALUES (?, ?, ?, ?, ?)"

    hostkeyChunks foreach (hostkeyChunksTuple => {
      val hostkey = hostkeyChunksTuple._1
      hostkeyChunksTuple._2 foreach (chunkTuple => {
        execute(addQuery, hostkey, chunkTuple._2, chunknum, chunkTuple._1, list)
      })
    })

    if (hostkeyChunks.isEmpty) { // keep empty chunks
      execute(addQuery, "", "", chunknum, 0, list)
    }
  }

  override def addChunks_a(chunknum: Int, hostkeyPrefixes: Seq[(String, Seq[String])], list: String) = {
    logger.trace("Inserting addChunk: [chunknum={}, hostkeyPrefixes={}, list={}",
        Array[Object](chunknum: java.lang.Integer, hostkeyPrefixes, list))
        
    val addQuery = "INSERT IGNORE INTO "+TABLE_PREFIX+"AddChunks (sHostkey, sPrefix, iAddChunkNum, sList) VALUES (?, ?, ?, ?)"

    hostkeyPrefixes foreach (hostkeyPrefixesTurple => {
      val hostkey = hostkeyPrefixesTurple._1
      hostkeyPrefixesTurple._2 foreach  (prefix => {
        execute(addQuery, hostkey, prefix, chunknum, list)
      })
    })

    if (hostkeyPrefixes.isEmpty) { // keep empty chunks
      execute(addQuery, "", "", chunknum, list)
    }
  }
}
