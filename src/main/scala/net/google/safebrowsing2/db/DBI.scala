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

import scala.collection.mutable

import org.joda.time.DateTime
import org.joda.time.Duration
import org.joda.time.Period

import javax.sql.DataSource
import util.JdbcTemplate
import util.LiteDataSource
import util.Logging
import net.google.safebrowsing2._

/**
 * Base Storage class used to access the database.
 *
 * Usage:
 * new DBI(dataSource, "gsb_")
 * new DBI(connection, "gsb_")
 * new DBI(LiteDataSource.driverManager("jdbc:mysql://localhost:3306/googlesafebrowsing2"), "gsb_")
 * new DBI(LiteDataSource.driverManager("jdbc:mysql://localhost:3306/googlesafebrowsing2", "root", "root"), "gsb_")
 */
class DBI(jt: JdbcTemplate, tablePrefix: String) extends Storage with Logging {
  def this(ds: () => Connection, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)
  def this(ds: LiteDataSource, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)
  def this(ds: DataSource, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)

  import jt._
  
  val TABLE_PREFIX = tablePrefix

  init

  /**
   * Should create tables if needed
   */
  def init = {
    logger.error("Database init")
    val tables = mutable.ListBuffer("Updates", "AddChunks", "SubChunks", "FullHashes", "FullHashErrors", "MacKeys")
    metaData(meta => {
      val res = meta.getTables(null, null, "%", null)
      while (res.next()) {
        val table = res.getString("TABLE_NAME")
        val existing = tables.find(t => table.equalsIgnoreCase(TABLE_PREFIX+t))
        if (existing.isDefined) {
          logger.debug("Table already exists: {}. Skipping table createion.", table)
          tables -= existing.get
        }
      }
      res.close()
    })

    tables.foreach(_ match {
      case "Updates" => createTableUpdates
      case "AddChunks" => createTableAddChunks
      case "SubChunks" => createTableSubChunks
      case "FullHashes" => createTableFullHashes
      case "FullHashErrors" => createTableFullHashErrors
      case "MacKeys" => createTableMacKeys
      case x => logger.warn("Unknown table: {}", x)
    })
  }

  def createTableUpdates = {
    logger.debug("Creating table: "+TABLE_PREFIX+"Updates")
    val schema = """	
		CREATE TABLE """+TABLE_PREFIX+"""Updates (
      		dtLastSuccess TIMESTAMP,
			dtLastAttempt TIMESTAMP NOT NULL,
			dtNextAttempt TIMESTAMP NOT NULL,
			iErrorCount INT NOT NULL,
			sList VARCHAR( 50 ) NOT NULL
		)
	"""

    execute(schema)
  }

  def createTableAddChunks = {
    logger.debug("Creating table: "+TABLE_PREFIX+"AddChunks")
    val schema = """	
		CREATE TABLE """+TABLE_PREFIX+"""AddChunks (
			sHostkey VARCHAR( 8 ),
			sPrefix VARCHAR( 64 ),
			iAddChunkNum INT NOT NULL,
			sList VARCHAR( 50 ) NOT NULL
		)
	"""

    execute(schema)

    var index = """	
		CREATE INDEX IDX_"""+TABLE_PREFIX+"""AddChunks_sHostkey ON """+TABLE_PREFIX+"""AddChunks (
			sHostkey
		)
	"""
    execute(index)

    index = """
		CREATE INDEX IDX_"""+TABLE_PREFIX+"""AddChunks_iAddChunkNum_sList ON """+TABLE_PREFIX+"""AddChunks (
			iAddChunkNum,
			sList
		)
	"""
    execute(index)
    
    index = """
		CREATE UNIQUE INDEX IDX_"""+TABLE_PREFIX+"""AddChunks_Unique ON """+TABLE_PREFIX+"""AddChunks (
			sHostkey,
			sPrefix,
			iAddChunkNum,
			sList
		)
	"""
    execute(index)
  }

  def createTableSubChunks = {
    logger.debug("Creating table: "+TABLE_PREFIX+"SubChunks")
    var schema = """
		CREATE TABLE """+TABLE_PREFIX+"""SubChunks (
			sHostkey VARCHAR( 8 ),
			sPrefix VARCHAR( 64 ),
			iSubChunkNum INT NOT NULL,
			iAddChunkNum INT NOT NULL,
			sList VARCHAR( 50 ) NOT NULL
		)
	"""

    execute(schema)

    var index = """
		CREATE INDEX IDX_"""+TABLE_PREFIX+"""SubChunks_sHostkey ON """+TABLE_PREFIX+"""SubChunks (
			sHostkey
		)
	"""
    execute(index)

    index = """
		CREATE INDEX IDX_"""+TABLE_PREFIX+"""SubChunks_iSubChunkNum ON """+TABLE_PREFIX+"""SubChunks (
			iSubChunkNum
		)
	"""
    execute(index)

    index = """
		CREATE INDEX IDX_"""+TABLE_PREFIX+"""SubChunks_iSubChunkNum_sList ON """+TABLE_PREFIX+"""SubChunks (
			iSubChunkNum,
			sList
		)
	"""
    execute(index)
    
    index = """
		CREATE UNIQUE INDEX IDX_"""+TABLE_PREFIX+"""SubChunks_Unique ON """+TABLE_PREFIX+"""SubChunks (
			sHostkey,
			sPrefix,
			iSubChunkNum,
			iAddChunkNum,
			sList
		)
	"""
    execute(index)
  }

   def createTableFullHashes = {
    logger.debug("Creating table: "+TABLE_PREFIX+"FullHashes")
    val schema = """
		CREATE TABLE """+TABLE_PREFIX+"""FullHashes (
			pkiFullHashesID INT AUTO_INCREMENT PRIMARY KEY,
			iAddChunkNum INT,
			sHash VARCHAR( 64 ),
			sList VARCHAR( 50 ),
			dtLastUpdate TIMESTAMP NOT NULL
		)
	"""

    execute(schema)
    
    val index = """
		CREATE UNIQUE INDEX IDX"""+TABLE_PREFIX+"""FullHashes_Unique ON """+TABLE_PREFIX+"""FullHashes (
			iAddChunkNum,
			sHash,
			sList
		)
	"""
    execute(index)
  }

  def createTableFullHashErrors = {
    logger.debug("Creating table: "+TABLE_PREFIX+"FullHashErrors")
    val schema = """
		CREATE TABLE """+TABLE_PREFIX+"""FullHashErrors (
			pkiFullHasheErrorsID INT AUTO_INCREMENT PRIMARY KEY,
			dtLastAttempt TIMESTAMP NOT NULL,
			dtNextAttempt TIMESTAMP NOT NULL,
			iErrorCount INT NOT NULL,
			sPrefix VARCHAR( 64 )
		)
	"""

    execute(schema)
  }

  def createTableMacKeys = {
    logger.debug("Creating table: "+TABLE_PREFIX+"MacKeys")
    val schema = """
		CREATE TABLE """+TABLE_PREFIX+"""MacKeys (
			sClientKey VARCHAR( 50 ),
			sWrappedKey VARCHAR( 150 )
		)
	"""

    execute(schema)
  }
   
  override def addChunks_s(chunknum: Int, hostkeyChunks: Seq[(String,  Seq[(Int, String)])], list: String) = {
    logger.trace("Inserting subChunk: [chunknum={}, hostkeyChunks={}, list={}",
      Array[Object](chunknum: java.lang.Integer, hostkeyChunks, list))

    val delQuery = "DELETE FROM "+TABLE_PREFIX+"SubChunks WHERE sHostkey = ? AND sPrefix = ? AND iSubChunkNum = ? AND iAddChunkNum = ? AND sList = ?"
    val addQuery = "INSERT INTO "+TABLE_PREFIX+"SubChunks (sHostkey, sPrefix, iSubChunkNum, iAddChunkNum, sList) VALUES (?, ?, ?, ?, ?)"

    hostkeyChunks foreach (hostkeyChunksTuple => {
      val hostkey = hostkeyChunksTuple._1
      hostkeyChunksTuple._2 foreach (chunkTuple => {
        execute(delQuery, hostkey, chunkTuple._2, chunknum, chunkTuple._1, list)
        execute(addQuery, hostkey, chunkTuple._2, chunknum, chunkTuple._1, list)
      })
    })

    if (hostkeyChunks.isEmpty) { // keep empty chunks
      execute(delQuery, "", "", chunknum, 0, list)
      execute(addQuery, "", "", chunknum, 0, list)
    }
  }

  override def addChunks_a(chunknum: Int, hostkeyPrefixes: Seq[(String, Seq[String])], list: String) = {
    logger.trace("Inserting addChunk: [chunknum={}, hostkeyPrefixes={}, list={}",
      Array[Object](chunknum: java.lang.Integer, hostkeyPrefixes, list))

    val delQuery = "DELETE FROM "+TABLE_PREFIX+"AddChunks WHERE sHostkey = ? AND  sPrefix  = ? AND iAddChunkNum = ? AND sList  = ?"
    val addQuery = "INSERT INTO "+TABLE_PREFIX+"AddChunks (sHostkey, sPrefix, iAddChunkNum, sList) VALUES (?, ?, ?, ?)"

    hostkeyPrefixes foreach (hostkeyPrefixesTurple => {
      val hostkey = hostkeyPrefixesTurple._1
      hostkeyPrefixesTurple._2 foreach  (prefix => {
        execute(delQuery, hostkey, prefix, chunknum, list)
        execute(addQuery, hostkey, prefix, chunknum, list)
      })
    })

    if (hostkeyPrefixes.isEmpty) { // keep empty chunks
      execute(delQuery, "", "", chunknum, list)
      execute(addQuery, "", "", chunknum, list)
    }
  }

  override def getChunksForHostKeys(hostkeys: Seq[String]): Seq[Chunk] = {
    // TODO: This looks ugly...
    val flattedKeys = hostkeys.map(k => "'" + k + "'").reduceLeft((x,y) => x + ", " + y)

    query("""SELECT a.sList, a.iAddChunkNum, a.sHostkey, a.sPrefix from """+TABLE_PREFIX+"""AddChunks a LEFT OUTER JOIN """+TABLE_PREFIX+"""SubChunks s
    		ON s.sList = a.sList
    		AND s.sHostkey = a.sHostkey
    		AND s.iAddChunkNum = a.iAddChunkNum
    		AND (s.sPrefix = a.sPrefix OR s.sPrefix = '')
    		WHERE s.iSubChunkNum IS NULL
    		AND a.sHostkey IN ("""+flattedKeys+""")""").seq(row =>
      Chunk(row.getInt("iAddChunkNum"), row.getString("sPrefix"), row.getString("sHostkey"), row.getString("sList")))
  }

  override def getAddChunksNums(list: String): Seq[Int] = {
	    query("SELECT DISTINCT(iAddChunkNum) FROM "+TABLE_PREFIX+"AddChunks WHERE sList = ? ORDER BY iAddChunkNum ASC", list).seq[Int].sorted
	  }

  override def getSubChunksNums(list: String): Seq[Int] = {
    query("SELECT DISTINCT(iSubChunkNum) FROM "+TABLE_PREFIX+"SubChunks WHERE sList = ? ORDER BY iSubChunkNum ASC", list).seq[Int].sorted
  }

  override def deleteAddChunks(chunknums: Seq[Int], list: String) = {
    logger.trace("Delete add chunks: [chunknums={}, list={}]", chunknums, list)
    
    val params = chunknums map (cn => Seq(cn, list))
    executeBatch("DELETE FROM "+TABLE_PREFIX+"AddChunks WHERE iAddChunkNum = ? AND sList = ?", params)
  }

  override def deleteSubChunks(chunknums: Seq[Int], list: String) = {
    logger.trace("Delete sub chunks: [chunknums={}, list={}]", chunknums, list)
    
    val params = chunknums map (cn => Seq(cn, list))
    executeBatch("DELETE FROM "+TABLE_PREFIX+"SubChunks WHERE iSubChunkNum = ? AND sList = ?", params)
  }

  override def getFullHashes(chunknum: Int, lastUpdate: DateTime, list: String): Seq[String] = {
    query("SELECT sHash FROM "+TABLE_PREFIX+"FullHashes WHERE dtLastUpdate >= ? AND iAddChunkNum = ? AND sList = ?", lastUpdate, chunknum, list).seq[String]
  }

  override def updateSuccess(lastAttempt: DateTime, nextAttempt: DateTime, list: String) = {
    if (getListStatus(list).isEmpty) {
      execute("INSERT INTO "+TABLE_PREFIX+"Updates (dtLastAttempt, dtLastSuccess, dtNextAttempt, iErrorCount, sList) VALUES (?, ?, ?, 0, ?)", lastAttempt, lastAttempt, nextAttempt, list)
    } else {
      execute("UPDATE "+TABLE_PREFIX+"Updates SET dtLastAttempt = ?, dtLastSuccess = ?, dtNextAttempt = ?, iErrorCount = 0 WHERE sList = ?", lastAttempt, lastAttempt, nextAttempt, list)
    }
  }

  override def updateError(thisAttempt: DateTime, list: String) = {
    val status = getListStatus(list)
    if (status.isEmpty) {
      execute("INSERT INTO "+TABLE_PREFIX+"Updates (dtLastAttempt, dtNextAttempt, iErrorCount, sList) VALUES (?, ?, 1, ?)", thisAttempt, thisAttempt.plusMinutes(1), list)
    } else {
      val (errors, nextAttempt) = updateBackoff(thisAttempt, status.get)
      execute("UPDATE "+TABLE_PREFIX+"Updates SET dtLastAttempt = ?, dtNextAttempt = ?, iErrorCount = ? WHERE sList = ?", thisAttempt, nextAttempt, errors, list)
    }
  }

  override def getListStatus(list: String): Option[Status] = {
    query("SELECT * FROM "+TABLE_PREFIX+"Updates WHERE sList = ? LIMIT 1", list).option(row => {
      val lastAttempt = row.getTimestamp("dtLastAttempt")
      val lastSuccess = Option(row.getTimestamp("dtLastSuccess")).map(new DateTime(_))
      val nextAttempt = row.getTimestamp("dtNextAttempt")
      val errors = row.getInt("iErrorCount")
      Status(new DateTime(lastAttempt), lastSuccess, new DateTime(nextAttempt), errors)
    })
  }
  
  override def addFullHashes(fetchTime: DateTime, fullHashes: Seq[Hash]) = {
    logger.trace("Add full hashes: {}", fullHashes)

    val deleteParams = fullHashes map (hash => Seq(hash.chunknum, hash.hash, hash.list))
    val insertParams = fullHashes map (hash => Seq(hash.chunknum, hash.hash, hash.list, fetchTime))
    executeBatch("DELETE FROM "+TABLE_PREFIX+"FullHashes WHERE iAddChunkNum = ? AND sHash = ? AND sList = ?", deleteParams)
    executeBatch("INSERT INTO "+TABLE_PREFIX+"FullHashes (iAddChunkNum, sHash, sList, dtLastUpdate) VALUES (?, ?, ?, ?)", insertParams)
  }
  
  override def deleteFullHashes(chunknums: Seq[Int], list: String) = {
    logger.trace("Delete full hashes: [chunknums={}, list={}]", chunknums, list)
    
    val params = chunknums map (cn => Seq(cn, list))
    executeBatch("DELETE FROM "+TABLE_PREFIX+"FullHashes WHERE iAddChunkNum = ? AND sList = ?", params)
  }
  
  override def fullHashError(thisAttempt: DateTime, prefix: String) = {
    val lastError = getFullHashError(prefix)
    if (lastError.isEmpty){
    	execute("INSERT INTO "+TABLE_PREFIX+"FullHashErrors (sPrefix, iErrorCount, dtLastAttempt, dtNextAttempt) VALUES (?, 1, ?, ?)", prefix, thisAttempt, thisAttempt.plusMinutes(1))
    } else {
      val (errors, nextAttempt) = fullHashBackoff(thisAttempt, lastError.get)
      execute("UPDATE "+TABLE_PREFIX+"FullHashErrors SET iErrorCount = ?, dtLastAttempt = ?, dtNextAttempt = ? WHERE sPrefix = ?", errors, thisAttempt, nextAttempt, prefix)
    }
  }

  override def clearFullhashErrors(chunks: Seq[Chunk]) = {
    val params = chunks.map(c => Seq(c.prefix))
    executeBatch("DELETE FROM "+TABLE_PREFIX+"FullHashErrors WHERE sPrefix = ?", params)
  }

  override def getFullHashError(prefix: String): Option[Status] = {
    query("SELECT dtLastAttempt, dtNextAttempt, iErrorCount FROM "+TABLE_PREFIX+"FullHashErrors WHERE sPrefix = ?", prefix).option(row => {
      val lastAttempt = row.getTimestamp("dtLastAttempt")
      val nextAttempt = row.getTimestamp("dtNextAttempt")
      val errors = row.getInt("iErrorCount")
      new Status(new DateTime(lastAttempt), None, new DateTime(nextAttempt), errors)
    })
  }
	  
  override def getMacKey(): Option[MacKey] = {
    query("SELECT sClientKey, sWrappedKey FROM "+TABLE_PREFIX+"MacKeys LIMIT 1").option(row =>
      MacKey(row.getString("sClientKey"), row.getString("sWrappedKey"))
    )
  }

  override def addMacKey(key: MacKey) = {
    deleteMacKeys();

    logger.trace("Adding mac key: {}", key)

    execute("INSERT INTO "+TABLE_PREFIX+"MacKeys (sClientKey, sWrappedKey) VALUES (?, ?)", key.clientKey, key.wrappedKey)
  }

  override def deleteMacKeys() = {
    logger.trace("Deleting mac keys")

    execute("DELETE FROM "+TABLE_PREFIX+"MacKeys")
  }

  override def reset(list: String) = {
    logger.warn("Reseting database for list: {}", list)
    
    execute("DELETE FROM "+TABLE_PREFIX+"SubChunks WHERE sList = ?", list);

    execute("DELETE FROM "+TABLE_PREFIX+"AddChunks WHERE sList = ?", list);

    execute("DELETE FROM "+TABLE_PREFIX+"FullHashes WHERE sList = ?", list);

    execute("DELETE FROM "+TABLE_PREFIX+"FullHashErrors");

    execute("DELETE FROM "+TABLE_PREFIX+"Updates WHERE sList = ?", list);
  }

  override def clearExpiredHashes = {
    execute("DELETE FROM "+TABLE_PREFIX+"FullHashes WHERE dtLastupdate < ?", new DateTime().minusMinutes(45))
  }
  
  override def getDatabaseStats: Map[String, String] = {
    val addChunks = query("SELECT count(*) as c FROM "+TABLE_PREFIX+"AddChunks").single[Int]
    val subChunks = query("SELECT count(*) as c FROM "+TABLE_PREFIX+"SubChunks").single[Int]
    val fullHashes = query("SELECT count(*) as c FROM "+TABLE_PREFIX+"FullHashes").single[Int]
    val fullHasheErrors = query("SELECT count(*) as c FROM "+TABLE_PREFIX+"FullHashErrors").single[Int]
    
    Map("Add chunk count" -> addChunks.toString,
        "Sub chunk count" -> subChunks.toString,
        "Full hash count" -> fullHashes.toString,
        "Full hash error count" -> fullHasheErrors.toString
        )
  }
  
  /**
   * Calculate error count and nextAttempt for updates
   * @see https://developers.google.com/safe-browsing/developers_guide_v2#RequestFrequencyData
   */
  protected[db] def updateBackoff(thisAttempt: DateTime, lastUpdate: Status): (Int, DateTime) = {
     // lastUpdate.errors will always be >= 1 here
    val errors = lastUpdate.errors + 1
    val lastWaitSeconds = new Duration(lastUpdate.lastAttempt, lastUpdate.nextAttempt).getStandardSeconds()
    val wait = errors match {
      case e if e < 2 => Period.minutes(1) // should never match but just to be safe
      case 2 => Period.minutes(30 + (math.random * 1).toInt)
      case e if e > 2 && e <= 5 => Period.seconds((lastWaitSeconds * 2).toInt)
      case e if e > 5 => Period.minutes(480)
    }
    val nextAttempt = thisAttempt.plus(wait)
    (errors, nextAttempt)
  }
  
  /**
   * Calculate error count and nextAttempt using full hash requests
   * @see https://developers.google.com/safe-browsing/developers_guide_v2#RequestFrequencyHashes
   */
  protected[db] def fullHashBackoff(thisAttempt: DateTime, lastError: Status): (Int, DateTime) = {
    // lastError.errors will always be >= 1 here
    var errors = lastError.errors+1
    val secondsSinceLast = new Duration(lastError.lastAttempt, thisAttempt).getStandardSeconds()
    val wait = errors match {
      // this is second error but last error was more than 5 minutes ago: no back off
      case e if e <= 2 && secondsSinceLast > 5*60 => errors = 1; Period.ZERO 
      case 2 => Period.minutes(30) // 2 errors within last 5 minutes: enter back off mode 
      case 3 => Period.hours(1)
      case e => Period.hours(2)
    }
    val nextAttempt = thisAttempt.plus(wait)
    (errors, nextAttempt)
  }
}
