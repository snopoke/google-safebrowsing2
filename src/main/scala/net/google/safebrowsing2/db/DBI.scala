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
 * Usage:
 * new DBI(dataSource)
 * new DBI(connection)
 * new DBI(LiteDataSource.driverManager("jdbc:mysql://localhost:3306/googlesafebrowsing2"))
 * new DBI(LiteDataSource.driverManager("jdbc:mysql://localhost:3306/googlesafebrowsing2", "root", "root"))
 */
class DBI(jt: JdbcTemplate) extends Storage {
    def this(ds: () => Connection) = this(new JdbcTemplate(ds))
    def this(ds: LiteDataSource) = this(new JdbcTemplate(ds))
    def this(ds: DataSource) = this(new JdbcTemplate(ds))

  import jt._
    
  init

  /**
   * Should create tables if needed
   */
  def init = {
    val tables = mutable.ListBuffer("updates", "a_chunks", "s_chunks", "full_hashes", "full_hashes_errors", "mac_keys")
    metaData(meta => {
      val res = meta.getTables(null, null, "%", null)
      while (res.next()){
        val table = res.getString("TABLE_NAME")
        if (tables.contains(table)){
        	logger.debug("Table already exists: {}. Skipping table createion.", table)
        	tables -= table
      	}
      }
      res.close()
    })
    
    tables.foreach(_ match {
      case "updates" => create_table_updates
      case "a_chunks" => create_table_a_chunks
      case "s_chunks" => create_table_s_chunks
      case "full_hashes" => create_table_full_hashes
      case "full_hashes_errors" => create_table_full_hashes_errors
      case "mac_keys" => create_table_mac_keys
      case x => logger.warn("Unknown table: {}", x)
    })
  }

  def create_table_updates = {
    logger.debug("Creating table: updates")
    val schema = """	
		CREATE TABLE updates (
			last TIMESTAMP NOT NULL DEFAULT 0,
			wait INT NOT NULL DEFAULT '0',
			errors INT NOT NULL DEFAULT '1800',
			list VARCHAR( 50 ) NOT NULL
		)
	"""

    execute(schema)
  }

  def create_table_a_chunks = {
    logger.debug("Creating table: a_chunks")
    val schema = """	
		CREATE TABLE a_chunks (
			hostkey VARCHAR( 8 ),
			prefix VARCHAR( 64 ),
			num INT NOT NULL,
			list VARCHAR( 50 ) NOT NULL
		)
	"""

    execute(schema)

    var index = """	
		CREATE INDEX a_chunks_hostkey ON a_chunks (
			hostkey
		)
	"""
    execute(index)

    index = """
		CREATE INDEX a_chunks_num_list ON a_chunks (
			num,
			list
		)
	"""
    execute(index)

    index = """
		CREATE UNIQUE INDEX a_chunks_unique ON a_chunks (
			hostkey,
			prefix,
			num,
			list
		)
	"""
    execute(index)
  }

  def create_table_s_chunks = {
    logger.debug("Creating table: s_chunks")
    var schema = """
		CREATE TABLE s_chunks (
			hostkey VARCHAR( 8 ),
			prefix VARCHAR( 64 ),
			num INT NOT NULL,
			add_num INT  Default '0',
			list VARCHAR( 50 ) NOT NULL
		)
	"""

    execute(schema)

    var index = """
		CREATE INDEX s_chunks_hostkey ON s_chunks (
			hostkey
		)
	"""
    execute(index)

    index = """
		CREATE INDEX s_chunks_num ON s_chunks (
			num
		)
	"""
    execute(index)

    index = """
		CREATE INDEX s_chunks_num_list ON s_chunks (
			num,
			list
		)
	"""
    execute(index)

    index = """
		CREATE UNIQUE INDEX s_chunks_unique ON s_chunks (
			hostkey,
			prefix,
			num,
			add_num,
			list
		)
	"""
    execute(index)
  }

  def create_table_full_hashes = {
    logger.debug("Creating table: full_hashes")
    val schema = """
		CREATE TABLE full_hashes (
			id INT AUTO_INCREMENT PRIMARY KEY,
			num INT,
			hash VARCHAR( 64 ),
			list VARCHAR( 50 ),
			timestamp TIMESTAMP Default 0
		)
	"""

    execute(schema)

    val index = """
		CREATE UNIQUE INDEX hash ON full_hashes (
			num,
			hash,
			list
		)
	"""
    execute(index)
  }

  def create_table_full_hashes_errors = {
    logger.debug("Creating table: full_hashes_errors")
    val schema = """
		CREATE TABLE full_hashes_errors (
			id INT AUTO_INCREMENT PRIMARY KEY,
			errors INT Default '0',
			prefix VARCHAR( 64 ),
			timestamp TIMESTAMP Default 0
		)
	"""

    execute(schema)
  }

  def create_table_mac_keys = {
    logger.debug("Creating table: mac_keys")
    val schema = """
		CREATE TABLE mac_keys (
			client_key VARCHAR( 50 ) Default '',
			wrapped_key VARCHAR( 150 ) Default ''
		)
	"""

    execute(schema)
  }

  override def addChunks_s(chunknum: Int, hostkey: String, chunks: Seq[(Int,String)], list: String) = {
    logger.trace("Inserting subChunk: [chunknum={}, hostkey={}, chunks={}, list={}",
        Array[Object](chunknum: java.lang.Integer, hostkey, chunks, list))
     
    val delQuery = "DELETE FROM s_chunks WHERE hostkey = ? AND prefix = ? AND num = ? AND add_num = ? AND list = ?"
    val addQuery = "INSERT INTO s_chunks (hostkey, prefix, num, add_num, list) VALUES (?, ?, ?, ?, ?)"

    chunks foreach (tuple => {
      execute(delQuery, hostkey, tuple._2, chunknum, tuple._1, list)
      execute(addQuery, hostkey, tuple._2, chunknum, tuple._1, list)
    })

    if (chunks.isEmpty) { // keep empty chunks
      execute(delQuery, "", "", chunknum, 0, list)
      execute(addQuery, "", "", chunknum, 0, list)
    }
  }

  override def addChunks_a(chunknum: Int, hostkey: String, prefixes: Seq[String], list: String) = {
    logger.trace("Inserting addChunk: [chunknum={}, hostkey={}, prefixes={}, list={}",
        Array[Object](chunknum: java.lang.Integer, hostkey, prefixes, list))
        
    val delQuery = "DELETE FROM a_chunks WHERE hostkey = ? AND  prefix  = ? AND num = ? AND list  = ?"
    val addQuery = "INSERT INTO a_chunks (hostkey, prefix, num, list) VALUES (?, ?, ?, ?)"

    prefixes foreach (prefix => {
      execute(delQuery, hostkey, prefix, chunknum, list)
      execute(addQuery, hostkey, prefix, chunknum, list)
    })

    if (prefixes.isEmpty) { // keep empty chunks
      execute(delQuery, "", "", chunknum, list)
      execute(addQuery, "", "", chunknum, list)
    }
  }

  override def getAddChunks(hostkey: String): Seq[Chunk] = {
    query("SELECT * FROM a_chunks WHERE hostkey = ?", hostkey).seq(row =>
      Chunk(row.getInt("num"), row.getString("prefix"), hostkey, row.getString("list"), -1)
    )
  }

  override def getSubChunks(hostkey: String): Seq[Chunk] = {
    query("SELECT * FROM s_chunks WHERE hostkey = ?", hostkey).seq(row =>
      Chunk(row.getInt("num"), row.getString("prefix"), hostkey, row.getString("list"), row.getInt("add_num"))
    )
  }

  override def getAddChunksNums(list: String): Seq[Int] = {
    query("SELECT DISTINCT(num) FROM a_chunks WHERE list = ? ORDER BY num ASC", list).seq[Int].sorted
  }

  override def getSubChunksNums(list: String): Seq[Int] = {
    query("SELECT DISTINCT(num) FROM s_chunks WHERE list = ? ORDER BY num ASC", list).seq[Int].sorted
  }

  override def deleteAddChunks(chunknums: Seq[Int], list: String) = {
    logger.trace("Delete add chunks: [chunknums={}, list={}]", chunknums, list)
    
    val params = chunknums map (cn => Seq(cn, list))
    executeBatch("DELETE FROM a_chunks WHERE num = ? AND list = ?", params)
  }

  override def deleteSubChunks(chunknums: Seq[Int], list: String) = {
    logger.trace("Delete sub chunks: [chunknums={}, list={}]", chunknums, list)
    
    val query = "DELETE FROM s_chunks WHERE num = ? AND list = ?"

    chunknums foreach (num => {
      execute(query, num, list)
    })
  }

  override def getFullHashes(chunknum: Int, timestamp: ReadableInstant, list: String): Seq[String] = {
    query("SELECT hash FROM full_hashes WHERE timestamp >= ? AND num = ? AND list = ?", chunknum, timestamp, list).seq[String]
  }

  override def updated(time: ReadableInstant, wait: Int, list: String) = {
    if (lastUpdate(list).isEmpty) {
      execute("INSERT INTO updates (last, wait, errors, list) VALUES (?, ?, 0, ?)", time, wait, list)
    } else {
      execute("UPDATE updates SET last = ?, wait = ?, errors = 0 WHERE list = ?", time, wait, list)
    }
  }

  override def updateError(time: ReadableInstant, list: String, wait: Int = 60, errors: Int = 1) = {
    val status = lastUpdate(list)
    if (status.isEmpty) {
      execute("INSERT INTO updates (last, wait, errors, list) VALUES (?, ?, ?, ?)", time, wait, errors, list)
    } else {
      execute("UPDATE updates SET last = ?, wait = ?, errors = ? WHERE list = ?", time, wait, status.get.errors + errors, list)
    }
  }

  override def lastUpdate(list: String): Option[Status] = {
    query("SELECT last, wait, errors FROM updates WHERE list = ? LIMIT 1", list).option(row => {
      val time = Option(row.getTimestamp("last")).getOrElse(new Date(0))
      val wait = Option(row.getInt("wait")).getOrElse(30*60) // 30 minutes default
      val errors = Option(row.getInt("errors")).getOrElse(0)
      Status(new DateTime(time), Period.seconds(wait), errors)
    })
  }

  override def addFullHashes(timestamp: ReadableInstant, full_hashes: Seq[Hash]) = {
    logger.trace("Add full hashes: {}", full_hashes)
    
    val deleteParams = full_hashes map (hash => Seq(hash.chunknum, hash.hash, hash.list))
    val insertParams = full_hashes map (hash => Seq(hash.chunknum, hash.hash, hash.list, timestamp))
    executeBatch("DELETE FROM full_hashes WHERE num = ? AND hash = ? AND list = ?", deleteParams)
    executeBatch("INSERT INTO full_hashes (num, hash, list, timestamp) VALUES (?, ?, ?, ?)", insertParams)
  }

  override def deleteFullHashes(chunknums: Seq[Int], list: String) = {
    logger.trace("Delete full hashes: [chunknums={}, list={}]", chunknums, list)
    
    val params = chunknums map (cn => Seq(cn, list))
    executeBatch("DELETE FROM full_hashes WHERE num = ? AND list = ?", params)
  }

  override def fullHashError(timestamp: ReadableInstant, prefix: String) = {
    val existing = query("SELECT id, errors FROM full_hashes_errors WHERE prefix = ? LIMIT 1", prefix).option(row =>
      (row.getInt("errors"), row.getInt("id"))
    )

    existing match {
      case None => execute("INSERT INTO full_hashes_errors (prefix, errors, timestamp) VALUES (?, 1, ?)", prefix, timestamp)
      case Some((errors, id)) => execute("UPDATE full_hashes_errors SET errors = ?, timestamp = ? WHERE id = ?", errors + 1, timestamp, id)
    }
  }

  override def clearFullhashErrors(chunks: Seq[Chunk]) = {
    val params = chunks.map(c => Seq(c.prefix))
    executeBatch("DELETE FROM full_hashes_errors WHERE prefix = ?", params)
  }

  override def getFullHashError(prefix: String): Option[Status] = {
    query("SELECT timestamp, errors FROM full_hashes_errors WHERE prefix = ? LIMIT 1", prefix).option(row =>
      new Status(new DateTime(row.getTimestamp("timestamp")), Period.ZERO, row.getInt("errors"))
    )
  }

  override def getMacKey(): Option[MacKey] = {
    query("SELECT client_key, wrapped_key FROM mac_keys LIMIT 1").option(row =>
      MacKey(row.getString("client_key"), row.getString("wrapped_key"))
    )
  }

  override def addMacKey(key: MacKey) = {
    delete_mac_keys();

    logger.trace("Adding mac key: {}", key)

    execute("INSERT INTO mac_keys (client_key, wrapped_key) VALUES (?, ?)", key.clientKey, key.wrappedKey)
  }

  override def delete_mac_keys() = {
    logger.trace("Deleting mac keys")
    
    execute("DELETE FROM mac_keys WHERE 1")
  }

  override def reset(list: String) = {
    logger.warn("Reseting database for list: {}", list)
    
    execute("DELETE FROM s_chunks WHERE list = ?", list);

    execute("DELETE FROM a_chunks WHERE list = ?", list);

    execute("DELETE FROM full_hashes WHERE list = ?", list);

    execute("DELETE FROM full_hashes_errors", list);

    execute("DELETE FROM updates WHERE list = ?", list);
  }
  
  def clearExpiredHashes = {
    execute("DELETE FROM full_hashes WHERE timestamp < ?", new DateTime().minusMinutes(45))
  }
}