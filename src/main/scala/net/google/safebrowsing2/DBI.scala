package net.google.safebrowsing2
import java.util.Collection
import java.util.Date
import java.util.{ List => JavaList }
import com.twitter.querulous.evaluator.QueryEvaluator
import net.google.safebrowsing2.model.Chunk
import net.google.safebrowsing2.model.Hash
import net.google.safebrowsing2.model.MacKey
import net.google.safebrowsing2.model.Status
import net.google.safebrowsing2.SafeBrowsing2._
import scala.collection.JavaConversions._
import scala.collection.JavaConverters._
import com.twitter.querulous.evaluator.ParamsApplier
import com.twitter.querulous.query.QueryClass

abstract class DBI(queryEvaluator: QueryEvaluator) extends Storage {

  var keepAll: Boolean = true

  def close = {
    if (!keepAll) {
      queryEvaluator.execute("DELETE FROM full_hashes WHERE timestamp < ?", new Date().getTime() - FULL_HASH_TIME)
    }

    // close connection
  }

  /**
   * Should connect to the database and create tables if needed
   */
  def init

  def create_table_updates = {

    val schema = """	
		CREATE TABLE updates (
			last INT NOT NULL DEFAULT '0',
			wait INT NOT NULL DEFAULT '0',
			errors INT NOT NULL DEFAULT '1800',
			list VARCHAR( 50 ) NOT NULL
		)
	"""

    queryEvaluator.execute(schema)
  }

  def create_table_a_chunks = {

    val schema = """	
		CREATE TABLE a_chunks (
			hostkey VARCHAR( 8 ),
			prefix VARCHAR( 8 ),
			num INT NOT NULL,
			list VARCHAR( 50 ) NOT NULL
		)
	"""

    queryEvaluator.execute(schema)

    var index = """	
		CREATE INDEX a_chunks_hostkey ON a_chunks (
			hostkey
		)
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE INDEX a_chunks_num_list ON a_chunks (
			num,
			list
		)
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE UNIQUE INDEX a_chunks_unique ON a_chunks (
			hostkey,
			prefix,
			num,
			list
		)
	"""
    queryEvaluator.execute(index)
  }

  def create_table_s_chunks = {

    var schema = """
		CREATE TABLE s_chunks (
			hostkey VARCHAR( 8 ),
			prefix VARCHAR( 8 ),
			num INT NOT NULL,
			add_num INT  Default '0',
			list VARCHAR( 50 ) NOT NULL
		)
	"""

    queryEvaluator.execute(schema)

    var index = """
		CREATE INDEX s_chunks_hostkey ON s_chunks (
			hostkey
		)
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE INDEX s_chunks_num ON s_chunks (
			num
		)
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE INDEX s_chunks_num_list ON s_chunks (
			num,
			list
		)
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE UNIQUE INDEX s_chunks_unique ON s_chunks (
			hostkey,
			prefix,
			num,
			add_num,
			list
		)
	"""
    queryEvaluator.execute(index)
  }

  def create_table_full_hashes = {

    val schema = """
		CREATE TABLE full_hashes (
			id INT AUTO_INCREMENT PRIMARY KEY,
			num INT,
			hash VARCHAR( 32 ),
			list VARCHAR( 50 ),
			timestamp INT Default '0'
		)
	"""

    queryEvaluator.execute(schema)

    val index = """
		CREATE UNIQUE INDEX hash ON full_hashes (
			num,
			hash,
			list
		)
	"""
    queryEvaluator.execute(index)
  }

  def create_table_full_hashes_errors = {

    val schema = """
		CREATE TABLE full_hashes_errors (
			id INT AUTO_INCREMENT PRIMARY KEY,
			errors INT Default '0',
			prefix VARCHAR( 8 ),
			timestamp INT Default '0'
		)
	"""

    queryEvaluator.execute(schema)
  }

  def create_table_mac_keys = {

    val schema = """
		CREATE TABLE mac_keys (
			client_key VARCHAR( 50 ) Default '',
			wrapped_key VARCHAR( 50 ) Default ''
		)
	"""

    queryEvaluator.execute(schema)
  }

  override def addChunks_s(chunknum: Int, hostkey: String, chunks: List[(String,String)], list: String) = {

    val delQuery = "DELETE FROM s_chunks WHERE hostkey = ? AND prefix = ? AND num = ? AND add_num = ? AND list = ?"
    val addQuery = "INSERT INTO s_chunks (hostkey, prefix, num, add_num, list) VALUES (?, ?, ?, ?, ?)"

    chunks foreach (tuple => {
      queryEvaluator.execute(delQuery, hostkey, tuple._2, chunknum, tuple._1, list)
      queryEvaluator.insert(addQuery, hostkey, tuple._2, chunknum, tuple._1, list)
    })

    if (chunks.isEmpty) { // keep empty chunks
      queryEvaluator.execute(delQuery, "", "", chunknum, "", list)
      queryEvaluator.insert(addQuery, "", "", chunknum, "", list)
    }
  }

  override def addChunks_a(chunknum: Int, hostkey: String, prefixes: List[String], list: String) = {

    val delQuery = "DELETE FROM a_chunks WHERE hostkey = ? AND  prefix  = ? AND num = ? AND  list  = ?"
    val addQuery = "INSERT INTO a_chunks (hostkey, prefix, num, list) VALUES (?, ?, ?, ?)"

    prefixes foreach (prefix => {
      queryEvaluator.execute(delQuery, hostkey, prefix, chunknum, list)
      queryEvaluator.insert(addQuery, hostkey, prefix, chunknum, list)
    })

    if (prefixes.isEmpty) { // keep empty chunks
      queryEvaluator.execute(delQuery, "", "", chunknum, list)
      queryEvaluator.insert(addQuery, "", "", chunknum, list)
    }
  }

  override def getAddChunks(hostkey: String): Seq[Chunk] = {
    queryEvaluator.select[Chunk]("SELECT * FROM a_chunks WHERE hostkey = ?", hostkey) { row =>
      new Chunk(row.getInt("num"), row.getString("prefix"), hostkey, row.getString("list"))
    }
  }

  override def getSubChunks(hostkey: String): Seq[Chunk] = {
    queryEvaluator.select[Chunk]("SELECT * FROM s_chunks WHERE hostkey = ?", hostkey) { row =>
      new Chunk(row.getInt("num"), row.getString("prefix"), row.getInt("add_num"), row.getString("list"))
    }
  }

  override def getAddChunksNums(list: String): Seq[Int] = {
    val nums = queryEvaluator.select("SELECT DISTINCT(num) FROM a_chunks WHERE list = ? ORDER BY num ASC", list) { row =>
      row.getInt("num")
    }.sorted

    nums
  }

  override def getSubChunksNums(list: String): Seq[Int] = {
    val nums = queryEvaluator.select("SELECT DISTINCT(num) FROM s_chunks WHERE list = ? ORDER BY num ASC", list) { row =>
      row.getInt("num")
    }.sorted

    nums
  }

  override def deleteAddChunks(chunknums: Seq[Int], list: String) = {
    val query = queryEvaluator.executeBatch("DELETE FROM a_chunks WHERE num = ? AND list = ?")_

    // TODO test this!!
    chunknums foreach (num => {
      query(a => a(num, list))
    })
  }

  override def deleteSubChunks(chunknums: Seq[Int], list: String) = {
    val query = "DELETE FROM s_chunks WHERE num = ? AND list = ?"

    chunknums foreach (num => {
      queryEvaluator.execute(query, num, list)
    })
  }

  override def getFullHashes(chunknum: Int, timestamp: Long, list: String): Seq[String] = {
    val query = "SELECT hash FROM full_hashes WHERE timestamp >= ? AND num = ? AND list = ?"

    queryEvaluator.select[String](query, timestamp, chunknum, list) { row =>
      row.getString("hash")
    }
  }

  override def updated(time: Date, wait: Int, list: String) = {
    if (lastUpdate(list) == 0) {
      queryEvaluator.insert("INSERT INTO updates (last, wait, errors, list) VALUES (?, ?, 0, ?)", time.getTime(), wait, list)
    } else {
      queryEvaluator.execute("UPDATE updates SET last = ?, wait = ?, errors = 0 WHERE list = ?", time.getTime(), wait, list)
    }
  }

  override def updateError(time: Date, list: String, wait: Int = 60, errors: Int = 1) = {
    if (lastUpdate(list).updateTime == 0) {
      queryEvaluator.insert("INSERT INTO updates (last, wait, errors, list) VALUES (?, ?, 0, ?)", time.getTime(), wait, list)
    } else {
      queryEvaluator.execute("UPDATE updates SET last = ?, wait = ?, errors = 0 WHERE list = ?", time.getTime(), wait, list)
    }
  }

  override def lastUpdate(list: String): Status = {
    queryEvaluator.selectOne[Status]("SELECT last, wait, errors FROM updates WHERE list = ? LIMIT 1", list) { row =>
      val time = Option(row.getInt("last")).getOrElse(0)
      val wait = Option(row.getInt("wait")).getOrElse(1800)
      val errors = Option(row.getInt("errors")).getOrElse(0)
      new Status(time, wait, errors)
    } getOrElse {
      new Status(0, 1800, 0)
    }
  }

  override def addFullHashes(timestamp: Date, full_hashes: Collection[Hash]) = {
    full_hashes foreach (hash => {
      queryEvaluator.execute("DELETE FROM full_hashes WHERE num = ? AND hash = ? AND list = ?", hash.getChunknum(), hash.getHash(), hash.getList())
      queryEvaluator.insert("INSERT INTO full_hashes (num, hash, list, timestamp) VALUES (?, ?, ?, ?)", hash.getChunknum(), hash.getHash(), hash.getList(), timestamp)
    })
  }

  override def deleteFullHashes(chunknums: Seq[Int], list: String) = {
    val query = queryEvaluator.executeBatch("DELETE FROM full_hashes WHERE num = ? AND list = ?")_
    chunknums foreach (chunk => {
      query(_(chunk, list))
    })
  }

  override def fullHashError(timestamp: Date, prefix: String) = {
    val existing = queryEvaluator.selectOne("SELECT id, errors FROM full_hashes_errors WHERE prefix = ? LIMIT 1", prefix) { row =>
      (row.getInt("errors"), row.getInt("id"))
    }

    existing match {
      case None => queryEvaluator.insert("INSERT INTO full_hashes_errors (prefix, errors, timestamp) VALUES (?, 1, ?)", prefix, timestamp)
      case Some((errors, id)) => queryEvaluator.execute("UPDATE full_hashes_errors SET errors = ?, timestamp = ? WHERE id = ?", errors + 1, timestamp, id)
    }
  }

  override def fullHashOK(timestamp: Date, prefix: String) = {
    val existing = queryEvaluator.selectOne("SELECT id FROM full_hashes_errors WHERE prefix = ? AND errors > 0 LIMIT 1", prefix) { row =>
      row.getInt("id")
    }

    existing match {
      case Some(id) => {
        queryEvaluator.execute("UPDATE full_hashes_errors SET errors = 0, timestamp = ? WHERE id = ?", timestamp, id);
        queryEvaluator.execute("DELETE FROM full_hashes_errors WHERE id = ?", id);
      }
      case _ => {}
    }
  }

  override def getFullHashError(prefix: String): Option[Status] = {
    queryEvaluator.selectOne("SELECT timestamp, errors FROM full_hashes_errors WHERE prefix = ? LIMIT 1", prefix) { row =>
      new Status(row.getInt("timestamp"), 0, row.getInt("errors"))
    }
  }

  override def getMacKey(): Option[MacKey] = {
    queryEvaluator.selectOne("SELECT client_key, wrapped_key FROM mac_keys LIMIT 1") { row =>
      new MacKey(row.getString("client_key"), row.getString("wrapped_key"))
    }
  }

  override def addMacKey(key: MacKey) = {
    delete_mac_keys();

    queryEvaluator.insert("INSERT INTO mac_keys (client_key, wrapped_key) VALUES (?, ?)", key.getClientKey(), key.getWrappedKey())
  }

  override def delete_mac_keys() = {
    queryEvaluator.execute("DELETE FROM mac_keys WHERE 1")
  }

  override def reset(list: String) = {
    queryEvaluator.execute("DELETE FROM s_chunks WHERE list = ?", list);

    queryEvaluator.execute("DELETE FROM a_chunks WHERE list = ?", list);

    queryEvaluator.execute("DELETE FROM full_hashes WHERE list = ?", list);

    queryEvaluator.execute("DELETE FROM full_hashes_errors", list);

    queryEvaluator.execute("DELETE FROM updates WHERE list = ?", list);
  }

}