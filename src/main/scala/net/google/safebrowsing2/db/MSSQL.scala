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
import util.Logging

/**
 * MSSQL Storage class used to access the database.
 * 
 * @see DBI
 */
class MSSQL(jt: JdbcTemplate, tablePrefix: String) extends DBI(jt, tablePrefix) {
  def this(ds: () => Connection, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)
  def this(ds: LiteDataSource, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)
  def this(ds: DataSource, tablePrefix: String) = this(new JdbcTemplate(ds), tablePrefix)

  import jt._
  
  override def createTableUpdates = {
    logger.debug("Creating table: "+TABLE_PREFIX+"Updates")
    val schema = """	
		CREATE TABLE """+TABLE_PREFIX+"""Updates (
		    sList VARCHAR( 50 ) NOT NULL PRIMARY KEY,
			dtLastSuccess DATETIME,
			dtLastAttempt DATETIME NOT NULL,
			dtNextAttempt DATETIME NOT NULL,
			iErrorCount INT NOT NULL
		)
	"""

    execute(schema)
  }

  override def createTableAddChunks = {
    logger.debug("Creating table: "+TABLE_PREFIX+"AddChunks")
    val schema = """	
		CREATE TABLE """+TABLE_PREFIX+"""AddChunks (
			sHostkey VARCHAR( 8 ),
			sPrefix VARCHAR( 64 ),
			iAddChunkNum INT NOT NULL,
			sList VARCHAR( 50 ) NOT NULL,
      		PRIMARY KEY (sHostkey,sPrefix,iAddChunkNum,sList)
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
  }

  override def createTableSubChunks = {
    logger.debug("Creating table: "+TABLE_PREFIX+"SubChunks")
    var schema = """
		CREATE TABLE """+TABLE_PREFIX+"""SubChunks (
			sHostkey VARCHAR( 8 ),
			sPrefix VARCHAR( 64 ),
			iSubChunkNum INT NOT NULL,
			iAddChunkNum INT NOT NULL,
			sList VARCHAR( 50 ) NOT NULL,
      		PRIMARY KEY (sHostkey,sPrefix,iSubChunkNum,iAddChunkNum,sList)
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
  }

  override def createTableFullHashes = {
    logger.debug("Creating table: "+TABLE_PREFIX+"FullHashes")
    val schema = """
		CREATE TABLE """+TABLE_PREFIX+"""FullHashes (
			pkiFullHashesID INT NOT NULL IDENTITY(1,1) PRIMARY KEY,
			iAddChunkNum INT,
			sHash VARCHAR( 64 ),
			sList VARCHAR( 50 ),
			dtLastUpdate DATETIME NOT NULL,
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

  override def createTableFullHashErrors = {
    logger.debug("Creating table: "+TABLE_PREFIX+"FullHashErrors")
    val schema = """
		CREATE TABLE """+TABLE_PREFIX+"""FullHashErrors (
			pkiFullHasheErrorsID INT NOT NULL IDENTITY(1,1) PRIMARY KEY,
			dtLastAttempt DATETIME NOT NULL,
			dtNextAttempt DATETIME NOT NULL,
			iErrorCount INT NOT NULL,
			sPrefix VARCHAR( 64 )
		)
	"""

    execute(schema)
  }

  override def createTableMacKeys = {
    logger.debug("Creating table: "+TABLE_PREFIX+"MacKeys")
    val schema = """
		CREATE TABLE """+TABLE_PREFIX+"""MacKeys (
			sClientKey VARCHAR( 50 ),
			sWrappedKey VARCHAR( 150 )
		)
	"""

    execute(schema)
  }
  
  override def getMacKey(): Option[MacKey] = {
    query("SELECT TOP 1 sClientKey, sWrappedKey FROM "+TABLE_PREFIX+"MacKeys").option(row =>
      MacKey(row.getString("sClientKey"), row.getString("sWrappedKey"))
    )
  }
}