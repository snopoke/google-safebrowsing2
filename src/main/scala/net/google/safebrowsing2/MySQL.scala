package net.google.safebrowsing2
import java.util.Collection
import java.util.Date
import java.util.{ List => JavaList }

import com.twitter.querulous.evaluator.QueryEvaluator

import net.google.safebrowsing2.model.Chunk
import net.google.safebrowsing2.model.ChunkType
import net.google.safebrowsing2.model.Hash
import net.google.safebrowsing2.model.MacKey
import net.google.safebrowsing2.model.Status

import scala.collection.JavaConversions._

abstract class MySQL(queryEvaluator: QueryEvaluator) extends DBI(queryEvaluator) {
  
  //  $self->{dbh} = DBI->connect("DBI:mysql:database=" . $self->{database} . ";host=" . $self->{host} . ";port=" . $self->{port}, $self->{username}, $self->{password}, {'RaiseError' => 1});
  //
  //	my @tables = $self->{dbh}->tables;
  //
  //	if (! defined first { $_ =~ '`updates`' } @tables) {
  //		$self->create_table_updates();
  //	}
  //	if (! defined first { $_ =~ '`a_chunks`' } @tables) {
  //		$self->create_table_a_chunks();
  //	}
  //	if (! defined first { $_ =~ '`s_chunks`' } @tables) { 
  //		$self->create_table_s_chunks();
  //	}
  //	if (! defined first { $_ =~ '`full_hashes`' } @tables) {
  //		$self->create_table_full_hashes();
  //	}
  //	if (! defined first { $_ =~ '`full_hashes_errors`' } @tables) { 
  //		$self->create_table_full_hashes_errors();
  //	}
  //	if (! defined first { $_ =~ '`mac_keys`' } @tables) { 
  //		$self->create_table_mac_keys();
  //	}

  override def create_table_updates = {

    val schema = """	
		CREATE TABLE updates (
			last INT NOT NULL DEFAULT '0',
			wait INT NOT NULL DEFAULT '0',
			errors INT NOT NULL DEFAULT '1800',
			list VARCHAR( 50 ) NOT NULL
		);
	"""

    queryEvaluator.execute(schema)
  }

  override def create_table_a_chunks = {

    val schema = """	
		CREATE TABLE a_chunks (
			hostkey VARBINARY( 8 ),
			prefix VARBINARY( 8 ),
			num INT NOT NULL,
			list VARCHAR( 50 ) NOT NULL
		);
	"""

    queryEvaluator.execute(schema)

    var index = """	
		CREATE INDEX a_chunks_hostkey ON a_chunks (
			hostkey
		);
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE INDEX a_chunks_num_list ON a_chunks (
			num,
			list
		);
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE UNIQUE INDEX a_chunks_unique ON a_chunks (
			hostkey,
			prefix,
			num,
			list
		);
	"""
    queryEvaluator.execute(index)
  }

  override def create_table_s_chunks = {

    var schema = """
		CREATE TABLE s_chunks (
			hostkey VARBINARY( 8 ),
			prefix VARBINARY( 8 ),
			num INT NOT NULL,
			add_num INT DEFAULT 0,
			list VARCHAR( 50 ) NOT NULL
		);
	"""

    queryEvaluator.execute(schema)

    var index = """
		CREATE INDEX s_chunks_hostkey ON s_chunks (
			hostkey
		);
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE INDEX s_chunks_num ON s_chunks (
			num
		);
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE INDEX s_chunks_num_list ON s_chunks (
			num,
			list
		);
	"""
    queryEvaluator.execute(index)

    index = """
		CREATE UNIQUE INDEX s_chunks_unique ON s_chunks (
			hostkey,
			prefix,
			num,
			add_num,
			list
		);
	"""
    queryEvaluator.execute(index)
  }

  override def create_table_full_hashes = {

    val schema = """
		CREATE TABLE full_hashes (
			id INT AUTO_INCREMENT PRIMARY KEY,
			num INT,
			hash VARBINARY( 32 ),
			list VARCHAR( 50 ),
			timestamp INT Default '0'
		);
	"""

    queryEvaluator.execute(schema)

    val index = """
		CREATE UNIQUE INDEX hash ON full_hashes (
			num,
			hash,
			list
		);
	"""
    queryEvaluator.execute(index)
  }

  override def create_table_full_hashes_errors = {

    val schema = """
		CREATE TABLE full_hashes_errors (
			id INT AUTO_INCREMENT PRIMARY KEY,
			errors INT Default '0',
			prefix VARBINARY( 8 ),
			timestamp INT Default '0'
		);
	"""

    queryEvaluator.execute(schema)
  }

  override def create_table_mac_keys = {

    val schema = """
		CREATE TABLE mac_keys (
			client_key VARCHAR( 50 ) Default '',
			wrapped_key VARCHAR( 50 ) Default ''
		);
	"""

    queryEvaluator.execute(schema)
  }

  override def addChunks_s(chunknum: Int, chunks: Collection[Chunk], list: String) = {

    val query = "INSERT IGNORE INTO s_chunks (hostkey, prefix, num, add_num, list) VALUES (?, ?, ?, ?, ?)"
    chunks foreach (chunk => {
      queryEvaluator.execute(query,
        chunk.getHostkey(), chunk.getPrefix(), chunknum, chunk.getAddChunknum(), list)
    })

    if (chunks.isEmpty) { // keep empty chunks
      queryEvaluator.execute(query, "", "", chunknum, "", list)
    }
  }

  override def addChunks_a(chunknum: Int, chunks: Collection[Chunk], list: String) = {
    val query = "INSERT IGNORE INTO a_chunks (hostkey, prefix, num, list) VALUES (?, ?, ?, ?)"

    chunks foreach (chunk => {
      // 32-byte prefix seen at chunk 69961
      // If this becomes more of a problem, the schema will have to be adjusted.
      if (chunk.getPrefix.length > 8) {
        chunk.setPrefix(chunk.getPrefix.substring(0, 4))
      }

      queryEvaluator.execute(query, chunk.getHostkey(), chunk.getPrefix(), chunknum, list)
    })

    if (chunks.isEmpty) { // keep empty chunks
      queryEvaluator.execute(query, "", "", chunknum, list)
    }
  }
}