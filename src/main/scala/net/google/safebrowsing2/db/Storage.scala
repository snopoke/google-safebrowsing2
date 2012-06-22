package net.google.safebrowsing2.db

import java.util.{List => JavaList}
import net.google.safebrowsing2.MacKey
import net.google.safebrowsing2.Hash
import net.google.safebrowsing2.Chunk
import net.google.safebrowsing2.Status
import org.joda.time.ReadableInstant
import net.google.safebrowsing2.Expression

trait Storage {

  def addChunks_s(chunknum: Int, hostkey: String, chunks: Seq[(Int,String)], list: String)

  def addChunks_a(chunknum: Int, hostkey: String, prefixes: Seq[String], list: String)

  def getAddChunks(hostkey: String): Seq[Chunk]

  def getSubChunks(hostkey: String): Seq[Chunk]

  def getAddChunksNums(list: String): Seq[Int]

  def getSubChunksNums(list: String): Seq[Int]

  def deleteAddChunks(chunknums: Seq[Int], list: String)

  def deleteSubChunks(chunknums: Seq[Int], list: String)

  def getFullHashes(chunknum: Int, timestamp: ReadableInstant, list: String): Seq[String]

  def updated(timestamp: ReadableInstant, wait: Int, list: String)

  def updateError(timestamp: ReadableInstant, list: String, wait: Int = 60, errors: Int = 1)

  def lastUpdate(list: String): Option[Status]

  def addFullHashes(timestamp: ReadableInstant, full_hashes: Seq[Hash])

  def deleteFullHashes(chunknums: Seq[Int], list: String)

  def fullHashError(timestamp: ReadableInstant, prefix: String)

  def clearFullhashErrors(expressions: Seq[Chunk])

  def getFullHashError(prefix: String): Option[Status]

  def getMacKey: Option[MacKey]

  def addMacKey(key: MacKey)

  def delete_mac_keys

  def reset(list: String)
  
  def clearExpiredHashes

}