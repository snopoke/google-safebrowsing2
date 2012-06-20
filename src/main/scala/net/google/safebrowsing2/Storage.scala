package net.google.safebrowsing2

import java.util.Collection
import java.util.Date
import java.util.{List => JavaList}
import net.google.safebrowsing2.model.Hash
import net.google.safebrowsing2.model.Chunk
import net.google.safebrowsing2.model.Status
import net.google.safebrowsing2.model.MacKey

trait Storage {

  def addChunks_s(chunknum: Int, hostkey: String, chunks: List[(String,String)], list: String)

  def addChunks_a(chunknum: Int, hostkey: String, prefixes: List[String], list: String)

  def getAddChunks(hostkey: String): Seq[Chunk]

  def getSubChunks(hostkey: String): Seq[Chunk]

  def getAddChunksNums(list: String): Seq[Int]

  def getSubChunksNums(list: String): Seq[Int]

  def deleteAddChunks(chunknums: Seq[Int], list: String)

  def deleteSubChunks(chunknums: Seq[Int], list: String)

  def getFullHashes(chunknum: Int, timestamp: Long, list: String): Seq[String]

  def updated(time: Date, wait: Int, list: String)

  def updateError(time: Date, list: String, wait: Int = 60, errors: Int = 1)

  def lastUpdate(list: String): Status

  def addFullHashes(timestamp: Date, full_hashes: Seq[Hash])

  def deleteFullHashes(chunknums: Seq[Int], list: String)

  def fullHashError(timestamp: Date, prefix: String)

  def fullHashOK(timestamp: Date, prefix: String)

  def getFullHashError(prefix: String): Option[Status]

  def getMacKey(): Option[MacKey]

  def addMacKey(key: MacKey)

  def delete_mac_keys()

  def reset(list: String)

}