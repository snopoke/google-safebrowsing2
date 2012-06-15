package net.google.safebrowsing2

import java.util.Collection
import java.util.Date
import java.util.{List => JavaList}
import net.google.safebrowsing2.model.ChunkType
import net.google.safebrowsing2.model.Hash
import net.google.safebrowsing2.model.Chunk
import net.google.safebrowsing2.model.Status
import net.google.safebrowsing2.model.MacKey

trait Storage {

  def addChunks(t: ChunkType, chunknum: Int, chunks: Collection[Chunk], list: String)

  def addChunks_s(chunknum: Int, chunks: Collection[Chunk], list: String)

  def addChunks_a(chunknum: Int, chunks: Collection[Chunk], list: String)

  def getAddChunks(hostkey: String): Collection[Chunk]

  def getSubChunks(hostkey: String): Collection[Chunk]

  def getAddChunksNums(list: String): Seq[Int]

  def getSubChunksNums(list: String): Seq[Int]

  def deleteAddChunks(chunknums: Seq[Int], list: String)

  def deleteSubChunks(chunknums: Seq[Int], list: String)

  def getFullHashes(chunknum: Int, timestamp: Date, list: String): JavaList[String]

  def updated(time: Date, wait: Int, list: String)

  def updateError(time: Date, list: String, wait: Int = 60, errors: Int = 1)

  def lastUpdate(list: String): Status

  def addFullHashes(timestamp: Date, full_hashes: Collection[Hash])

  def deleteFullHashes(chunknums: Seq[Int], list: String)

  def fullHashError(timestamp: Date, prefix: String)

  def fullHashOK(timestamp: Date, prefix: String)

  def getFullHashError(prefix: String): Option[Status]

  def getMacKey(): Option[MacKey]

  def addMacKey(key: MacKey)

  def delete_mac_keys()

  def reset(list: String)

}