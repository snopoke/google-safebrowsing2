package net.google.safebrowsing2.model
import java.util.Date

case class Hash(chunknum: Int, hash: String, list: String)
case class Chunk(chunknum: Int, prefix: String, hostkey: String, list: String, addChunknum: Int)
case class MacKey(clientKey: String, wrappedKey: String)
case class Status(val updateTime: Int, val waitSecs: Int, val errors: Int) {
  lazy val waitMs = waitSecs * 1000
  lazy val waitUntil = new Date(updateTime + waitMs)
  lazy val updateDate = new Date(updateTime) 
}