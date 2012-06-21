package net.google.safebrowsing2
import java.util.Date
import org.joda.time.ReadableInstant
import org.joda.time.Period
import org.joda.time.DateTime

case class Hash(chunknum: Int, hash: String, list: String)
case class Chunk(chunknum: Int, prefix: String, hostkey: String, list: String, addChunknum: Int)
case class MacKey(clientKey: String, wrappedKey: String)
case class Status(val updateTime: DateTime, val waitPeriod: Period, val errors: Int) {
  lazy val waitUntil = updateTime.plus(waitPeriod)
}