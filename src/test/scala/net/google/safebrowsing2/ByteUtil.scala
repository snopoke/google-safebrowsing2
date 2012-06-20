package net.google.safebrowsing2

import util.Helpers._

trait ByteUtil {
  
  def bytes(start: Int, end: Int) = { ((start until end toList).toArray).map(_.toByte) }
  def byteString(len: Int) = { new String(bytes(0, len)) }
  def hexString(len: Int): String = { hexString(0, len) }
  def hexString(start: Int, end: Int): String = { bytes2Hex(bytes(start, end)) }

}