package net.google.safebrowsing2.parsers

import util.Helpers._
import scala.collection.mutable.ListBuffer
import scala.annotation.tailrec

object FullHashParser extends BinaryParsers {
  
  case class Envelope(rekey: Boolean, mac: Option[String], hashdata: Seq[FullHashData])
  case class FullHashData(list: String, addChunknum: Int, hashdata: Seq[Byte]) {
    lazy val hashes = {
      val list = new ListBuffer[String]
      @tailrec def slice(data: Seq[Byte]): Seq[String] = {
        if (data.isEmpty) list.toList
        else {
          list += bytes2Hex(data.take(32))
   		  slice(data.drop(32))
        }
      }
      slice(hashdata)
    }
  }
  
  /** Used for testing */
  def parse(in: String) = super.parseAll(body, in)
  def parse(bytes: Seq[Byte]) = super.parseAll(body, new ByteReader(bytes))
  
  def loalpha(e: Elem) = e > 96 && e < 123
  def digit(e: Elem) = e > 47 && e < 58
  
  def body = (data | rekey) ^^ {b =>
    b match {
      case e: Envelope => e
      case s: String => Envelope(true, None, Nil)
    }
  }
  def data = opt(mac)~rep1(hashentry) ^^ {
    case m~h => Envelope(false, m, h)
  } 
  def mac = takeWhile(acceptIf(e => loalpha(e) || digit(e))(el => "Unexpected "+el)) <~ lf ^^ {m => 
    toString(m)
  }
  def rekey = accept("e:pleaserekey".getBytes.toList) <~ lf ^^ {_ => "rekey"}
  def hashentry = takeUntil(colon)~colon~takeUntil(colon)~colon~hashdata ^^ {
    case list~c1~addchunk~c2~hashdata => FullHashData(toString(list), asciiInt(addchunk), hashdata)
  }
  def hashdata = takeUntil(lf)<~lf >> {
    n => take(Integer.valueOf(toString(n))) 
  }
  def colon = elem(':')
  def lf = elem('\n')
}