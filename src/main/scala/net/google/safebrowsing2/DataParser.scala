package net.google.safebrowsing2

import util.Helpers._
import scala.util.parsing.input.CharArrayReader.EofCh

object DataParser extends BinaryParsers {
  
    case class AdHead(chunknum: Int, hashlen: Int, data: Array[Byte]) {
    lazy val host = bytes2Hex(data.take(4))
    val count = data(4).toInt
    
    /**
     * count = 0 -> no PREFIX
     * count = N -> N PREFIXes
     * 
     * PREFIX length = hashlen
     */
    lazy val prefixes:List[String] = if(count == 0) Nil else {
      (0 to count-1 toList) map { i =>
        val start = 5+(hashlen*i)
        bytes2Hex(data.slice(start, start+hashlen).toArray)
      }
    }
    
     override def equals(that: Any): Boolean = that match {
      case a: AdHead => {a.chunknum == chunknum && 
        a.count == count &&
        a.hashlen == hashlen && 
    	a.host == host &&
    	a.data.deepEquals(data)
      }
      case _ => false
    }
     
     override def toString = {
       "AdHead(%d,%d,%s)".format(chunknum, hashlen, bytes2Hex(data))
     }
  }
  
  case class SubHead(chunknum: Int, hashlen: Int, data: Array[Byte]) {
    lazy val host = bytes2Hex(data.take(4))
    val count = data(4).toInt
    
    /**
     * count = 0 -> only one ADDCHUNKNUM, no PREFIX
     * count = N -> N (ADDCHUNKNUM, PREFIX) pairs
     * 
     * ADDCHUNKNUM length = 4
     * PREFIX length = hashlen
     */
    lazy val pairs:List[(String,String)] = if(count == 0) List((bytes2Hex(data.slice(5,9)), "")) else {
      (0 to count-1 toList) map { i =>
        val start = 5+((hashlen+4)*i)
        val prefixStart = start + 4
        val addchunknum = bytes2Hex(data.slice(start, prefixStart))
        val prefix = bytes2Hex(data.slice(prefixStart, prefixStart+hashlen))
        (addchunknum, prefix)
      }
    }
    
    override def equals(that: Any): Boolean = that match {
      case s: SubHead => {s.chunknum == chunknum && 
        s.count == count &&
        s.hashlen == hashlen && 
    	s.host == host &&
    	s.data.deepEquals(data)
      }
      case _ => false
    }
    
    override def toString = {
       "SubHead(%d,%d,%s)".format(chunknum, hashlen, bytes2Hex(data))
     }
  }
  
  def parse(in: String) = super.parseAll(data, in)
  def parse(bytes: Seq[Byte]) = super.parseAll(data, new ByteReader(bytes))
  
  def data = (addHead | subHead)+ 

  def addHead = elem('a')~colon ~> head ^^ {
    case cnum~s1~hlen~s2~data => AdHead(asciiInt(cnum), asciiInt(hlen), data.toArray)
  }
  def subHead = elem('s')~colon ~> head ^^ {
    case cnum~s1~hlen~s2~data => SubHead(asciiInt(cnum), asciiInt(hlen), data.toArray)
  }
  def head = takeUntil(colon)~colon~takeUntil(colon)~colon~chunkl
  def chunkl = takeUntil(lf)<~lf >> {
    n => take(Integer.valueOf(toString(n))) 
  }
  
  def colon = elem(':')
  def lf = elem('\n')
}