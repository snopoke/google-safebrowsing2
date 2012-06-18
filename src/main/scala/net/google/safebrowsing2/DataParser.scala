package net.google.safebrowsing2

import net.google.safebrowsing2.Helpers._

object DataParser extends BinaryParsers {
  
    case class AdHead(chunknum: Int, hashlen: Int, data: Array[Byte]) {
    val host = bytes2Hex(data.take(4))
    val count = data(4).toInt
    
    /**
     * count = 0 -> no PREFIX
     * count = N -> N PREFIXes
     * 
     * PREFIX length = hashlen
     */
    val prefix:List[String] = if(count == 0) Nil else {
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
  }
  
  case class SubHead(chunknum: Int, hashlen: Int, data: Array[Byte]) {
    val host = bytes2Hex(data.take(4))
    val count = data(4).toInt
    
    /**
     * count = 0 -> only one ADDCHUNKNUM, no PREFIX
     * count = N -> N (ADDCHUNKNUM, PREFIX) pairs
     * 
     * ADDCHUNKNUM length = 4
     * PREFIX length = hashlen
     */
    val pairs:List[(String,String)] = if(count == 0) List((bytes2Hex(data.slice(5,9)), "")) else {
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
  }
  
  def parse(in: String) = super.parse(data, in)
  def parse(bytes: Seq[Byte]) = super.parse(data, new ByteReader(bytes))
  
  def data = (addHead | subHead)+

  def addHead = elem('a')~clon ~> head ^^ {
    case cnum~s1~hlen~s2~data => AdHead(asciiInt(cnum), asciiInt(hlen), data.toArray)
  }
  def subHead = elem('s')~clon ~> head ^^ {
    case cnum~s1~hlen~s2~data => SubHead(asciiInt(cnum), asciiInt(hlen), data.toArray)
  }
  def head = takeUntil(clon)~clon~takeUntil(clon)~clon~chunkl
  def chunkl = takeUntil(nline)<~nline >> {
    n => take(Integer.valueOf(toString(n))) 
  }
  
  def clon = elem(':')
  def nline = elem('\n')
}