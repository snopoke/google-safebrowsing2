package net.google.safebrowsing2
import scala.util.parsing.combinator.RegexParsers
import scala.collection.mutable

object DataParser extends RegexParsers {
  override def skipWhitespace = false

  case class AdHead(chunknum: Int, hashlen: Int, data: String) {
    val host = data.take(4)
    val count = data.substring(4,5).toInt
    
    /**
     * count = 0 -> no PREFIX
     * count = N -> N PREFIXes
     * 
     * PREFIX length = hashlen
     */
    val prefix:List[String] = if(count == 0) Nil else {
      (0 to count-1 toList) map { i =>
        val start = 5+(hashlen*i)
        data.substring(start, start+hashlen)
      }
    }
  }
  
  case class SubHead(chunknum: Int, hashlen: Int, data: String) {
    val host = data.take(4)
    val count = data.substring(4,5).toInt
    
    /**
     * count = 0 -> only one ADDCHUNKNUM, no PREFIX
     * count = N -> N (ADDCHUNKNUM, PREFIX) pairs
     * 
     * ADDCHUNKNUM length = 4
     * PREFIX length = hashlen
     */
    val pairs:List[(String,String)] = if(count == 0) List((data.substring(5,9), "")) else {
      (0 to count-1 toList) map { i =>
        val start = 5+((hashlen+4)*i)
        val prefixStart = start + 4
        (data.substring(start, prefixStart), data.substring(prefixStart, prefixStart+hashlen))
      }
    }
  }
  
  def parse(input: String) = parseAll(data, input)
  def data = (addHead | subHead)+
  def number = """[0-9]*""".r
  def addHead = "a:" ~> head ^^ {
    case cnum~s1~hlen~s2~data => AdHead(cnum.toInt, hlen.toInt, data)
  }
  def subHead = "s:" ~> head ^^ {
    case cnum~s1~hlen~s2~data => SubHead(cnum.toInt, hlen.toInt, data)
  }
  def head = number~":"~number~":"~chunkl
  def chunkl = number <~ space >> {n => (".{"+n+"}").r }
  def space = """[ \n]+""".r
}