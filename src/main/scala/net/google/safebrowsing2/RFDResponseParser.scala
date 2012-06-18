package net.google.safebrowsing2
import scala.util.parsing.combinator.RegexParsers
import scala.collection.mutable

object RFDResponseParser extends RegexParsers {
  override def skipWhitespace = false

  case class Resp(mac: Option[String], next: Int, reset: Option[Boolean], list: Option[List[ChunkList]])
  case class ChunkList(name: String, data: List[ListData])
  abstract trait ListData
  case class Redirect(url: String, mac: Option[String]) extends ListData
  case class AdDel(list: List[Int]) extends ListData
  case class SubDel(list: List[Int]) extends ListData
  
  def parse(input: String) = parseAll(chunk, input)
  def chunk = opt(head) ~ next ~ opt(reset) ~ opt(list+) ^^ {
    case m ~ n ~ r ~ l => Resp(m, n, r, l)
  }
  def head = (rekey | mac) <~ space
  def rekey = "e:please" ~> "rekey"
  def mac = """[a-z0-9]*""".r 
  def next = "n:" ~> number <~ space ^^ { _.toInt }
  def reset = "r:pleasereset" <~ space ^^ { r => true }
  def list = "i:" ~> listname ~ (listdata+) ^^ {
    case name ~ data => ChunkList(name, data)
  }
  def number = """[0-9]*""".r
  def listname = """[a-z0-9\-]*""".r <~ space
  def listdata: Parser[ListData] = redirecturl | addelHead | subdelHead
  def redirecturl = "u:" ~> url~opt(","~>mac) <~ space ^^ { case u ~ m => Redirect(u, m) }
  def addelHead = "ad:" ~> chunklist <~ space ^^ { ad => AdDel(ad.reduce((list, n) => list ::: n)) }
  def subdelHead = "sd:" ~> chunklist <~ space ^^ { sd => SubDel(sd.reduce((list, n) => list ::: n)) }
  def url = """([^, \n]+)""".r
  def chunklist = rep1sep(range | cnumber, ",")
  def range = number ~ "-" ~ number ^^ {
    case start ~ d ~ end => start.toInt to end.toInt toList
  }
  def cnumber = number ^^ {n => List(n.toInt) }
  def space = """[ \n]+""".r
}

