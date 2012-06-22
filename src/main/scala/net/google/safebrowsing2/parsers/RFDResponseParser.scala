/* 
 * Copyright 2012 Simon Kelly
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.google.safebrowsing2.parsers

import scala.util.parsing.combinator.RegexParsers
import scala.collection.mutable

/**
 * Parser for Request For Data response body
 * @see https://developers.google.com/safe-browsing/developers_guide_v2#HTTPResponseForDataBody
 * Note: spec omits leading 'm:' for MAC key
 */
object RFDResponseParser extends RegexParsers {
  override def skipWhitespace = false

  case class Resp(rekey: Boolean, mac: Option[String], next: Int, reset: Boolean, list: Option[List[ChunkList]])
  case class ChunkList(name: String, data: List[ListData])
  abstract trait ListData
  case class Redirect(url: String, mac: Option[String]) extends ListData
  case class AdDel(list: List[Int]) extends ListData
  case class SubDel(list: List[Int]) extends ListData
  
  def parse(input: String) = parseAll(chunk, input)
  def chunk = opt(head) ~ next ~ opt(reset) ~ opt(list+) ^^ {
    case m ~ n ~ r ~ l => {
      m match {
        case Some("rekey") => Resp(true, None, n, r.getOrElse(false), l) 
        case _ => Resp(false, m, n, r.getOrElse(false), l) 
      }
    }
  }
  def head = (rekey | mac) <~ space
  def rekey = "e:please" ~> "rekey"
  def mac = "m:"~>".+".r 
  def next = "n:" ~> number <~ space ^^ { _.toInt }
  def reset = "r:pleasereset" <~ space ^^ { r => true }
  def list = "i:" ~> listname ~ (listdata+) ^^ {
    case name ~ data => ChunkList(name, data)
  }
  def number = """[0-9]*""".r
  def listname = """[a-z0-9\-]*""".r <~ space
  def listdata: Parser[ListData] = redirecturl | addelHead | subdelHead
  def redirecturl = "u:" ~> url~opt(","~>".+".r) <~ space ^^ { case u ~ m => Redirect(u, m) }
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

