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
  
  def body = (data | rekey) ^^ {b =>
    b match {
      case e: Envelope => e
      case s: String => Envelope(true, None, Nil)
    }
  }
  def data = opt(mac)~rep1(hashentry) ^^ {
    case m~h => Envelope(false, m, h)
  } 
  def mac = takeWhile(acceptIf(e => e != ':' && e != '\n')(el => "Unexpected "+el)) <~ lf ^^ {m => 
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