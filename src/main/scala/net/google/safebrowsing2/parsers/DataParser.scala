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
import scala.util.parsing.input.CharArrayReader.EofCh
import collection.mutable.ListBuffer

object DataParser extends BinaryParsers {

  case class AddChunk(chunknum: Int, hashlen: Int, data: Array[Byte]) {
    /**
     * ADD-DATA = (HOSTKEY COUNT [PREFIX]*)+
     * HOSTKEY  = <4 unsigned bytes>                            # 32-bit hash prefix
     * COUNT    = <1 unsigned byte>
     * PREFIX   = <HASHLEN unsigned bytes>
     *
     * count = 0 -> no PREFIX (special case: PREFIX = HOSTKEY)
     * count = N -> N PREFIXes
     *
     * PREFIX length = hashlen
     */
    lazy val addList: List[(String, List[String])] = {
      val list = new ListBuffer[(String, List[String])]()

      var i = 0
      while(i < data.length) {
        val hostkey = bytes2Hex(data.slice(i, i + 4).toArray)
        val count = toInt(Array(data(i + 4)))
        val prefixes: List[String] = if (count == 0) List("") else {
          (0 until count toList) map { j =>
            val start = (i + 5) + (hashlen * j)
            bytes2Hex(data.slice(start, start + hashlen).toArray)
          }
        }        
        list += ((hostkey, prefixes))
        i += (5 + count * hashlen) // host key (4 bytes) + count (1 byte) + count * hashlen
      }

      list.toList
    }

    override def equals(that: Any): Boolean = that match {
      case a: AddChunk => {
        a.chunknum == chunknum &&
          a.hashlen == hashlen &&
          a.data.deep.equals(data.deep)
      }
      case _ => false
    }

    override def toString = {
      "AdHead(%d,%d,%s)".format(chunknum, hashlen, bytes2Hex(data))
    }
  }

  case class SubChunk(chunknum: Int, hashlen: Int, data: Array[Byte]) {
    /**
     * SUB-DATA    = (HOSTKEY COUNT (ADDCHUNKNUM | (ADDCHUNKNUM PREFIX)+))+
     * HOSTKEY     = <4 unsigned bytes>                            # 32-bit hash prefix
     * COUNT       = <1 unsigned byte>
     * ADDCHUNKNUM = <4 byte unsigned integer in network byte order>
     * PREFIX      = <HASHLEN unsigned bytes>
     *
     * count = 0 -> only one ADDCHUNKNUM, PREFIX = HOSTKEY
     * count = N -> N (ADDCHUNKNUM, PREFIX) pairs
     *
     * ADDCHUNKNUM length = 4
     * PREFIX length = hashlen
     */
    lazy val subList: List[(String, List[(Int, String)])] = {
      val list = new ListBuffer[(String, List[(Int, String)])]()

      var i = 0
      while(i < data.length) {
        val hostkey = bytes2Hex(data.slice(i, i + 4).toArray)
        val count = toInt(Array(data(i + 4)))
        val pairs: List[(Int, String)] = if (count == 0) List((toInt(data.slice((i + 5), (i + 9))), ""))
        else {
          (0 until count toList) map { j =>
            val start = (i + 5) + ((hashlen + 4) * j)
            val prefixStart = start + 4
            val addchunknum = toInt(data.slice(start, prefixStart))
            val prefix = bytes2Hex(data.slice(prefixStart, prefixStart + hashlen))
            (addchunknum, prefix)
          }
        }

        list += ((hostkey, pairs))
        if (count == 0) {
          i += (5 + 4)
        } else {
          i += (5 + count * (4 + hashlen))
        }
      }

      list.toList
    }

    override def equals(that: Any): Boolean = that match {
      case s: SubChunk => {
        s.chunknum == chunknum &&
          s.hashlen == hashlen &&
          s.data.deep.equals(data.deep)
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

  def addHead = elem('a') ~ colon ~> head ^^ {
    case cnum ~ s1 ~ hlen ~ s2 ~ data => AddChunk(asciiInt(cnum), asciiInt(hlen), data.toArray)
  }
  def subHead = elem('s') ~ colon ~> head ^^ {
    case cnum ~ s1 ~ hlen ~ s2 ~ data => SubChunk(asciiInt(cnum), asciiInt(hlen), data.toArray)
  }
  def head = takeUntil(colon) ~ colon ~ takeUntil(colon) ~ colon ~ chunkl
  def chunkl = takeUntil(lf) <~ lf >> {
    n => take(Integer.valueOf(toString(n)))
  }

  def colon = elem(':')
  def lf = elem('\n')
}