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

object DataParser extends BinaryParsers {

  case class AddChunk(chunknum: Int, hashlen: Int, data: Array[Byte]) {
    lazy val hostkey = bytes2Hex(data.take(4))
    lazy val count = if (data.length > 4) data(4).toInt else 0

    /**
     * count = 0 -> no PREFIX (special case: PREFIX = HOSTKEY)
     * count = N -> N PREFIXes
     *
     * PREFIX length = hashlen
     */
    lazy val prefixes: List[String] = if (count == 0) List(hostkey) else {
      (0 until count toList) map { i =>
        val start = 5 + (hashlen * i)
        bytes2Hex(data.slice(start, start + hashlen).toArray)
      }
    }

    override def equals(that: Any): Boolean = that match {
      case a: AddChunk => {
        a.chunknum == chunknum &&
          a.count == count &&
          a.hashlen == hashlen &&
          a.hostkey == hostkey &&
          a.data.deep.equals(data.deep)
      }
      case _ => false
    }

    override def toString = {
      "AdHead(%d,%d,%s)".format(chunknum, hashlen, bytes2Hex(data))
    }
  }

  case class SubChunk(chunknum: Int, hashlen: Int, data: Array[Byte]) {
    lazy val hostkey = bytes2Hex(data.take(4))
    lazy val count = if (data.length > 4) data(4).toInt else 0

    /**
     * count = 0 -> only one ADDCHUNKNUM, PREFIX = HOSTKEY
     * count = N -> N (ADDCHUNKNUM, PREFIX) pairs
     *
     * ADDCHUNKNUM length = 4
     * PREFIX length = hashlen
     */
    lazy val pairs: List[(Int, String)] = if (data.length < 9) Nil
    else if (count == 0) List((toInt(data.slice(5, 9)), hostkey))
    else {
      (0 until count toList) map { i =>
        val start = 5 + ((hashlen + 4) * i)
        val prefixStart = start + 4
        val addchunknum = toInt(data.slice(start, prefixStart))
        val prefix = bytes2Hex(data.slice(prefixStart, prefixStart + hashlen))
        (addchunknum, prefix)
      }
    }

    override def equals(that: Any): Boolean = that match {
      case s: SubChunk => {
        s.chunknum == chunknum &&
          s.count == count &&
          s.hashlen == hashlen &&
          s.hostkey == hostkey &&
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