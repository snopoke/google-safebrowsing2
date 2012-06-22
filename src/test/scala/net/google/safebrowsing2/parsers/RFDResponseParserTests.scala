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

import org.junit.Test
import org.junit.Assert._
import org.hamcrest.CoreMatchers._
import net.google.safebrowsing2.parsers.RFDResponseParser._

class RFDResponseParserTests {

  @Test
  def testWithMac = {
    val response = "m:lAcpo_sFRJ4lOC-zqLgR_uqGtsU=\n" +
      "n:123\n" +
      "i:google-list-123\n" +
      "u:http://redir1,mac1\n" +
      "u:http://redir2\n" +
      "ad:1,2-4,5\n" +
      "i:google-list-456\n" +
      "sd:5-9,12-15,16\n"
    val parsed = RFDResponseParser.parse(response) match {
      case RFDResponseParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    assertTrue(parsed.isDefined)

    val adl = List(1,2,3,4,5)
    val cl1 = ChunkList("google-list-123", List(Redirect("http://redir1", Option("mac1")), Redirect("http://redir2", None), AdDel(adl)))
    val cl2 = ChunkList("google-list-456", List(SubDel(List(5,6,7,8,9,12,13,14,15,16))))
    val clist = List(cl1, cl2)
    assertThat(parsed.get, is(Resp(false, Some("lAcpo_sFRJ4lOC-zqLgR_uqGtsU="), 123, false, Some(clist))))
  }

  @Test
  def testWithoutMac = {
    val response = "n:123\n" +
      "i:google-list-123\n" +
      "u:http://redir1\n" +
      "ad:1,2-4,5\n"

    val parsed = RFDResponseParser.parse(response) match {
      case RFDResponseParser.Success(c, _) => Option(c)
      case x => println(x); None
    }

    assertTrue("parsing failed", parsed.isDefined)

    val adl = List(1,2,3,4,5)
    val cl1 = ChunkList("google-list-123", List(Redirect("http://redir1", None), AdDel(adl)))
    assertThat(parsed.get, is(Resp(false, None, 123, false, Some(cl1 :: Nil))))
  }

  @Test
  def testRekey = {
    val response = "e:pleaserekey\n" +
      "n:123\n"

    val parsed = RFDResponseParser.parse(response) match {
      case RFDResponseParser.Success(c, _) => Option(c)
      case x => println(x); None
    }

    assertTrue("parsing failed", parsed.isDefined)
    assertThat(parsed.get, is(Resp(true, None, 123, false, None)))
  }
  
  @Test
  def testReset = {
    val response = "n:123\n" +
    		"r:pleasereset\n"

    val parsed = RFDResponseParser.parse(response) match {
      case RFDResponseParser.Success(c, _) => Option(c)
      case x => println(x); None
    }

    assertTrue("parsing failed", parsed.isDefined)
    assertThat(parsed.get, is(Resp(false, None, 123, true, None)))
  }
}