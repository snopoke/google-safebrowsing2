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
import net.google.safebrowsing2.parsers.DataParser._

class DataParserTests {

  @Test
  def testParseData = {
    val data = "a:4:5:5\n" +
    		"abcd0" +
    		"a:6:2:9\n" +
    		"cded2abcd" +
    		"s:3:2:9\n" +
    		"45sd0789a" +
    		"s:3:2:17\n" +
    		"45sd24567MN1234PQ"
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, rest) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    val expected = List(AddChunk(4,5,"abcd0".getBytes()), 
        AddChunk(6,2,"cded2abcd".getBytes()), 
        SubChunk(3,2,"45sd0789a".getBytes()), 
        SubChunk(3,2,"45sd24567MN1234PQ".getBytes()))
    assertThat(parsed.get, is(expected))
  }
  
  @Test
  def testParseData_fail = {
    val data = "a:4:5:5\n" +
    		"ab"
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, rest) => fail("Expected failure, got " + c)
      case x => // test passes
    }
  }
  
  @Test
  def testParse_add0 = {
    val data = "a:4:5:5\n" +
    		new String(Array(9,10,11,12,0): Array[Byte])
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertThat(parsed.get.size, is(1))
    
    // AddChunk with count = 0
    val add = parsed.get(0).asInstanceOf[AddChunk]
    assertThat(add.hostkey, is("090A0B0C"))
    assertThat(add.count, is(0))
    assertThat(add.prefixes, is(List("090A0B0C")))
  }  
  
  @Test
  def testParse_addEmpty = {
    val data = "a:4:5:0\n"
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertThat(parsed.get.size, is(1))
    
    // AddChunk with count = 0
    val add = parsed.get(0).asInstanceOf[AddChunk]
    assertThat(add.hostkey, is(""))
    assertThat(add.count, is(0))
    assertThat(add.prefixes, is(List("")))
  }  
  
  @Test
  def testParse_addGT0 = {
    val data = "a:6:2:9\n" +
    		new String(Array(9,10,11,12,2,3,4,5,6): Array[Byte])
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertThat(parsed.get.size, is(1))
    
    // AddChunk with count = 2
    val add = parsed.get(0).asInstanceOf[AddChunk]
    assertThat(add.hostkey, is("090A0B0C"))
    assertThat(add.count, is(2))
    assertThat(add.prefixes, is(List("0304","0506")))
  }
  
  @Test
  def testParse_sub0 = {
    val data = "s:3:2:9\n" +
    		new String(Array(9,10,11,12,0,0,0,0,6): Array[Byte])
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertThat(parsed.get.size, is(1))
    
    // SubChunk with count = 0
    val sub = parsed.get(0).asInstanceOf[SubChunk]
    assertThat(sub.hostkey, is("090A0B0C"))
    assertThat(sub.count, is(0))
    assertThat(sub.pairs, is(List((6,"090A0B0C"))))
  }
  
  @Test
  def testParse_subEmpty = {
    val data = "s:3:2:0\n"
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertThat(parsed.get.size, is(1))
    
    // SubChunk with count = 0
    val sub = parsed.get(0).asInstanceOf[SubChunk]
    assertThat(sub.hostkey, is(""))
    assertThat(sub.count, is(0))
    assertTrue(sub.pairs.isEmpty)
  }
  
  @Test
  def testParse_subGT0 = {
    val data = "s:3:2:17\n" +
    		new String(Array(9,10,11,12,2,0,0,1,0,1,1,0,1,0,0,15,15): Array[Byte])
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertThat(parsed.get.size, is(1))
    
    // SubChunk with count = 2
    val sub = parsed.get(0).asInstanceOf[SubChunk]
    assertThat(sub.hostkey, is("090A0B0C"))
    assertThat(sub.count, is(2))
    assertThat(sub.pairs, is(List((256,"0101"), (65536, "0F0F"))))
  }
}