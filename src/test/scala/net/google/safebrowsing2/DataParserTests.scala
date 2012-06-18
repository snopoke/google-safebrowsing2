package net.google.safebrowsing2
import org.junit.Test
import org.junit.Assert._
import org.hamcrest.CoreMatchers._
import net.google.safebrowsing2.DataParser._

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
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    val expected = List(AdHead(4,5,"abcd0".getBytes()), 
        AdHead(6,2,"cded2abcd".getBytes()), 
        SubHead(3,2,"45sd0789a".getBytes()), 
        SubHead(3,2,"45sd24567MN1234PQ".getBytes()))
    assertThat(parsed.get, is(expected))
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
    
    // AdHead with count = 0
    val add = parsed.get(0).asInstanceOf[AdHead]
    assertThat(add.host, is("090A0B0C"))
    assertThat(add.count, is(0))
    assertThat(add.prefix, is(Nil:List[String]))
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
    
    // AdHead with count = 2
    val add = parsed.get(0).asInstanceOf[AdHead]
    assertThat(add.host, is("090A0B0C"))
    assertThat(add.count, is(2))
    assertThat(add.prefix, is(List("0304","0506")))
  }
  
  @Test
  def testParse_sub0 = {
    val data = "s:3:2:9\n" +
    		new String(Array(9,10,11,12,0,3,4,5,6): Array[Byte])
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertThat(parsed.get.size, is(1))
    
    // SubHead with count = 0
    val sub = parsed.get(0).asInstanceOf[SubHead]
    assertThat(sub.host, is("090A0B0C"))
    assertThat(sub.count, is(0))
    assertThat(sub.pairs, is(List(("03040506",""))))
  }
  
  @Test
  def testParse_subGT0 = {
    val data = "s:3:2:17\n" +
    		new String(Array(9,10,11,12,2,3,4,5,6,0,1,7,8,9,10,15,15): Array[Byte])
    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertThat(parsed.get.size, is(1))
    
    // SubHead with count = 2
    val sub = parsed.get(0).asInstanceOf[SubHead]
    assertThat(sub.host, is("090A0B0C"))
    assertThat(sub.count, is(2))
    assertThat(sub.pairs, is(List(("03040506","0001"), ("0708090A", "0F0F"))))
  }
}