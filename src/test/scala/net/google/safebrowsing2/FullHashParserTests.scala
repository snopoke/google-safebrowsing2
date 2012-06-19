package net.google.safebrowsing2
import org.junit.Test
import org.junit.Assert._
import org.hamcrest.CoreMatchers._
import net.google.safebrowsing2.FullHashParser.{FullHashData, Envelope}

class FullHashParserTests {

  @Test
  def testParseDataWithMac = {
    val data = "mac123456\n" +
    		"list1:123:8\n" +
    		"abcdefgh" +
    		"list2:456:6\n" +
    		"ABCDEF"
    val parsed = FullHashParser.parse(data) match {
      case FullHashParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertFalse(parsed.get.rekey)
    val list = List(FullHashData("list1","123","abcdefgh".getBytes()), 
       FullHashData("list2","456","ABCDEF".getBytes()))
    assertThat(parsed.get, is(Envelope(false, Option("mac123456"), list)))
  }
  
  @Test
  def testParseDataWithoutMac = {
    val data = "list1:123:8\n" +
    		new String(Array(0,1,2,3,4,5,6,7): Array[Byte]) +
    		"list2:456:6\n" +
    		"ABCDEF"
    val parsed = FullHashParser.parse(data) match {
      case FullHashParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertFalse(parsed.get.rekey)
    val list = List(FullHashData("list1","123",Array(0,1,2,3,4,5,6,7): Array[Byte]), 
       FullHashData("list2","456","ABCDEF".getBytes()))
    assertThat(parsed.get, is(Envelope(false, None, list)))
  }
  
  @Test
  def testParseRekey = {
    val data = "e:pleaserekey\n"
    val parsed = FullHashParser.parse(data) match {
      case FullHashParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    assertTrue(parsed.get.rekey)
  }
  
  @Test
  def testHashSplitting = {
    val data = "list1:123:64\n" + 
    		byteString(64)

    val parsed = FullHashParser.parse(data) match {
      case FullHashParser.Success(c, _) => Option(c)
      case x => println(x); None
    }
    
    assertTrue("Parsing failed", parsed.isDefined)
    val hashdata = parsed.get.hashdata
    assertThat(hashdata.size, is(1))
    val hashes = hashdata(0).hashes
    assertThat(hashes.size, is(2))
    assertThat(hashes(0), is(hexString(32)))
    assertThat(hashes(1), is(hexString(32,64)))
  }
  
  def bytes(start: Int, end: Int) = { ((start until end toList).toArray).map(_.toByte) }
  def byteString(len: Int) = { new String(bytes(0, len)) }
  def hexString(len: Int): String = { hexString(0, len) }
  def hexString(start: Int, end: Int): String = { Helpers.bytes2Hex(bytes(start, end)) }
}