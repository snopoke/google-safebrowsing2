package net.google.safebrowsing2
import org.junit.Test
import org.junit.Assert._
import org.hamcrest.CoreMatchers._
import net.google.safebrowsing2.RFDResponseParser._

class RFDResponseParserTests {

  @Test
  def testWithMac = {
    val response = "8798asf987as\n" +
      "n:123\n" +
      "i:google-list-123\n" +
      "u:http://redir1\n" +
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
    val cl1 = ChunkList("google-list-123", List(Redirect("http://redir1"), Redirect("http://redir2"), AdDel(adl)))
    val cl2 = ChunkList("google-list-456", List(SubDel(List(5,6,7,8,9,12,13,14,15,16))))
    val clist = List(cl1, cl2)
    assertThat(parsed.get, is(Chunk(Some("8798asf987as"), 123, None, Some(clist))))
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
    val cl1 = ChunkList("google-list-123", List(Redirect("http://redir1"), AdDel(adl)))
    assertThat(parsed.get, is(Chunk(None, 123, None, Some(cl1 :: Nil))))
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
    assertThat(parsed.get, is(Chunk(Some("rekey"), 123, None, None)))
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
    assertThat(parsed.get, is(Chunk(None, 123, Some(true), None)))
  }
}