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

package net.google.safebrowsing2
import org.junit.Test
import org.junit.Assert._
import org.junit.matchers.JUnitMatchers._
import org.hamcrest.CoreMatchers._
import org.junit.Before
import org.scalatest.mock.MockitoSugar
import org.mockito.Mockito._
import com.github.tototoshi.http.Client
import org.mockito.Mockito
import org.mockito.Matchers.{ any => anyM }
import com.github.tototoshi.http.Response
import org.apache.http.HttpResponse
import util.Helpers._
import net.google.safebrowsing2.db.DBI
import org.apache.http.HttpEntity
import org.mockito.stubbing.Answer
import org.mockito.invocation.InvocationOnMock

class SafeBrowsing2Tests extends MockitoSugar with ByteUtil {

  var sb2: SafeBrowsing2 = _
  var storage: DBI = _

  @Before
  def before = {
    storage = mock[DBI]
    sb2 = new SafeBrowsing2("", storage)
    sb2.httpClient = mock[Client]
  }

  @Test
  def testGetMacKeys = {
    val response = "clientkey:24:VyUHdnlAPEJa42JKq5oo8Q==\n" +
      "wrappedkey:12:AKEgNisrzEPf"

    val key = sb2.processMacResponse(response)
    assertTrue(key.isDefined)
    assertThat(key.get.clientKey, is("VyUHdnlAPEJa42JKq5oo8Q=="))
    assertThat(key.get.wrappedKey, is("AKEgNisrzEPf"))
  }

  @Test(expected = classOf[AssertionError])
  def testGetMacKeys_incorrectClientLength = {
    val response = "clientkey:23:VyUHdnlAPEJa42JKq5oo8Q==\n" +
      "wrappedkey:12:AKEgNisrzEPf"
    val key = sb2.processMacResponse(response)
  }

  @Test(expected = classOf[AssertionError])
  def testGetMacKeys_incorrectWrappedLength = {
    val response = "clientkey:24:VyUHdnlAPEJa42JKq5oo8Q==\n" +
      "wrappedkey:13:AKEgNisrzEPf"
    val key = sb2.processMacResponse(response)
  }

  @Test
  def testCreateRange = {
    val input = Array(1, 2, 4, 5, 6, 8)
    val range = sb2.createRange(input)
    assertThat(range, is("1-2,4-6,8"))
  }

  @Test
  def testGetExistingChunks = {
    val a_nums = Array(1, 2, 3, 5, 6, 7);
    val s_nums = Array(8, 9, 10, 15, 16, 19)

    when(storage.getAddChunksNums("list")).thenReturn(a_nums)
    when(storage.getSubChunksNums("list")).thenReturn(s_nums)

    val existing = sb2.getExistingChunks(Array("list"), true);
    assertThat(existing, is("list;a:1-3,5-7:s:8-10,15-16,19:mac\n"))
  }

  @Test
  def testGetExistingChunks_aOnly = {
    val a_nums = Array(1, 2, 3, 5, 6, 7);

    when(storage.getAddChunksNums("list")).thenReturn(a_nums)

    val existing = sb2.getExistingChunks(Array("list"), false);
    assertThat(existing, is("list;a:1-3,5-7\n"))
  }

  @Test
  def testGetExistingChunks_sOnly = {
    val s_nums = Array(8, 9, 10, 15, 16, 19)

    when(storage.getSubChunksNums("list")).thenReturn(s_nums)

    val existing = sb2.getExistingChunks(Array("list"), false);
    assertThat(existing, is("list;s:8-10,15-16,19\n"))
  }

  @Test
  def testProcessRedirect = {
    val resp = mock[Response]
    val data = "a:6:2:9\n" +
      new String(Array(9, 10, 11, 12, 2, 1, 1, 2, 2): Array[Byte]) +
      "s:3:2:9\n" +
      new String(Array(1, 2, 3, 4, 0, 0, 0, 0, 8): Array[Byte])
    when(sb2.httpClient.GET("http://url")).thenReturn(resp)
    when(resp.statusCode()).thenReturn(200)
    when(resp.asBytes()).thenReturn(data.getBytes())

    sb2.processRedirect("url", None, "list", None)
    verify(storage).addChunks_a(6, "090A0B0C", List("0101", "0202"), "list")
    verify(storage).addChunks_s(3, "01020304", List((8, "")), "list")
  }

  @Test(expected = classOf[ApiException])
  def testProcessRedirect_badStatuScode = {
    val resp = mock[Response]
    when(sb2.httpClient.GET("http://url")).thenReturn(resp)
    when(resp.statusCode()).thenReturn(400)

    val result = sb2.processRedirect("url", None, "list", None)
  }

  @Test(expected = classOf[MacException])
  def testProcessRedirect_missingMac = {
    val data = "a:6:2:9\n" +
      new String(Array(9, 10, 11, 12, 2, 1, 1, 2, 2): Array[Byte])
    val resp = mock[Response]
    when(sb2.httpClient.GET("http://url")).thenReturn(resp)
    when(resp.statusCode()).thenReturn(200)

    val result = sb2.processRedirect("url", None, "list", Some(MacKey("", "")))
  }

  @Test
  def testProcessRedirect_withMac = {
    val data = "a:6:2:9\n" +
      new String(Array(9, 10, 11, 12, 2, 1, 1, 2, 2): Array[Byte])

    val resp = mock[Response]
    when(sb2.httpClient.GET("http://url")).thenReturn(resp)
    when(resp.statusCode()).thenReturn(200)
    when(resp.asBytes()).thenReturn(data.getBytes())

    val hmac = Some(getMac(data.getBytes(), "clientkey"))

    val result = sb2.processRedirect("url", hmac, "list", Some(MacKey("clientkey", "")))
    verify(storage).addChunks_a(6, "090A0B0C", List("0101", "0202"), "list")
  }

  @Test
  def testParseFullHashes = {
    val data = "list1:123:64\n" +
      byteString(64)
    val hashes = sb2.parseFullHashes(data.getBytes(), None)
    assertThat(hashes.size, is(2))
    assertThat(hashes(0).list, is("list1"))
    assertThat(hashes(0).chunknum, is(123))
    assertThat(hashes(0).hash, is(hexString(32)))
    assertThat(hashes(1).list, is("list1"))
    assertThat(hashes(1).chunknum, is(123))
    assertThat(hashes(1).hash, is(hexString(32, 64)))
  }

  @Test(expected = classOf[RekeyException])
  def testParseFullHashes_rekey = {
    val data = "e:pleaserekey\n"
    val hashes = sb2.parseFullHashes(data.getBytes(), None)
  }
  
  @Test(expected = classOf[MacException])
  def testParseFullHashes_macFail = {
    val data = "badmac\nlist1:123:64\n" +
      byteString(64)
    val hashes = sb2.parseFullHashes(data.getBytes(), Some(MacKey("clientkey","wrappedkey")))
  }
  
  @Test(expected = classOf[MacException])
  def testParseFullHashes_emptyMac = {
    val data = "list1:123:64\n" +
      byteString(64)
    val hashes = sb2.parseFullHashes(data.getBytes(), Some(MacKey("clientkey","wrappedkey")))
  }
  
  @Test
  def testParseFullHashes_macPass = {
    val data = getMac(byteString(64).getBytes(),"clientkey") + "\nlist1:123:64\n" +
      byteString(64)
    val hashes = sb2.parseFullHashes(data.getBytes(), Some(MacKey("clientkey","wrappedkey")))
  }

  @Test
  def testLocalLookupSuffix_noMatch = {
    val e = Expression("www.test.com", "/1.html")
    val addChunks = Seq(Chunk(123, "nonmatchingprefix", "hostkey", "listname", 0))
    when(storage.getAddChunks("suffix")).thenReturn(addChunks)

    val chunks = sb2.local_lookup_suffix("suffix", Seq(e))
    assertTrue(chunks.isEmpty)
  }

  @Test
  def testLocalLookupSuffix_matchInSub = {
    val e = Expression("www.test.com", "/1.html")
    val addChunks = Seq(Chunk(123, e.hexHash.take(4), "hostkey", "listname", 0))
    val subChunks = Seq(Chunk(456, e.hexHash.take(4), "hostkey", "listname", 123))
    when(storage.getAddChunks("suffix")).thenReturn(addChunks)
    when(storage.getSubChunks("suffix")).thenReturn(subChunks)

    val chunks = sb2.local_lookup_suffix("suffix", Seq(e))
    assertTrue(chunks.isEmpty)
  }

  @Test
  def testLocalLookupSuffix_match = {
    val e = Expression("www.test.com", "/1.html")
    val addChunks = Seq(Chunk(123, "nonmatchingprefix", "hostkey", "listname", 0),
      Chunk(234, e.hexHash.take(4), "hostkey", "listname", 0))
    val subChunks = Seq(Chunk(456, "nonmatchingprefix", "hostkey", "listname", 123))
    when(storage.getAddChunks("suffix")).thenReturn(addChunks)
    when(storage.getSubChunks("suffix")).thenReturn(subChunks)

    val chunks = sb2.local_lookup_suffix("suffix", Seq(e))
    assertThat(chunks.size, is(1))
    assertThat(chunks(0).chunknum, is(234))
  }

  @Test
  def testRequestFullHash = {
    val chunks = Seq(Chunk(123, "00112233", "hostkey", "listname", 0),
      Chunk(123, "11221133", "hostkey", "listname", 0))
    val data = "list1:123:64\n" +
      byteString(64)
    when(storage.getFullHashError(anyM(classOf[String]))).thenReturn(None)
    val response = mock[Response]
    when(sb2.httpClient.POST(anyM(classOf[String]), anyM(classOf[Array[Byte]]), anyM(classOf[Map[String, String]]))).thenReturn(response)
    when(response.statusCode(false)).thenReturn(200)
    when(response.asBytes()).thenReturn(data.getBytes())

    val hashes = sb2.requestFullHashes(chunks, false)
    assertThat(hashes.size, is(2))
    assertThat(hashes(0).hash, is(hexString(32)))
    assertThat(hashes(1).hash, is(hexString(32, 64)))
  }

  @Test
  def testRequestFullHash_differentSizes = {
    val chunks = Seq(Chunk(123, "00112233", "hostkey", "listname", 0),
      Chunk(123, "112211334455", "hostkey", "listname", 0))

    when(storage.getFullHashError(anyM(classOf[String]))).thenReturn(None)
    val response = mock[Response]
    when(sb2.httpClient.POST(anyM(classOf[String]), anyM(classOf[Array[Byte]]), anyM(classOf[Map[String, String]]))).thenReturn(response)
    when(response.statusCode(false)).thenReturn(200)

    var callNum = 0
    when(response.asBytes()).thenAnswer(new Answer[Array[Byte]] {
      def answer(invocation: InvocationOnMock) = {
        val data = "list1:123:32\n".getBytes() ++ bytes(callNum, callNum + 32)
        callNum += 32
        data
      }
    })

    val hashes = sb2.requestFullHashes(chunks, false)
    assertThat(hashes.size, is(2))
    assertThat(hashes(0).hash, is(hexString(32)))
    assertThat(hashes(1).hash, is(hexString(32, 64)))
  }
}