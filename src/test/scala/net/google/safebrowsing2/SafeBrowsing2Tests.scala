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
import org.mockito.Matchers
import com.github.tototoshi.http.Response
import org.apache.http.HttpResponse
import util.Helpers._
import net.google.safebrowsing2.db.DBI

class SafeBrowsing2Tests extends MockitoSugar with ByteUtil {

  var sb2: SafeBrowsing2 = _
  var storage: DBI = _

  @Before
  def before = {
    storage = mock[DBI]
    sb2 = new SafeBrowsing2(storage)
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
      new String(Array(1, 2, 3, 4, 0, 1, 1, 2, 2): Array[Byte])
    when(sb2.httpClient.GET("http://url")).thenReturn(resp)
    when(resp.statusCode()).thenReturn(200)
    when(resp.asBytes()).thenReturn(data.getBytes())

    val result = sb2.processRedirect("url", None, "list", None)
    assertThat(result, is(Result.SUCCESSFUL))
    verify(storage).addChunks_a(6, "090A0B0C", List("0101", "0202"), "list")
    verify(storage).addChunks_s(3, "01020304", List(("01010202", "")), "list")
  }

  @Test
  def testProcessRedirect_badStatuScode = {
    val resp = mock[Response]
    when(sb2.httpClient.GET("http://url")).thenReturn(resp)
    when(resp.statusCode()).thenReturn(400)

    val result = sb2.processRedirect("url", None, "list", None)
    assertThat(result, is(Result.SERVER_ERROR))
  }

  @Test
  def testProcessRedirect_missingMac = {
    val data = "a:6:2:9\n" +
      new String(Array(9, 10, 11, 12, 2, 1, 1, 2, 2): Array[Byte])
    val resp = mock[Response]
    when(sb2.httpClient.GET("http://url")).thenReturn(resp)
    when(resp.statusCode()).thenReturn(200)

    val result = sb2.processRedirect("url", None, "list", Some(MacKey("", "")))
    assertThat(result, is(Result.MAC_ERROR))
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
    assertThat(result, is(Result.SUCCESSFUL))
  }

  @Test
  def testCanonicalDomainSuffixes = {
    val domains = sb2.canonicalDomainSuffixes("www.google.com")
    assertThat(domains.size, is(2))
    assertTrue(domains.contains("www.google.com"))
    assertTrue(domains.contains("google.com"))
  }

  @Test
  def testCanonicalDomainSuffixes_short = {
    val domains = sb2.canonicalDomainSuffixes("google.com")
    assertThat(domains.size, is(1))
    assertTrue(domains.contains("google.com"))
  }

  @Test
  def testCanonicalDomainSuffixes_long = {
    val domains = sb2.canonicalDomainSuffixes("malware.testing.google.test")
    assertThat(domains.size, is(2))
    assertTrue(domains.contains("google.test"))
    assertTrue(domains.contains("testing.google.test"))
  }
  
  @Test
  def testCanonicalDomain_long = {
    val domains = sb2.canonicalDomain("a.b.c.d.e.f.g")
    assertThat(domains.size, is(5))
    assertTrue(domains.contains("a.b.c.d.e.f.g"))
    assertTrue(domains.contains("c.d.e.f.g"))
    assertTrue(domains.contains("d.e.f.g"))
    assertTrue(domains.contains("e.f.g"))
    assertTrue(domains.contains("f.g"))
  }
  
  @Test
  def testCanonicalDomain_short = {
    val domains = sb2.canonicalDomain("d.e.f.g")
    assertThat(domains.size, is(3))
    assertTrue(domains.contains("d.e.f.g"))
    assertTrue(domains.contains("e.f.g"))
    assertTrue(domains.contains("f.g"))
  }
  
  @Test
  def testCanonicalPath = {
    val paths = sb2.canonicalPath("/1/2.html?param=1")
    assertThat(paths.size, is(4))
    assertTrue(paths.contains("/1/2.html?param=1"))
    assertTrue(paths.contains("/1/2.html"))
    assertTrue(paths.contains("/1/"))
    assertTrue(paths.contains("/"))
  }
  
  @Test
  def testCanonicalPath_long = {
    val paths = sb2.canonicalPath("/1/2/3/4/5/6/7.html?param=1")
    assertThat(paths.size, is(6))
    assertTrue(paths.contains("/1/2/3/4/5/6/7.html?param=1"))
    assertTrue(paths.contains("/1/2/3/4/5/6/7.html"))
    assertTrue(paths.contains("/"))
    assertTrue(paths.contains("/1/"))
    assertTrue(paths.contains("/1/2/"))
    assertTrue(paths.contains("/1/2/3/"))
    assertTrue(paths.contains("/1/2/3/"))
  }
    
  @Test
  def testCanonical = {
    val urls = sb2.canonical("http://a.b.c/1/2.html?param=1")
    assertThat(urls.size, is (8))
    assertTrue(urls.contains("a.b.c/1/2.html?param=1"))
    assertTrue(urls.contains("a.b.c/1/2.html"))
    assertTrue(urls.contains("a.b.c/"))
    assertTrue(urls.contains("a.b.c/1/"))
    assertTrue(urls.contains("b.c/1/2.html?param=1"))
    assertTrue(urls.contains("b.c/1/2.html"))
    assertTrue(urls.contains("b.c/"))
    assertTrue(urls.contains("b.c/1/"))
  }
  
  @Test
  def testCanonical_long = {
    val urls = sb2.canonical("http://a.b.c.d.e.f.g/1.html")
    assertThat(urls.size, is (10))
    assertTrue(urls.contains("a.b.c.d.e.f.g/1.html"))
    assertTrue(urls.contains("a.b.c.d.e.f.g/"))
    assertTrue(urls.contains("c.d.e.f.g/1.html"))
    assertTrue(urls.contains("c.d.e.f.g/"))
    assertTrue(urls.contains("d.e.f.g/1.html"))
    assertTrue(urls.contains("d.e.f.g/"))
    assertTrue(urls.contains("e.f.g/1.html"))
    assertTrue(urls.contains("e.f.g/"))
    assertTrue(urls.contains("f.g/1.html"))
    assertTrue(urls.contains("f.g/"))
  }

  @Test
  def testPrefix = {
    val prefix = sb2.hashPrefix("abc")
    assertThat(prefix.length, is(8))
    val e: Array[Byte] = Array(0xBA, 0x78, 0x16, 0xBF).map(_.toByte)
    assertThat(prefix, is(bytes2Hex(e)))
  }

  @Test
  def testParseFullHashes() = {
    val data = "list1:123:64\n" +
      byteString(64)
    val hashes = sb2.parseFullHashes(data.getBytes())
    assertThat(hashes.size, is(2))
    assertThat(hashes(0).list, is("list1"))
    assertThat(hashes(0).chunknum, is(123))
    assertThat(hashes(0).hash, is(hexString(32)))
    assertThat(hashes(1).list, is("list1"))
    assertThat(hashes(1).chunknum, is(123))
    assertThat(hashes(1).hash, is(hexString(32, 64)))
  }
  
  @Test
  def testLocalLookupSuffix_noMatch = {
    val addChunks = Seq(Chunk(123,"prefix", "hostkey", "listname", 0))
    when(storage.getAddChunks("suffix")).thenReturn(addChunks)
    
    val chunks = sb2.local_lookup_suffix("suffix", Seq("prefix2"))
    assertTrue(chunks.isEmpty)
  }
  
  @Test
  def testLocalLookupSuffix_matchInSub = {
    val addChunks = Seq(Chunk(123,"prefix", "hostkey", "listname", 0))
	val subChunks = Seq(Chunk(456,"prefix", "hostkey", "listname", 123))
    when(storage.getAddChunks("suffix")).thenReturn(addChunks)
    when(storage.getSubChunks("suffix")).thenReturn(subChunks)
    
    val chunks = sb2.local_lookup_suffix("suffix", Seq("prefix"))
    assertTrue(chunks.isEmpty)
  }
  
  @Test
  def testLocalLookupSuffix_match = {
    val addChunks = Seq(Chunk(123,"prefix", "hostkey", "listname", 0),
        Chunk(234,"prefix1", "hostkey", "listname", 0))
	val subChunks = Seq(Chunk(456,"prefix", "hostkey", "listname", 123))
    when(storage.getAddChunks("suffix")).thenReturn(addChunks)
    when(storage.getSubChunks("suffix")).thenReturn(subChunks)
    
    val chunks = sb2.local_lookup_suffix("suffix", Seq("prefix1"))
    assertThat(chunks.size, is(1))
    assertThat(chunks(0).chunknum, is(234))
  }
}