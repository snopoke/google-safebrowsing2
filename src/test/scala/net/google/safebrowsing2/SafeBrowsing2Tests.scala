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

class SafeBrowsing2Tests extends MockitoSugar {
  
  var sb2: SafeBrowsing2 = _ 
  var storage: Storage = _
  
  @Before
  def before = {
    storage = mock[Storage]
    sb2 = new SafeBrowsing2(storage)
    sb2.httpClient = mock[Client]
  }

  @Test
  def testGetMacKeys = {
    val response = "clientkey:24:VyUHdnlAPEJa42JKq5oo8Q==\n" +
    		"wrappedkey:12:AKEgNisrzEPf"
    
    val key = sb2.processMacResponse(response)
    assertTrue(key.isDefined)
    assertThat(key.get.getClientKey(), is("VyUHdnlAPEJa42JKq5oo8Q=="))
    assertThat(key.get.getWrappedKey(), is("AKEgNisrzEPf"))
  }
  
  @Test(expected = classOf[ AssertionError] )
  def testGetMacKeys_incorrectClientLength = {
    val response = "clientkey:23:VyUHdnlAPEJa42JKq5oo8Q==\n" +
    		"wrappedkey:12:AKEgNisrzEPf"
    val key = sb2.processMacResponse(response)
  }
  
  @Test(expected = classOf[ AssertionError] )
  def testGetMacKeys_incorrectWrappedLength = {
    val response = "clientkey:24:VyUHdnlAPEJa42JKq5oo8Q==\n" +
    		"wrappedkey:13:AKEgNisrzEPf"
    val key = sb2.processMacResponse(response)
  }
  
  @Test
  def testCreateRange = {
    val input = Array(1,2,4,5,6,8)
    val range = sb2.createRange(input)
    assertThat(range, is ("1-2,4-6,8"))
  }
  
  @Test
  def testGetExistingChunks = {
    val a_nums = Array(1,2,3,5,6,7);
    val s_nums = Array(8,9,10,15,16,19)
    
    when(storage.getAddChunksNums("list")).thenReturn(a_nums)
    when(storage.getSubChunksNums("list")).thenReturn(s_nums)
    
    val existing = sb2.getExistingChunks(Array("list"), true);
    assertThat(existing, is("list;a:1-3,5-7:s:8-10,15-16,19:mac\n"))
  }
  
   @Test
  def testGetExistingChunks_aOnly = {
    val a_nums = Array(1,2,3,5,6,7);
    
    when(storage.getAddChunksNums("list")).thenReturn(a_nums)
    
    val existing = sb2.getExistingChunks(Array("list"), false);
    assertThat(existing, is("list;a:1-3,5-7\n"))
  }
  
  @Test
  def testGetExistingChunks_sOnly = {
    val s_nums = Array(8,9,10,15,16,19)
    
    when(storage.getSubChunksNums("list")).thenReturn(s_nums)
    
    val existing = sb2.getExistingChunks(Array("list"), false);
    assertThat(existing, is("list;s:8-10,15-16,19\n"))
  }
  
  @Test
  def testProcessRedirect = {
    val resp = mock[Response]
    val data = "a:6:2:9\n" +
    		"cded2abcd" +
    		"s:3:2:9\n" +
    		"45sd0789a"
    when(sb2.httpClient.GET("http://url")).thenReturn(resp)
    when(resp.statusCode()).thenReturn(200)
    when(resp.asString()).thenReturn(data)
    
    val result = sb2.processRedirect("url", None, "list")
    assertThat(result, is(Result.SUCCESSFUL))
    verify(storage).addChunks_a(6,"cded",List("ab","cd"), "list")
    verify(storage).addChunks_s(3,"45sd",List(("789a","")), "list")
  }

}