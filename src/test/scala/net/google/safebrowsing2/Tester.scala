package net.google.safebrowsing2
import net.google.safebrowsing2.model.MacKey
import org.apache.commons.codec.binary.Base64
import java.net.HttpURLConnection
import com.github.tototoshi.http.Client

object Tester extends Application {

  val apikey = "ABQIAAAABYkmAAm4XQxOniSBu7POOBSi8x_kWneXQyiBH-s1nM-mcx8RKg"
  val pver = "2.2"
  val appver = "0.1"
  var postUrl = "http://safebrowsing.clients.google.com/safebrowsing/downloads?client=api&apikey=" + apikey + "&appver=" + appver + "&pver=" + pver;
  val clientkey = "24:O-yo9Dl283VTgN_ep_VRUA=="
  val wrappedkey = "AKEgNitiRFHYuApfqGEZ-L2rOfxbUPqCsolWXKwPfkv9MtFA6t2_-tmCV39Q6lKtCsvN2q92UKzzpuI9RnXE31m_oCtC8hkmbw=="

  val c = new Client
  val r = c.GET("http://safebrowsing-cache.google.com/safebrowsing/rd/ChNnb29nLW1hbHdhcmUtc2hhdmFyEAEYt6UFIMClBTIGt1IBAP8D")
  val data: Array[Byte] = r.asBytes()

  val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); None
  }
  
  println(parsed)
  
  def rfd = {
    val body = "goog-malware-shavar;\ngoogpub-phish-shavar;"
    val c = new Client
    val response = c.POST(postUrl, body)

    val responseData = response.asString
    response.statusCode() match {
      case 200 => {}
      case other => {
        println("Request failed")
      }
    }

    println("-----------------")
    println(responseData)
    println("-----------------")
    val parseResult = RFDResponseParser.parse(responseData) match {
      case RFDResponseParser.Success(resp, _) => Option(resp)
      case x => println("Error parsing RFD response: " + x); None
    }

    val res = parseResult.get
    println(res)
  }
}