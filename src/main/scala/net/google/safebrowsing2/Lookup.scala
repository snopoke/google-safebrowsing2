package net.google.safebrowsing2
import org.slf4j.LoggerFactory
import com.github.tototoshi.http.Client
import scala.collection.mutable
import java.net.URI
import com.buildabrand.gsb.util.URLUtils
import util.Logging

/**
 * Lookup implements the Google Safe Browsing v2 Lookup API.
 *
 * If you need to check more than 10,000 URLs a day, you need to use {@link net.google.safebrowsing2.SafeBrowsing2}
 *
 * @see http://code.google.com/apis/safebrowsing/lookup_guide.html
 * @param apikey the Google Safe Browsing API key to use in any requests
 * @param appName the name of the application doing the lookup e.g. "firefox"
 * @param urlBase the base URL to use for the request. Defaults to "https://sb-ssl.google.com/safebrowsing/api/"
 * @param pver the version of the Lookup API. Defaults to "3.0"
 */
class Lookup(apikey: String, appName: String, urlBase: String, pver: String) extends Logging {
  def this(apikey: String, appName: String) = this(apikey, appName, "https://sb-ssl.google.com/safebrowsing/api/", "3.0")

  val appver = "1.0"

  val httpClient = new Client

  /**
   * Lookup a list URLs against the Google Safe Browsing v2 lists.
   *
   * @param urls
   * 	The list of URL's to check
   * @param delay
   * 	Int indicating how many seconds to delay between batches of 500 to avoid rate limiting by Google.
   *
   * @return Map[String, String]
   * 	url -> {Google match}.
   * 	The possible list of values for {Google match} are:
   * 		"ok" (no match),
   * 		"malware",
   * 		"phishing",
   * 		"malware,phishing" (match both lists),
   *  		"error[: XXX]" (XXX is HTTP error code if relevant )
   */
  def lookup(urls: Seq[String], delay: Int = 0) = {

    val results = mutable.Map.empty[String, String]

    // Max is 500 URLs per request
    var remain: Seq[String] = urls
    do {
      val batch = remain.take(500)
      remain = remain.drop(500)

      val body = new StringBuffer(batch.size.toString)
      batch foreach (url => {
        val canonical = URLUtils.getInstance().canonicalizeURL(url)
        body.append("\n" + canonical)
        logger.debug("{} => {}", url, canonical)
      })
      logger.debug("BODY:\n{}\n\n", body)

      val apiUrl = urlBase + "lookup?client=" + appName + "&apikey=" + apikey + "&appver=" + appver + "&pver=" + pver;

      if (delay > 0 && !results.isEmpty) {
        Thread.sleep(delay*1000)
      }

      val res = httpClient.POST(apiUrl, body.toString())
      val responseBody = res.asString()
      res.statusCode() match {
        case 200 => results ++= parseResponse(responseBody, batch)
        case 204 => {
          logger.debug("No matches in batch")
          batch foreach (url => results += url -> "ok")
        }
        case other => {
          logger.error("Error requesting batch: {}", other)
          batch foreach (url => results += url -> ("error: " + other))
        }
      }
    } while (!remain.isEmpty)

    results
  }

  def parseResponse(response: String, urls: Seq[String]): Map[String, String] = {
    val results = mutable.Map.empty[String, String]
    val lines = response.split("\n")
    if (lines.length != urls.length) {
      logger.error("Number of URLs in the reponse does not match the number of URLs in the request: {} / {}", lines.length, urls.length)
      urls foreach (url => results += url -> "error")
      return results.toMap
    }

    for (i <- 0 until lines.length) {
      results += urls(i) -> lines(i)
    }

    results.toMap
  }
}