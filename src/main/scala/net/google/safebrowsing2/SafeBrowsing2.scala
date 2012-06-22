package net.google.safebrowsing2
import java.net.URI
import java.net.URL
import java.util.Date
import scala.Array.canBuildFrom
import scala.collection.mutable.ListBuffer
import scala.collection.mutable
import scala.util.control.Breaks.break
import scala.util.control.Breaks.breakable
import com.buildabrand.gsb.util.URLUtils
import com.github.tototoshi.http.Client
import net.google.safebrowsing2.parsers.DataParser
import net.google.safebrowsing2.parsers.FullHashParser
import net.google.safebrowsing2.parsers.RFDResponseParser
import util.Helpers.bytes2Hex
import util.Helpers.getMac
import util.Helpers.hex2Bytes
import util.Helpers.sha256
import util.Logging
import net.google.safebrowsing2.db.DBI
import scala.math.min
import org.joda.time.DateTime
import org.joda.time.Period
import db.Storage
import org.joda.time.Duration

class SafeBrowsing2(apikey: String, storage: Storage) extends Logging {
  val MALWARE = "goog-malware-shavar"
  val PHISHING = "googpub-phish-shavar"
  val lists = Array(MALWARE, PHISHING)
  val appver = "0.1"
  var pver = "2.2"
  var httpClient: Client = new Client

  /**
   * @param listName the list to update or null to update all lists
   * @param force if true force the update ignoring wait times
   * @param withMac if true request using Message Authentication Codes
   * @return the number of seconds to wait before updating again
   */
  @throws(classOf[ApiException])
  def update(listName: String, force: Boolean = false, withMac: Boolean = false): Int = {

    val candidates: Array[String] = if (listName == null || !listName.isEmpty()) {
      Array(listName)
    } else {
      lists
    }

    val now = new DateTime()
    var minUpdateWait = Int.MaxValue

    // filter list based on when we last updated it
    val toUpdate = candidates.filter(listName => {
      val info = storage.lastUpdate(listName)
      val tooEarly = !force && info.map(_.waitUntil.isAfter(now)).getOrElse(false)
      if (tooEarly) {

        if (info.isDefined) {
          val secs = new Duration(now, info.get.waitUntil).getStandardSeconds()
          if (secs < minUpdateWait)
            minUpdateWait = secs.toInt
        }

        logger.debug("Too early to update {}: {} / {}", Array[Object](listName, now, info.map(_.waitUntil)))
      } else {
        logger.debug("OK to update {}: {} / {}", Array[Object](listName, now, info.map(_.waitUntil)))
      }
      !tooEarly
    })

    if (toUpdate.isEmpty) {
      logger.debug("Too early to update any list");
      return minUpdateWait;
    }

    var macKey: Option[MacKey] = None
    if (withMac) {
      macKey = getMacKeys orElse {
        throw new ApiException("Error getting MAC keys")
      }
    }

    var postUrl = "http://safebrowsing.clients.google.com/safebrowsing/downloads?client=api&apikey=" + apikey + "&appver=" + appver + "&pver=" + pver;
    macKey map { key =>
      postUrl += "&wrkey=" + key.wrappedKey
    }

    logger.debug("Performing request for data")
    var body = getExistingChunks(toUpdate, withMac)
    logger.trace("Request for data body:\n{}", body)
    val response = httpClient.POST(postUrl, body)

    val responseData = response.asString
    response.statusCode() match {
      case 200 => logger.debug("Request for data success")
      case other => {
        logger.error("Request failed. Response:\n{}", responseData)
        toUpdate.foreach(list => storage.updateError(now, list))
        throw new ApiException("Update request failed: HTTP Error=" + other)
      }
    }

    logger.trace("RFD response for lists: {}\n{}", toUpdate.mkString(","), responseData)

    val parseResult = RFDResponseParser.parse(responseData) match {
      case RFDResponseParser.Success(resp, _) => Option(resp)
      case x => {
        logger.error("Error parsing RFD response: " + x);
        throw new ParsingException("Error parsing response from server")
      }
    }
    
    logger.debug("Parsing RFD data successful")
    val resp = parseResult.get
    if (resp.rekey) {
      logger.debug("Re-key requested")
      storage.delete_mac_keys
      return update(listName, force, withMac)
    }

    resp.mac.foreach(dataMac => {
      macKey.foreach(ourMac => {
        // FIXME: MAC validation is failing
        logger.debug("MAC of request: {}", dataMac)
        val data = responseData.replaceAll("""^m:\s*(\S+)\s*\n""", "")
        if (!validateMac(data.getBytes, ourMac.clientKey, dataMac)) {
          logger.error("MAC error on main request")
          throw new MacException("MAC error on main request")
        }
      })
    })

    if (resp.reset) {
      logger.error("================> DATABASE RESET REQUESTED <=================")
      toUpdate foreach (l => storage.reset(l))
      return 0
    }

    try {
      resp.list foreach (list => {
        list foreach (chunklist => {
          chunklist.data foreach (d => {
            d match {
              case RFDResponseParser.Redirect(url, mac) => {
                processRedirect(url, mac, chunklist.name, macKey)
              }
              case RFDResponseParser.AdDel(adlist) => {
                processDelAd(adlist, chunklist.name)
              }
              case RFDResponseParser.SubDel(sublist) => {
                processDelSub(sublist, chunklist.name)
              }
            }
          })
        })
      })
    } catch {
      case e => {
        toUpdate foreach (list => {
          logger.error("Error updating list: " + list, e)
          storage.updateError(now, list)
        })
        throw e
      }
    }

    toUpdate foreach (list => {
      logger.debug("List update: [list={}] [wait={}]", list, resp.next)
      storage.updated(now, resp.next, list)
      if (resp.next < minUpdateWait)
        minUpdateWait = resp.next
    })

    minUpdateWait
  }
  
  /**
   * Lookup a URL against the Google Safe Browsing database.
   *
   * @param url
   * @param listName Optional. Lookup against a specific list.
   * @returns Returns List name if there is a match or null
   * 
   * Java compatibility method
   */
  def jlookup(url: String, listName: String, withMac: Boolean): String = {
    lookup(url, listName, withMac).orNull
  }

  /**
   * Lookup a URL against the Google Safe Browsing database.
   *
   * @param url
   * @param listName Optional. Lookup against a specific list.
   * @returns Returns Option(list name) if there is a match or None.
   */
  def lookup(url: String, listName: String, withMac: Boolean): Option[String] = {
    val candidates: Array[String] = if (!listName.isEmpty()) {
      Array(listName)
    } else {
      lists
    }

    val generator = new ExpressionGenerator(url)
    val expressions = generator.expressions
    val hostKey = generator.hostKey
    lookup_hostKey(candidates, expressions, hostKey, withMac)
  }

  def lookup_hostKey(lists: Seq[String], expressions: Seq[Expression], hostKey: String, withMac: Boolean): Option[String] = {

    // Local lookup
    val add_chunks = local_lookup_suffix(hostKey, expressions)
    if (add_chunks.isEmpty) {
      logger.debug("No hit in local lookup")
      return None
    }

    // Check against full hashes
    val hashesInStore = new ListBuffer[String]()
    add_chunks foreach (achunk => {
      if (lists.contains(achunk.list)) {
        val hashes = storage.getFullHashes(achunk.chunknum, new DateTime().minus(Period.minutes(45)), achunk.list)
        logger.debug("Full hashes already stored for chunk " + achunk.chunknum + ": " + hashes.length)
        hashesInStore ++= hashes

        expressions foreach (e => {
          if (hashes.find(_.equals(e.hexHash)).isDefined) {
            logger.debug("Full hash was found in storage")
            return Some(achunk.list)
          }
        })
      }
    })

    // filter out chunks that we already have full hashes for
    val requestChunks = add_chunks.filter(chunk => hashesInStore.find(hash => hash.startsWith(chunk.prefix)).isEmpty)
    //ask for new hashes
    val hashes = requestFullHashes(requestChunks, withMac)
    storage.addFullHashes(new DateTime(), hashes)

    expressions foreach (e => {
      val hash = hashes.find(h => h.hash.equals(e.hexHash))
      val list = hash.flatMap(h => lists.find(l => h.list.equals(l)))
      if (hash.isDefined && list.isDefined) {
        logger.debug("Match for url {} in list {}", e.value, list.get)
        return list
      }
    })
    None
  }

  /**
   *  Request full full hashes for specific prefixes from Google.
   */
  def requestFullHashes(chunks: Seq[Chunk], withMac: Boolean): Seq[Hash] = {

    /**
     * Return true if the wait time has passed or false otherwise
     */
    def delay(status: Status, wait: Period): Boolean = {
      status.updateTime.plus(wait).isBeforeNow()
    }

    var macKey: Option[MacKey] = None
    if (withMac) {
      macKey = storage.getMacKey.orElse(requestMacKeys)
      if (macKey.isEmpty) throw new MacException("Unable to get MacKey")
    }

    // TODO: better back off
    val toFetch = chunks filter (c => {
      val errors = storage.getFullHashError(c.prefix)
      val fetch = errors match {
        case None => true
        case Some(status) if (status.errors <= 2) => true
        case Some(status) if (status.errors == 3) => delay(status, Period.minutes(30))
        case Some(status) if (status.errors == 4) => delay(status, Period.hours(1))
        case Some(status) => delay(status, Period.hours(2))
      }
      if (!fetch) {
        logger.debug("Delaying fetch of full hash for chunk: {} / {}", c, errors)
      }
      fetch
    })

    if (toFetch.isEmpty) {
      logger.debug("Fetching of all full hashes has been delayed.")
      return Nil
    }

    val sizeMap = mutable.Map[Int, ListBuffer[Chunk]]()
    toFetch.foreach(c => {
      sizeMap.getOrElseUpdate(c.prefix.length, ListBuffer[Chunk]()) += c
    })

    var hashes = mutable.ListBuffer[Hash]()
    for ((length, list) <- sizeMap) {
      hashes ++= requestFullHashes(list.toList, length, macKey)
    }

    hashes.seq
  }

  def requestFullHashes(prefixes: List[Chunk], prefixLength: Int, macKey: Option[MacKey]): Seq[Hash] = {
    if (prefixes.isEmpty) return Nil

    prefixes foreach (p => {
      if (p.prefix.length != prefixLength) {
        throw new ApiException("All prefixes must have length " + prefixLength)
      }
    })

    val header = (prefixLength + ":" + prefixLength * prefixes.size + "\n").getBytes()
    val body = header ++ prefixes.map(p => hex2Bytes(p.prefix)).reduce(_ ++ _)
    logger.trace("Full hash request body:\n{}", new String(body))

    var url = "http://safebrowsing.clients.google.com/safebrowsing/gethash?client=api&apikey=" + apikey + "&appver=" + appver + "&pver=" + pver;
    macKey.foreach(key => url += "&wrkey=" + key.wrappedKey)

    val res = httpClient.POST(url, body, Map())
    res.statusCode(false) match {
      case 200 => {}
      case 204 => logger.debug("No content returned for hash request"); res.consume; Nil
      case other => {
        res.consume
        val msg = "Full hash request failed: " + other
        logger.error(msg)
        prefixes foreach (c => {
          // TODO: back off mode
          storage.fullHashError(new DateTime(), c.prefix)
        })
        throw new ApiException(msg)
      }
    }

    try {
      storage.clearFullhashErrors(prefixes)
      parseFullHashes(res.asBytes(), macKey)
    } catch {
      case e: RekeyException => {
        storage.delete_mac_keys
        requestFullHashes(prefixes, prefixLength, macKey)
      }
      case other => throw other
    }
  }

  def parseFullHashes(data: Array[Byte], macKey: Option[MacKey]): Seq[Hash] = {
    val parsed = FullHashParser.parse(data) match {
      case FullHashParser.Success(c, _) => Option(c)
      case x => logger.error("Error parsing full hash data: {}", x); return Nil
    }

    val hashes = parsed.map(env => {
      if (env.rekey) { throw new RekeyException }
      macKey.foreach(mac => {
        if (env.mac.isEmpty) throw new MacException("Empty MAC in full hash request")

        val signed = data.dropWhile(_ != '\n').drop(1)
        if (!validateMac(signed, mac.clientKey, env.mac.get)) {
          val msg = "MAC validation failed for full hash data"
          logger.error(msg)
          throw new MacException(msg)
        }
      })

      env.hashdata.map(full => {
        full.hashes.map(h => Hash(full.addChunknum, h, full.list))
      }).reduce(_ ++ _)
    })
    hashes.getOrElse(Nil)
  }

  /**
   * Lookup a host prefix in the local database only.
   */
  def local_lookup_suffix(suffix: String, expressions: Seq[Expression]): Seq[Chunk] = {

    // Step 1: get all add chunks for this host key
    // Do it for all lists
    var add_chunks = storage.getAddChunks(suffix)
    if (add_chunks.isEmpty) { // no match
      logger.debug("No host key");
      return add_chunks
    }

    // Step 3: filter out non-matching chunks
    add_chunks = add_chunks.filter(c => expressions.find(e => e.hexHash.startsWith(c.prefix)).isDefined)

    if (add_chunks.isEmpty) {
      logger.debug("No prefix match for any host key");
      return add_chunks
    }

    // Step 4: get all sub chunks for this host key
    val sub_chunks = storage.getSubChunks(suffix)

    // remove all add_chunks that occur in the list of sub_chunks
    add_chunks = add_chunks.filter(c => {
      sub_chunks.find(sc =>
        c.chunknum == sc.addChunknum &&
          c.list.equals(sc.list) &&
          c.prefix.equals(sc.prefix)).isEmpty
    })

    if (add_chunks.isEmpty) {
      logger.debug("All add_chunks have been removed by sub_chunks");
    }

    add_chunks
  }

  def getExistingChunks(lists: Array[String], withMac: Boolean): String = {
    var body = ""

    lists foreach (list => {
      // Report existing chunks
      val a_range = createRange(storage.getAddChunksNums(list))
      val s_range = createRange(storage.getSubChunksNums(list))

      var chunks_list = ""
      if (!a_range.isEmpty) {
        chunks_list += "a:" + a_range
      }
      if (!s_range.isEmpty()) {
        if (!a_range.isEmpty)
          chunks_list += ":"
        chunks_list += "s:" + s_range;
      }

      body += "%s;%s".format(list, chunks_list)
      if (withMac)
        body += ":mac"
      body += "\n"
    })
    body
  }

  def processDelAd(nums: List[Int], list: String) = {
    logger.debug("Delete Add Chunks: {}", nums)
    storage.deleteAddChunks(nums, list)

    // Delete full hash as well
    storage.deleteFullHashes(nums, list)
  }

  def processDelSub(nums: List[Int], list: String) = {
    logger.debug("Delete Sub Chunks: {}", nums)
    storage.deleteSubChunks(nums, list)
  }

  @throws(classOf[ApiException])
  def processRedirect(url: String, hmac: Option[String], listName: String, macKey: Option[MacKey]) = {
    logger.debug("Checking redirection http://{} ({})", url, listName)
    val res = httpClient.GET("http://" + url)

    res.statusCode(false) match {
      case 200 => {}
      case other => {
        res.consume
        val msg = "Request to %s failed: %d".format(url, other)
        logger.error(msg)
        throw new ApiException(msg)
      }
    }

    val data = res.asBytes()

    macKey foreach { key =>
      hmac match {
        case Some(x) => {
          if (!validateMac(data, key.clientKey, x)) {
            val msg = "MAC validation failed for redirection url: " + url
            logger.error(msg)
            logger.debug("Length of data: " + data.length)
            throw new MacException(msg)
          }
        }
        case _ => {
          val msg = "MAC key empty for redirection url: " + url
          logger.error(msg)
          throw new MacException(msg)
        }
      }
    }

    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => {
        val msg = "Error parsing redirect data: " + x
        logger.error(msg);
        throw new ParsingException(msg)
      }
    }

    parsed.get foreach (l => {
      l match {
        case a: DataParser.AdHead => storage.addChunks_a(a.chunknum, a.host, a.prefixes, listName)
        case s: DataParser.SubHead => storage.addChunks_s(s.chunknum, s.host, s.pairs, listName)
      }
    })
  }

  def getMacKeys: Option[MacKey] = {
    val keys = storage.getMacKey
    keys orElse ({
      val key = requestMacKeys
      key map { k =>
        storage.addMacKey(k)
      }
      key
    })
  }

  def requestMacKeys: Option[MacKey] = {
    logger.debug("Requesting mac keys")
    val url = "http://sb-ssl.google.com/safebrowsing/newkey"
    val c = new Client
    val resp = c.GET(url, Map(
      "client" -> "api",
      "apikey" -> apikey,
      "appver" -> appver,
      "pver" -> pver))

    resp.statusCode(false) match {
      case 200 => processMacResponse(resp.asString())
      case other => logger.error("Key request failed: {}" + other); resp.consume; None
    }
  }

  def processMacResponse(res: String): Option[MacKey] = {
    logger.trace("MAC Response:\n{}", res)
    val Client = "^clientkey:(\\d+):(.*)$".r
    val Wrapped = "^wrappedkey:(\\d+):(.*)$".r
    var clientkey = ""
    var wrappedkey = ""
    res.split("\n").foreach(line => {
      line match {
        case Client(len, ckey) => {
          assert(ckey.length() == len.toInt, "Client key is not expected length")
          clientkey = ckey
        }
        case Wrapped(len, wkey) => {
          assert(wkey.length() == len.toInt, "Wrapped key is not expected length")
          wrappedkey = wkey
        }
      }
    })
    Some(MacKey(clientkey, wrappedkey))
  }

  def createRange(numbers: Seq[Int]): String = {
    if (numbers == null || numbers.isEmpty) {
      return ""
    }

    var range = numbers(0).toString
    var new_range = 0
    for (i <- 1.until(numbers.size)) {
      if (numbers(i) != numbers(i - 1) + 1) {
        if (i > 1 && new_range == 1)
          range += numbers(i - 1)
        range += "," + numbers(i)

        new_range = 0
      } else if (new_range == 0) {
        range += "-"
        new_range = 1
      }
    }
    if (new_range == 1)
      range += numbers(numbers.length - 1)

    range
  }

  def validateMac(data: Array[Byte], key: String, digest: String): Boolean = {
    val sig = getMac(data, key)
    logger.debug("Mac check: {} / {}", sig, digest)
    sig == digest
  }
}

class ApiException(msg: String) extends Exception(msg)
class MacException(msg: String) extends ApiException(msg)
class ParsingException(msg: String) extends ApiException(msg)
class RekeyException extends ApiException("")
