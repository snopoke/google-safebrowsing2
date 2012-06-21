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
import Result.DATABASE_RESET
import Result.INTERNAL_ERROR
import Result.MAC_ERROR
import Result.MAC_KEY_ERROR
import Result.NO_UPDATE
import Result.Result
import Result.SERVER_ERROR
import Result.SUCCESSFUL
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

object Result extends Enumeration {
  type Result = Value
  val DATABASE_RESET = Value("DATABASE_RESET")
  val MAC_ERROR = Value("MAC_ERROR")
  val MAC_KEY_ERROR = Value("MAC_KEY_ERROR")
  val INTERNAL_ERROR = Value("INTERNAL_ERROR") // internal/parsing error
  val SERVER_ERROR = Value("SERVER_ERROR") // Server sent an error back
  val NO_UPDATE = Value("NO_UPDATE") // no update (too early)
  val NO_DATA = Value("NO_DATA") // no data sent
  val SUCCESSFUL = Value("SUCCESSFUL") // data sent
}

class SafeBrowsing2(apikey: String, storage: DBI) extends Logging {
  val MALWARE = "goog-malware-shavar"
  val PHISHING = "googpub-phish-shavar"
  val lists = Array(MALWARE, PHISHING)
  val appver = "0.1"
  var pver = "2.2"
  var httpClient: Client = new Client

  def update(listName: String, force: Boolean = false, withMac: Boolean = false): Result = {

    val candidates: Array[String] = if (listName == null || !listName.isEmpty()) {
      Array(listName)
    } else {
      lists
    }

    val now = new DateTime()
    // filter list based on when we last updated it
    val toUpdate = candidates.filter(listName => {
      val info = storage.lastUpdate(listName)
      val tooEarly = !force && info.map(_.waitUntil.isAfter(now)).getOrElse(false)
      if (tooEarly) {
        logger.debug("Too early to update {}: {} / {}", Array[Object](listName, now, info.map(_.waitUntil)))
      } else {
        logger.debug("OK to update {}: {} / {}", Array[Object](listName, now, info.map(_.waitUntil)))
      }
      !tooEarly
    })

    if (toUpdate.isEmpty) {
      logger.debug("Too early to update any list");
      return NO_UPDATE;
    }

    sys.exit()
    
    var macKey: Option[MacKey] = None
    if (withMac) {
      macKey = getMacKeys orElse {
        return MAC_KEY_ERROR;
      }
    }

    var postUrl = "http://safebrowsing.clients.google.com/safebrowsing/downloads?client=api&apikey=" + apikey + "&appver=" + appver + "&pver=" + pver;
    macKey map { key =>
      postUrl = "&wrkey=" + key
    }

    var body = getExistingChunks(toUpdate, withMac)
    val response = httpClient.POST(postUrl, body)

    val responseData = response.asString
    logger.trace("RFD response for lists: {}\n{}", toUpdate.mkString(","), responseData)
    response.statusCode() match {
      case 200 => {}
      case other => {
        logger.error("Request failed")
        toUpdate.foreach(list => storage.updateError(now, list))
        return SERVER_ERROR
      }
    }

    val parseResult = RFDResponseParser.parse(responseData) match {
      case RFDResponseParser.Success(resp, _) => Option(resp)
      case x => logger.error("Error parsing RFD response: " + x); return INTERNAL_ERROR
    }

    val resp = parseResult.get
    if (resp.rekey) {
      logger.debug("Re-key requested")
      storage.delete_mac_keys()
      return update(listName, force, withMac)
    }

    resp.mac.foreach(dataMac => {
      macKey.foreach(ourMac => {
        logger.debug("MAC of request: {}", dataMac)
        val data = responseData.replaceAll("""^m:\s*(\S+)\s*\n""", "")
        if (!validateMac(data.getBytes(), ourMac.clientKey, dataMac)) {
          logger.error("MAC error on main request")
          return MAC_ERROR
        }
      })
    })

    if (resp.reset) {
      logger.debug("Database must be reset")
      toUpdate foreach (l => storage.reset(l))
      return DATABASE_RESET
    }

    var result = SUCCESSFUL
    breakable {
      resp.list foreach (list => {
        list foreach (chunklist => {
          chunklist.data foreach (d => {
            d match {
              case RFDResponseParser.Redirect(url, mac) => {
                result = processRedirect(url, mac, chunklist.name, macKey)
                if (result != SUCCESSFUL) break
              }
              case RFDResponseParser.AdDel(adlist) => {
                result = processDelAd(adlist, chunklist.name)
                if (result != SUCCESSFUL) break
              }
              case RFDResponseParser.SubDel(sublist) => {
                result = processDelSub(sublist, chunklist.name)
                if (result != SUCCESSFUL) break
              }
            }
          })
        })
      })
    }

    toUpdate foreach (list => {
      result match {
        case SUCCESSFUL => {
          logger.debug("List update: [list={}] [wait={}]", list, resp.next)
          storage.updated(now, resp.next, list)
        }
        case MAC_ERROR => {}
        case other => {
          logger.error("Error updating list: " + list + ", error: " + other)
          storage.updateError(now, list)
        }
      }
    })

    return result
  }

  /**
   * Lookup a URL against the Google Safe Browsing database.
   *
   * @param url
   * @param listName Optional. Lookup against a specific list. Use the list(s) from new() by default.
   * @returns Returns Option(list name) with matching list or None.
   */
  def lookup(url: String, listName: String = ""): Option[String] = {
    val candidates: Array[String] = if (!listName.isEmpty()) {
      Array(listName)
    } else {
      lists
    }

    var cleanurl = URLUtils.getInstance().canonicalizeURL(url)
    val uri = new URL(cleanurl)
    val domain = uri.getHost()
    val hostKey = makeHostKey(domain)
    lookup_hostKey(candidates, url, hashPrefix(hostKey))
  }

  def lookup_hostKey(lists: Seq[String], url: String, hostKey: String): Option[String] = {

    val full_hashes = getFullHashes(url)

    // Get the prefixes from the first 4 bytes (8 chars)
    val full_hashes_prefix = full_hashes map (h => h.substring(0, 8))

    // Local lookup
    val add_chunks = local_lookup_suffix(hostKey, full_hashes_prefix)
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

        full_hashes foreach (h => {
          if (hashes.find(_.equals(h)).isDefined) {
            logger.debug("Full hash was found in storage")
            return Some(achunk.list)
          }
        })
      }
    })

    //ask for new hashes
    val hashes = requestFullHashes(full_hashes_prefix)
    storage.addFullHashes(new DateTime(), hashes)

    full_hashes foreach (fhash => {
      val hash = hashes.find(h => h.hash.equals(fhash))
      val list = hash.flatMap(h => lists.find(l => h.list.equals(l)))
      if (hash.isDefined && list.isDefined) {
        logger.debug("Match for url {} in list {}", url, list.get)
        return list
      }
    })
    None
  }

  /**
   *  Request full full hashes for specific prefixes from Google.
   */
  def requestFullHashes(prefixes: Seq[String]): Seq[Hash] = {

    /**
     * Return true if the wait time has passed or false otherwise
     */
    def delay(status: Status, wait: Period): Boolean = {
      status.updateTime.plus(wait).isBeforeNow()
    }

    val toFetch = prefixes filter (prefix => {
      val errors = storage.getFullHashError(prefix)
      val fetch = errors match {
        case None => true
        case Some(status) if (status.errors <= 2) => true
        case Some(status) if (status.errors == 3) => delay(status, Period.minutes(30)) 
        case Some(status) if (status.errors == 4) => delay(status, Period.hours(1))
        case Some(status) => delay(status, Period.hours(2))
      }
      if (!fetch){
        logger.debug("Delaying fetch of full hash for prefix: {} / {}", prefix, errors)
      }
      fetch
    })

    if (toFetch.isEmpty){
      logger.debug("Fetching of all full hashes has been delayed.")
      return Nil
    }
    
    val url = "http://safebrowsing.clients.google.com/safebrowsing/gethash?client=api&apikey=" + apikey + "&appver=" + appver + "&pver=" + pver;

    val prefix_list = toFetch.map(p => hex2Bytes(p)).reduce(_ ++ _)
    // assume all prefixes are the same size
    // TODO: split into batches of different sizes
    /*
     * # python equivalent
     * prefix_sizes = {}  # prefix length -> list of prefixes.
     * for prefix in prefixes:
     *   prefix_sizes.setdefault(len(prefix), []).append(prefix)
     */
    val size = hex2Bytes(toFetch(0)).length
    val header = (size + ":" + size*toFetch.size + "\n").getBytes()
    println(prefix_list.length)
    val body = header ++ prefix_list
    logger.trace("Full hash request body:\n{}", new String(body))
    val res = httpClient.POST(url, body, Map())
    res.statusCode(false) match {
      case 200 => {
        storage.clearFullhashErrors(toFetch)
        parseFullHashes(res.asBytes())
      }
      case 204 => logger.debug("No content returned for hash request"); res.consume; Nil
      case other => {
        res.consume
        logger.error("Full hash request failed: {}", other)
        toFetch foreach (p => {
          // TODO: backoff mode
        	storage.fullHashError(new DateTime(), p)
        })
        Nil
      }
    }
  }

  def parseFullHashes(data: Array[Byte]): Seq[Hash] = {
    val parsed = FullHashParser.parse(data) match {
      case FullHashParser.Success(c, _) => Option(c)
      case x => logger.error("Error parsing full hash data: {}", x); return Nil
    }

    val hashes = parsed.map(env => {
      if (env.rekey) { /* ignore for now */ }
      env.mac.foreach(mac => {
        // TODO check mac 
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
  def local_lookup_suffix(suffix: String, fullHashPrefixes: Seq[String]): Seq[Chunk] = {

    // Step 1: get all add chunks for this host key
    // Do it for all lists
    var add_chunks = storage.getAddChunks(suffix)
    if (add_chunks.isEmpty) { // no match
      logger.debug("No host key");
      return add_chunks
    }

    // Step 3: filter out add_chunks not in prefix list
    add_chunks = add_chunks.filter(c => fullHashPrefixes.contains(c.prefix))

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

  /**
   * Return all possible full hashes for a URL.
   */
  def getFullHashes(url: String): Seq[String] = {
    val urls = canonical(url);
    urls map (u => bytes2Hex(sha256(u)))
  }

  /**
   * Find all canonical URLs for a URL.
   */
  def canonical(url: String): Seq[String] = {
    val urls = new ListBuffer[String]()

    val uri = new URI(URLUtils.getInstance().canonicalizeURL(url));
    val domains = canonicalDomain(uri.getHost);
    
    var path = uri.getPath
    if(uri.getQuery != null) 
      path += "?" + uri.getQuery
      
    val paths = canonicalPath(path);

    domains foreach (d => {
      paths foreach (p => {
        urls += "%s%s".format(d, p)
      })
    })

    return urls.toList;
  }

  /**
   * Find all canonical paths for a URL.
   */
  def canonicalPath(path: String): Seq[String] = {

    val paths = mutable.MutableList[String](path)

    if (path.contains("?")) {
      paths += path.replaceAll("""\?.*$""", "")
    }

    val parts = path.split("""\/""").dropRight(1)
    var previous = ""
    breakable {
      for (i <- 0 until parts.length) {
        previous += parts(i) + "/"
        paths += previous
        if (paths.length >= 6) break
      }
    }
    paths
  }

  /**
   * Return a hash prefix as a HEX string. The size of the prefix is set to 4 bytes.
   */
  def hashPrefix(s: String): String = {
    bytes2Hex(sha256(s).take(4))
  }

  /**
   * Find all canonical domains for a domain.
   */
  def canonicalDomain(domain: String): Seq[String] = {

    if (domain.matches("""\d+\.\d+\.\d+\.\d+""")) {
      // loose check for IP address, should be enough
      return Seq(domain);
    }

    var parts = domain.split("""\.""")
    parts = parts.takeRight(min(5, parts.length - 1))
    
    val domains = mutable.MutableList[String](domain)
    while (parts.length >= 2) {
      domains += parts.mkString(".")
      parts = parts.drop(1)
    }

    domains.seq
  }

  /**
   * Get host key for domain
   */
  def makeHostKey(domain: String): String = {

    if (domain.matches("""\d+\.\d+\.\d+\.\d+""")) {
      // loose check for IP address, should be enough
      return domain
    }

    val parts = domain.split("""\.""")
    val hostKey = parts.takeRight(3).mkString(".")
    logger.debug("HostKey: {} -> {}", domain, hostKey)
    hostKey + "/" // Don't forget trailing slash
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

  def processDelAd(nums: List[Int], list: String): Result = {
    logger.debug("Delete Add Chunks: {}", nums)
    storage.deleteAddChunks(nums, list)

    // Delete full hash as well
    storage.deleteFullHashes(nums, list)
    return SUCCESSFUL
  }

  def processDelSub(nums: List[Int], list: String): Result = {
    logger.debug("Delete Sub Chunks: {}", nums)
    storage.deleteSubChunks(nums, list)
    return SUCCESSFUL
  }

  def processRedirect(url: String, hmac: Option[String], listName: String, macKey: Option[MacKey]): Result = {
    logger.debug("Checking redirection http://{} ({})", url, listName)
    val res = httpClient.GET("http://" + url)

    res.statusCode(false) match {
      case 200 => {}
      case other => {
        res.consume
        logger.error("Request to {} failed: {}", url, other)
        return SERVER_ERROR
      }
    }
    
    val data = res.asBytes()

    macKey foreach { key =>
      hmac match {
        case Some(x) => {
          if (!validateMac(data, key.clientKey, x)) {
            logger.error("MAC error on redirection: MAC validation failed")
            logger.debug("Length of data: " + data.length)
            return MAC_ERROR
          }
        }
        case _ => {
          logger.error("MAC error on redirection: redirect MAC empty")
          return MAC_ERROR
        }
      }
    }

    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => logger.error("Error parsing redirect data: {}", x); return INTERNAL_ERROR
    }

    parsed.get foreach (l => {
      l match {
        case a: DataParser.AdHead => storage.addChunks_a(a.chunknum, a.host, a.prefixes, listName)
        case s: DataParser.SubHead => storage.addChunks_s(s.chunknum, s.host, s.pairs, listName)
      }
    })

    return SUCCESSFUL
  }

  def getMacKeys: Option[MacKey] = {
    val keys = storage.getMacKey()
    keys orElse ({
      val key = requestMacKeys
      key map { k =>
        storage.addMacKey(k)
      }
      key
    })
  }

  def requestMacKeys: Option[MacKey] = {
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

object SafeBrowsing2 {

  val FULL_HASH_TIME = 45 * 60 * 1000
  val INTERVAL_FULL_HASH_TIME = "INTERVAL 45 MINUTE"
}
