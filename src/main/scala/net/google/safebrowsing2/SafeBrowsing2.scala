package net.google.safebrowsing2
import java.util.Date
import org.slf4j.LoggerFactory
import net.google.safebrowsing2.model.MacKey
import org.apache.commons.codec.binary.Base64
import scala.collection.mutable.ListBuffer
import java.net.URLEncoder
import javax.crypto
import net.google.safebrowsing2.model.Chunk
import com.github.tototoshi.http.Client
import scala.util.control.Breaks._
import com.twitter.conversions.time
import java.net.URL
import scala.collection.mutable
import net.google.safebrowsing2.Helpers._
import java.net.URI
import model.Status

object SafeBrowsing2 {
  val MALWARE = "goog-malware-shavar"
  val PHISHING = "googpub-phish-shavar"
  val FULL_HASH_TIME = 45 * 60 * 1000
  val INTERVAL_FULL_HASH_TIME = "INTERVAL 45 MINUTE"
}

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

import Result._

class SafeBrowsing2(storage: Storage) {

  val FULL_HASH_TIME = 45 * 60 * 1000
  val appver = "0.1"
  val log = LoggerFactory.getLogger(classOf[SafeBrowsing2])
  var lists = Array("googpub-phish-shavar", "goog-malware-shavar")
  var apikey = ""
  var pver = "2.2"
  var debug = 0
  var errors = 0
  var last_error = ""
  var macKey: Option[MacKey] = None
  var httpClient = new Client

  def update(listName: String, force: Boolean = false, withMac: Boolean = false): Result = {

    val candidates: Array[String] = if (!listName.isEmpty()) {
      Array(listName)
    } else {
      lists
    }

    val toUpdate = candidates.filter(listName => {
      val info = storage.lastUpdate(listName)
      val tooEarly = info.waitDate.compareTo(new Date()) > 1 && !force
      if (tooEarly) {
        log.debug("Too early to update {}\n", listName)
      } else {
        log.debug("OK to update {}: {} / {}", Array(listName, new Date(), info.waitDate))
      }
      !tooEarly
    })

    if (toUpdate.isEmpty) {
      log.debug("Too early to update any list");
      return NO_UPDATE;
    }

    val client_key = ""
    val wrapped_key = ""
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
    log.debug(responseData)
    response.statusCode() match {
      case 200 => {}
      case other => {
        log.error("Request failed")
        toUpdate.foreach(list => storage.updateError(new Date(), list))
        return SERVER_ERROR
      }
    }

    val parseResult = RFDResponseParser.parse(responseData) match {
      case RFDResponseParser.Success(resp, _) => Option(resp)
      case x => log.error("Error parsing RFD response: " + x); return INTERNAL_ERROR
    }

    val resp = parseResult.get
    resp.mac foreach (m =>
      m match {
        case "rekey" => {
          log.debug("Re-key requested")
          storage.delete_mac_keys()
          return update(listName, force, withMac)
        }
        case _ => {
          log.debug("MAC of request: {}", m)
          val data = responseData.replaceAll("""^m:\s*(\S+)\s*\n""", "")
          if (!validate_data_mac(data.getBytes(), macKey.get.getClientKey(), m)) {
            log.error("MAC error on main request")
            return MAC_ERROR
          }
        }
      })

    resp.reset foreach {
      log.debug("Database must be reset")
      toUpdate foreach (l => storage.reset(l))
      return DATABASE_RESET
    }

    var result = SUCCESSFUL
    breakable {
      resp.list foreach (list => {
        list foreach (chunklist => {
          val a = chunklist.data map (d => {
            d match {
              case RFDResponseParser.Redirect(url, mac) => {
                result = processRedirect(url, mac, chunklist.name)
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
          log.debug("List update: [list={}] [wait={}]", list, resp.next)
          storage.updated(new Date(), resp.next, list)
        }
        case MAC_ERROR => {}
        case other => {
          log.error("Error updating list: " + list + ", error: " + other)
          storage.updateError(new Date(), list)
        }
      }
    })
    if (result == SUCCESSFUL) {
      toUpdate foreach (list => {

      })
    } else {

    }

    return SUCCESSFUL
  }

  /**
   * Lookup a URL against the Google Safe Browsing database.
   * @param url
   * @param listName Optional. Lookup against a specific list. Use the list(s) from new() by default.
   * @returns Returns the name of the list if there is any match, returns an empty string otherwise.
   */
  def lookup(url: String, listName: String = "") = {
    val candidates: Array[String] = if (!listName.isEmpty()) {
      Array(listName)
    } else {
      lists
    }

    // TODO: create our own URI management for canonicalization
    // fix for http:///foo.com (3 ///)
    var cleanurl = url.replaceAll("""(https?:\/\/)\/+""", "$1")
    val uri = new URL(cleanurl)
    val domain = uri.getHost()
    val hosts = canonicalDomainSuffixes(domain) // only top-2 in this case

    hosts foreach (host => {
      log.debug("Domain for key: {} => {}", domain, host)
      val suffix = prefix(host + "/") // Don't forget trailing hash
      log.debug("Host key: {}", suffix)

    })
    //	foreach my $host (@hosts) {
    //		$self->debug("Domain for key: $domain => $host\n");
    //		my $suffix = $self->prefix("$host/"); # Don't forget trailing hash
    //		$self->debug("Host key: " . $self->hex_to_ascii($suffix) . "\n");
    //
    //		my $match = $self->lookup_suffix(lists => [@lists], url => $url, suffix => $suffix);
    //		return $match if ($match ne '');
    //	}
    //
    //	return '';
  }

  def lookup_suffix(lists: Seq[String], url: String, suffix: String): Option[String] = {

    // Calculate prefixes
    val full_hashes = getFullHashes(url) // Get the prefixes from the first 4 bytes
    val full_hashes_prefix = full_hashes map (h => bytes2Hex(h.take(4)))
    // Local lookup

    val add_chunks = local_lookup_suffix(url, suffix, full_hashes_prefix)
    if (add_chunks.isEmpty) {
      log.debug("No hit in local lookup")
      return None
    }

    // Check against full hashes
    add_chunks foreach (achunk => {
      if (lists.contains(achunk.getList())) {
        val hashes = storage.getFullHashes(achunk.getChunknum(), new Date().getTime() - FULL_HASH_TIME, achunk.getList())
        log.debug("Full hashes already stored for chunk " + achunk.getChunknum() + ": " + hashes.length)

        full_hashes foreach (h => {
          if (hashes.find(_.equals(h)).isDefined) {
            log.debug("Full has was found in storage")
            return Some(achunk.getList())
          }
        })
      }
    })

    //ask for new hashes
    //TODO: make sure we don't keep asking for the same over and over
   // val hashes = request_full_hash()
    None

    //
    //	# 
    //	my @hashes = $self->request_full_hash(prefixes => [ map($_->{prefix} || $_->{hostkey}, @add_chunks) ]);
    //	$self->{storage}->add_full_hashes(full_hashes => [@hashes], timestamp => time());
    //
    //	foreach my $full_hash (@full_hashes) {
    //		my $hash = first { $_->{hash} eq  $full_hash} @hashes;
    //		next if (! defined $hash);
    //
    //		my $list = first { $hash->{list} eq $_ } @$lists;
    //
    //		if (defined $hash && defined $list) {
    //# 			$self->debug($self->hex_to_ascii($hash->{hash}) . " eq " . $self->hex_to_ascii($full_hash) . "\n\n");
    //
    //			$self->debug("Match\n");
    //
    //			return $hash->{list};
    //		}
    //# 		elsif (defined $hash) {
    //# 			$self->debug("hash: " . $self->hex_to_ascii($hash->{hash}) . "\n");
    //# 			$self->debug("list: " . $hash->{list} . "\n");
    //# 		}
    //	}
    //	
    //	$self->debug("No match\n");
    //	return '';
  }
  
/**
 *  Request full full hashes for specific prefixes from Google.
 */
def request_full_hash(prefixes: Seq[String]) = {
  
  def delay(status: Status, wait: Int): Boolean = {
    new Date().getTime() - status.updateTime > wait
  }
	prefixes filter(prefix => {
	  val errors = storage.getFullHashError(prefix)
	  errors match {
	    case None => true
	    case Some(status) if (status.errors <= 2) => true
	    case Some(status) if (status.errors == 3) => delay(status, 30*60) // 30 mins
	    case Some(status) if (status.errors == 4) => delay(status, 60*60) // 1 hour
	    case Some(status) => delay(status, 2*60*60) // 2 hours
	  }
	})

	val url = "http://safebrowsing.clients.google.com/safebrowsing/gethash?client=api&apikey=" + apikey + "&appver=" + appver + "&pver=" + pver;

	val prefix_list = prefixes.map(p => hex2Bytes(p)).reduce(_ ++ _)
	val header = (prefixes(0).length + ":" + prefixes.size + "\n").getBytes()
	val body = header ++ prefix_list
//	val res = httpClient.POST(url, body, Map())
//
//	if (! $res->is_success) {
//		$self->error("Full hash request failed\n");
//		$self->debug($res->as_string . "\n");
//
//		foreach my $prefix (@$prefixes) {
//			my $errors = $self->{storage}->get_full_hash_error(prefix => $prefix);
//			if (defined $errors && (
//				$errors->{errors} >=2 			# backoff mode
//				|| $errors->{errors} == 1 && (time() - $errors->{timestamp}) > 5 * 60)) { # 5 minutes
//					$self->{storage}->full_hash_error(prefix => $prefix, timestamp => time()); # more complicate than this, need to check time between 2 errors
//			}
//		}
//
//		return ();
//	}
//	else {
//		$self->debug("Full hash request OK\n");
//
//		foreach my $prefix (@$prefixes) {
//			$self->{storage}->full_hash_ok(prefix => $prefix, timestamp => time());
//		}
//	}
//
//	$self->debug($res->request->as_string . "\n");
//	$self->debug($res->as_string . "\n");
//# 	$self->debug(substr($res->content, 0, 250), "\n\n");
//
//	return $self->parse_full_hashes($res->content);
}

  /**
   * Lookup a host prefix in the local database only.
   */
  def local_lookup_suffix(url: String, suffix: String,
    fullHashPrefixes: Seq[String] = Array[String]()): Seq[Chunk] = {

    // Step 1: get all add chunks for this host key
    // Do it for all lists
    val add_chunks = storage.getAddChunks(suffix)
    if (add_chunks.isEmpty) { // no match
      log.debug("No host key");
      return add_chunks
    }

    // Step 2: calculate prefixes
    // Get the prefixes from the first 4 bytes
    val fullHashPrefixList = if (fullHashPrefixes.isEmpty) {
      getFullHashes(url) map (h => bytes2Hex(h.take(4)))
    } else {
      fullHashPrefixes
    }

    // Step 3: filter out add_chunks not in prefix list
    add_chunks.filter(c => fullHashPrefixList.contains(c.getPrefix()))

    if (add_chunks.isEmpty) {
      log.debug("No prefix match for any host key");
      return add_chunks
    }

    // Step 4: get all sub chunks for this host key
    val sub_chunks = storage.getSubChunks(suffix)

    // remove all add_chunks that occur in the list of sub_chunks
    add_chunks.filter(c => {
      sub_chunks.find(sc =>
        c.getChunknum() == sc.getAddChunknum() &&
          c.getList().equals(sc.getList()) &&
          c.getPrefix().equals(sc.getPrefix())).isEmpty
    })

    if (add_chunks.isEmpty) {
      log.debug("All add_chunks have been removed by sub_chunks");
    }

    add_chunks
  }

  /**
   * Return all possible full hashes for a URL.
   */
  def getFullHashes(url: String): Seq[Array[Byte]] = {
    val urls = canonical(url);
    urls map (sha256(_))
  }

  /**
   * Find all canonical URLs for a URL.
   */
  def canonical(url: String): Seq[String] = {
    val urls = new ListBuffer()

    val uri = canonicalUri(url);
    val domains = canonicalDomain(uri.getHost);
    val paths = canonicalPath(uri.getPath);

    domains foreach (d => {
      paths foreach (p => {
        urls ++ "%s%s".format(d, p)
      })
    })

    return urls.toList;
  }

  /**
   * Find all canonical paths for a URL.
   */
  def canonicalPath(path: String): Seq[String] = {

    val paths = Array(path)

    if (path.contains("?")) {
      paths ++ path.replaceAll("""\?.*$""", "")
    }

    val parts = path.split("""\/""")
    var previous = ""
    breakable {
      for (i <- 0 to parts.length) {
        previous += parts(i) + "/"
        paths ++ previous
        if (paths.length >= 6) break
      }
    }
    paths
  }

  /**
   * Create a canonical URI.
   *
   * NOTE: URI cannot handle all the test cases provided by Google. This method is a hack to pass most of the test. A few tests are still failing. The proper way to handle URL canonicalization according to Google would be to create a new module to handle URLs. However, I believe most real-life cases are handled correctly by this function.
   */
  def canonicalUri(url: String): URI = {
    var cleanurl = url.trim;

    var uri = new URI(cleanurl).normalize()

    if (uri.getScheme() == null || uri.getScheme().isEmpty) {
      uri = new URI("http://" + cleanurl).normalize()
    }

    // TODO: improve canonicalization

    uri
  }

  /**
   * Return a hash prefix as a HEX string. The size of the prefix is set to 4 bytes.
   */
  def prefix(s: String): String = {
    bytes2Hex(sha256(s).take(4))
  }

  /**
   * Find all canonical domains a domain.
   */
  def canonicalDomain(domain: String): Seq[String] = {

    if (domain.matches("""\d+\.\d+\.\d+\.\d+""")) {
      // loose check for IP address, should be enough
      return Array(domain);
    }

    val domains = mutable.MutableList[String]()
    var parts = domain.split("""\.""")
    parts = parts.takeRight(6)
    while (parts.length > 2) {
      domains += parts.mkString(".")
      parts = parts.drop(1)
    }

    domains
  }

  /**
   * Find all suffixes for a domain.
   */
  def canonicalDomainSuffixes(domain: String): Seq[String] = {

    if (domain.matches("""\d+\.\d+\.\d+\.\d+""")) {
      // loose check for IP address, should be enough
      return Array(domain);
    }

    val domains = mutable.MutableList[String]()
    var parts = domain.split("""\.""")
    if (parts.length >= 3) {
      parts = parts.takeRight(3)
      domains += parts.mkString(".")
      parts = parts.drop(1)
    }

    domains += parts.mkString(".")
    domains
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
    log.debug("Delete Add Chunks: {}", nums)
    storage.deleteAddChunks(nums, list)

    // Delete full hash as well
    storage.deleteFullHashes(nums, list)
    return SUCCESSFUL
  }

  def processDelSub(nums: List[Int], list: String): Result = {
    log.debug("Delete Sub Chunks: {}", nums)
    storage.deleteSubChunks(nums, list)
    return SUCCESSFUL
  }

  def processRedirect(url: String, hmac: Option[String], listName: String): Result = {
    log.debug("Checking redirection http://{} ({})", url, listName)
    val res = httpClient.GET("http://" + url)

    val data = res.asBytes()
    res.statusCode() match {
      case 200 => {}
      case other => {
        log.error("Request to {} failed: {}", url, other)
        return SERVER_ERROR
      }
    }

    macKey foreach { key =>
      hmac match {
        case Some(x) => {
          if (!validate_data_mac(data, key.getClientKey(), x)) {
            log.error("MAC error on redirection: MAC validation failed")
            log.debug("Length of data: " + data.length)
            return MAC_ERROR
          }
        }
        case _ => {
          log.error("MAC error on redirection: redirect MAC empty")
          return MAC_ERROR
        }
      }
    }

    val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => log.error("Error parsing redirect data: {}", x); return INTERNAL_ERROR
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

    val body = resp.asString()
    resp.statusCode() match {
      case 200 => processMacResponse(body)
      case other => println("Key request failed: {}" + other); None
    }
  }

  def processMacResponse(res: String): Option[MacKey] = {
    val Client = "^clientkey:(\\d+):(.*)$".r
    val Wrapped = "^wrappedkey:(\\d+):(.*)$".r
    val key = new MacKey
    res.split("\n").foreach(line => {
      line match {
        case Client(len, ckey) => {
          assert(ckey.length() == len.toInt, "Client key is not expected length")
          key.setClientKey(ckey)
        }
        case Wrapped(len, wkey) => {
          assert(wkey.length() == len.toInt, "Wrapped key is not expected length")
          key.setWrappedKey(wkey)
        }
      }
    })
    Some(key)
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

  def validate_data_mac(data: Array[Byte], key: String, digest: String): Boolean = {
    val SHA1 = "HmacSHA1";
    val keySpec = new crypto.spec.SecretKeySpec(key.getBytes(), SHA1)
    val sig = {
      val mac = crypto.Mac.getInstance(SHA1)
      mac.init(keySpec)
      Base64.encodeBase64URLSafeString(mac.doFinal(data))
    }
    //$hash .= '=';
    log.debug("{} / {}", sig, digest)
    sig == digest
  }
}