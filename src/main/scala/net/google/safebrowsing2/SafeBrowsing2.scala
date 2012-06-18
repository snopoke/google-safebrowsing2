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

object SafeBrowsing2 {
  val MALWARE = "goog-malware-shavar"
  val PHISHING = "googpub-phish-shavar"
  val FULL_HASH_TIME = 45 * 60
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

//abstract trait ChunkData
//case class AdHead(chunknum: Int, host: String, prefixes: List[String]) extends ChunkData
//case class SubHead(chunknum: Int, host: String, prefixes: List[(String, String)]) extends ChunkData

import Result._
class SafeBrowsing2(storage: Storage) {

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
      log.debug("Host key: {}", bytes2Hex(suffix))
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

  ///**
  // * Find all canonical paths for a URL.
  // */
  //def canonical_path(path: String) = {
  //
  //	my @paths = ($path); # return full path
  //	
  //	if ($path =~ /\?/) {
  //		$path =~ s/\?.*$//;
  //
  //		push(@paths, $path);
  //	}
  //
  //	my @parts = split /\//, $path;
  //	my $previous = '';
  //	while (scalar @parts > 1 && scalar @paths < 6) {
  //		my $val = shift(@parts);
  //		$previous .= "$val/";
  //
  //		push(@paths, $previous);
  //	}
  //	
  //	return @paths;
  //}

  /**
   * Return a hash prefix. The size of the prefix is set to 4 bytes.
   */
  def prefix(s: String): Array[Byte] = {
    sha256(s).take(4)
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

//    val parsed = parseChunkData(data)

//    parsed foreach (l => {
//      l match { //FIXME
//        case a: AdHead => storage.addChunks_a(a.chunknum, "", List(), listName)
//        case s: SubHead => storage.addChunks_s(s.chunknum, "", List(), listName)
//      }
//    })

    return SUCCESSFUL
  }

//  def parseChunkData(data: Array[Byte]): List[ChunkData] = {
//    val chunkData = new ListBuffer[ChunkData]()
//    
//    var next = Array[Byte]()
//    val headlen = data.prefixLength(_ != '\n') + 1
//    val (head, tail) = data.splitAt(headlen)
//    val header = new String(head)
//    val ctype = header.take(1)
//    val HeadPattern = """^.:(\d+):(\d+):(\d+)\n""".r
//    header match {
//      case HeadPattern(cnum, hlen, dlen) => {
//        val chunkNum = cnum.toInt
//        val hashlen = hlen.toInt
//        val cdata = tail.take(dlen.toInt)
//        next = data.drop(dlen.toInt)
//        val host = bytes2Hex(cdata.take(4))
//        val count = cdata(5).toInt
//        ctype match {
//          case "a" => {
//            val prefixes = if (count == 0) Nil else {
//              (0 to count - 1 toList) map { i =>
//                val start = 5 + (hashlen * i)
//                bytes2Hex(cdata.slice(start, start + hashlen))
//              }
//            }
//            chunkData += AdHead(chunkNum, host, prefixes)
//          }
//          case "s" => {
//            val pairs = if (count == 0) List((bytes2Hex(cdata.slice(5, 9)), "")) else {
//              (0 to count - 1 toList) map { i =>
//                val start = 5 + ((hashlen + 4) * i)
//                val prefixStart = start + 4
//                val addchunknum = bytes2Hex(cdata.slice(start, prefixStart))
//                val prefix = bytes2Hex(cdata.slice(prefixStart, prefixStart + hashlen))
//                (addchunknum, prefix)
//              }
//            }
//           chunkData += SubHead(chunkNum, host, pairs)
//          }
//        }
//      }
//      case _ => println("error"); None
//    }
//    
//    if (next.length > 0) {
//    	chunkData.toList ++ parseChunkData(next) 
//    } else
//      chunkData.toList
//  }

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