package net.google.safebrowsing2
import java.util.Date
import org.slf4j.LoggerFactory
import net.google.safebrowsing2.model.MacKey
import scalaj.http.Http
import scalaj.http.HttpException
import org.apache.commons.codec.binary.Base64
import scala.collection.mutable.ListBuffer
import java.net.URLEncoder
import javax.crypto
import net.google.safebrowsing2.model.ChunkType
import net.google.safebrowsing2.model.Chunk

object SafeBrowsing2 {
  val MALWARE 					= "goog-malware-shavar"
  val PHISHING 					= "googpub-phish-shavar"
  val FULL_HASH_TIME 			= 45 * 60
  val INTERVAL_FULL_HASH_TIME 	= "INTERVAL 45 MINUTE"
}

object Result extends Enumeration {
  type Result = Value
  val DATABASE_RESET 			= Value("DATABASE_RESET")
  val MAC_ERROR 				= Value("MAC_ERROR")
  val MAC_KEY_ERROR 			= Value("MAC_KEY_ERROR")
  val INTERNAL_ERROR 			= Value("INTERNAL_ERROR") // internal/parsing error
  val SERVER_ERROR 				= Value("SERVER_ERROR") // Server sent an error back
  val NO_UPDATE 				= Value("NO_UPDATE") // no update (too early)
  val NO_DATA 					= Value("NO_DATA") // no data sent
  val SUCCESSFUL				= Value("SUCCESSFUL") // data sent
}

import Result._
class SafeBrowsing2(storage: Storage) {
  
  val VERSION		= "0.1"
  val log = LoggerFactory.getLogger(classOf[SafeBrowsing2])
  var lists			= Array("googpub-phish-shavar", "goog-malware-shavar")
  var apikey		= ""
  var version		= "2.2"
  var debug			= 0
  var errors		= 0
  var last_error	= ""
  var macKey: Option[MacKey] = None 

  def update(listName: String, force: Boolean = false, mac: Boolean = false): Result = {

    val toUpdate: Array[String] = if (!listName.isEmpty()) {
      Array(listName)
    } else {
		lists.filter(list => {
		  val info = storage.lastUpdate(list)
		  val tooEarly = info.getTime() + info.getWait() > new Date().getTime() && !force
		  if (tooEarly) {
			log.debug("Too early to update {}\n", list)
		  } else {
		    log.debug("OK to update {}: {} / {}", Array(list, new Date().getTime(), info.getTime() + info.getWait()))
		  }
		  !tooEarly
		})
 	}
	
	if (toUpdate.isEmpty){
		log.debug("Too early to update any list");
		return NO_UPDATE;
	}
	
	// MAC?
	val client_key = ""
	val wrapped_key = ""
	if (mac) {
		macKey = get_mac_keys orElse {
		  return MAC_KEY_ERROR;
		}
	}
		
	var postUrl = "http://safebrowsing.clients.google.com/safebrowsing/downloads?client=api&apikey=" + apikey + "&appver="+VERSION+"&pver=" + version;
	macKey map {key => 
	  postUrl = "&wrkey=" + key
	}

	var body = ""
	lists foreach (list => {
	   // Report existng chunks
		val a_range = create_range(storage.getAddChunksNums(list))
		val s_range = create_range(storage.getSubChunksNums(list))
	
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
		if (mac)
			body += ":mac"
		body += "\n"
    })

	val response = Http.postData(postUrl, body)

	log.debug(response.toString)

	response.responseCode match {
	  case 200 => {}
	  case other => {
	    log.error("Request failed")
	    lists.foreach(list => storage.updateError(new Date(), list))
	    SERVER_ERROR
	  }
	}

	val responseData = response.asString

	val parseResult = RFDResponseParser.parse(responseData) match {
      case RFDResponseParser.Success(resp, _) => Option(resp)
      case x => log.error("Error parsing RFD response: " + x); return INTERNAL_ERROR
    }
	
	val res = parseResult.get
	res.mac match {
	  case Some(m) => m match {
	    case "rekey" => {
	      storage.delete_mac_keys()
	      return update(listName, force, mac)
	    }
	    case _ => {
	         log.debug("MAC of request: {}", m)
	         val data = responseData.replaceAll("""^m:\s*(\S+)\s*\n""", "")
	         if (! validate_data_mac(data, macKey.get.getClientKey(), m)){
	        	 	log.error("MAC error on main request")
	        	 	return MAC_ERROR
	         }
	    }
	  }
	  case _ => {/* no mac so ignore*/}
	}
	
	res.reset match {
	  case Some(x) => {
		  log.debug("Database must be reset")
		  toUpdate foreach(l => storage.reset(l))
		  return DATABASE_RESET
	  }
	  case _ => {}
	}
	
	res.list foreach(list => {
	  list foreach(chunklist => {
	    chunklist.data foreach(d => {
	      d match {
	        case RFDResponseParser.Redirect(url, mac) => processRedirect(url, mac, chunklist.name)
	        case RFDResponseParser.AdDel(adlist) => processDelAd(adlist, chunklist.name)
	        case RFDResponseParser.SubDel(sublist) => processDelSub(sublist, chunklist.name)
	      }
	    })
	  })
	})
	
	return SUCCESSFUL
//	foreeach {
//
//		my $result = $self->parse_data(data => $data, list => $list);
//		if ($result != SUCCESSFUL) {
//			foreach my $list (@lists) {
//				$self->update_error('time' => $last_update, list => $list);
//			}
//
//			return $result;
//		}
//	}
//
//	foreach my $list (@lists) {
//		$self->debug("List update: $last_update $wait $list\n");
//		$self->{storage}->updated('time' => $last_update, 'wait' => $wait, list => $list);
//	}
//
//	return $result; # ok
}
  
  def processDelAd(nums: List[Int], list: String) = {
	  log.debug("Delete Add Chunks: {}", nums)
	    storage.deleteAddChunks(nums, list)
	    
	    // Delete full hash as well
	    storage.deleteFullHashes(nums, list)
  }
  
  def processDelSub(nums: List[Int], list: String) = {
    log.debug("Delete Sub Chunks: {}", nums)
	 storage.deleteSubChunks(nums, list)
  }
  
  def processRedirect(url: String, hmac: String, list: String) {
	  log.debug("Checking redirection http://{} ({})", url, list)
	  val res = Http("http://" + url)
	  res.responseCode match {
	    case 200 => {}
	    case _ => {
	      log.error("Request to {} failed", url)
	      lists foreach (list => {
	        storage.updateError(new Date(), list)
	      })
	      return SERVER_ERROR
	    }
	  }
	  
	  val data = res.asString
	  if (log.isDebugEnabled())
		  log.debug(data.substring(0, 250))
	  
	  macKey map { key =>
    	  if (!validate_data_mac(data, key.getClientKey(), hmac)){
    	    log.error("MAC error on redirection")
    	    log.debug("Length of data: " + data.length())
    	    return MAC_ERROR
    	  }
	  }
	  
	 val parsed = DataParser.parse(data) match {
      case DataParser.Success(c, _) => Option(c)
      case x => println(x); return INTERNAL_ERROR //TODO record error
    }
	 
	 parsed.get foreach (l => {
	   l match {
	     case a: DataParser.AdHead => storage.addChunks_a(a.chunknum, a.host, a.prefix, list)
	     case s: DataParser.SubHead => storage.addChunks_s(s.chunknum, s.host, s.pairs, list)
	   }
	 })
  }
  
  def get_mac_keys: Option[MacKey] = {

	val keys = storage.getMacKey()
	keys orElse({
	  val key = request_mac_keys
	  key map {k =>
	    storage.addMacKey(k)
	  }
	  key
	})
  }
  
  def request_mac_keys: Option[MacKey] = {
	val url = "http://sb-ssl.google.com/safebrowsing/newkey"
	val result = Http("http://foo.com/search")
				.param("client","api")
				.param("apikey", apikey)
				.param("appver", VERSION)
				.param("pver", version)
	result.responseCode match {
	  case 200 => processResponse(result.asString)
	  case other => log.error("Key request failed: {}", other); return None
	}
  }
  
  def processResponse(res: String): Option[MacKey] = {
    val Client = "^clientkey:(\\d+):(.*)$".r
	val Wrapped = "^wrappedkey:(\\d+):(.*)$".r
	val key = new MacKey
	res.split("\n").foreach(line => {
	  line match {
	    case Client(len, ckey) => {
	     assert(ckey.length() == len.toInt, "Client key is not expected length")
	     key.setClientKey(new String(Base64.decodeBase64(ckey))) 
	    }
	    case Wrapped(len, wkey) => {
	      assert(wkey.length() == len.toInt, "Wrapped key is not expected length")
	      key.setWrappedKey(wkey)
	    }
	  }
	})
	Some(key)
  }
  
   def create_range(numbers: Seq[Int]): String = {
    if (numbers.isEmpty) {
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
   
   def expand_range(range: String): List[Int] = {
	val elements = range.split(",")
			
	val list = new ListBuffer[Int]()
	val Single = """^\d+$""".r
	val Range = """^(\d+)-(\d+)$""".r
	elements foreach (e => {
	  e match {
	  case Single => list + e
	  case Range(s, e) => {
	    val start = s.toInt
	    val end = e.toInt
	    for (i <- start until end) 
	      list + i
	  	}
	  }
	})
	list.toList
  }
   
   def validate_data_mac(data: String, key: String, digest: String): Boolean = {
      val SHA1 = "HmacSHA1";
    val keySpec = new crypto.spec.SecretKeySpec(key.getBytes(), SHA1)
    val sig = {
      val mac = crypto.Mac.getInstance(SHA1)
      mac.init(keySpec)
      Base64.encodeBase64URLSafeString(mac.doFinal(data.getBytes()))
    }
	//$hash .= '=';
    log.debug("{} / {}", sig, digest)
    sig == digest
  }
}

