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
  var mac			= 0

  def update(listName: String, force: Boolean = false, mac: Boolean = false): Result = {

	val toUpdate = lists.filter(list => {
	  val info = storage.lastUpdate(list)
	  val tooEarly = info.getTime() + info.getWait() > new Date().getTime() && !force
	  if (tooEarly) {
		log.debug("Too early to update {}\n", list)
	  } else {
	    log.debug("OK to update {}: {} / {}", Array(list, new Date().getTime(), info.getTime() + info.getWait()))
	  }
	  !tooEarly
	})
	
	if (toUpdate.isEmpty){
		log.debug("Too early to update any list");
		return NO_UPDATE;
	}
	
	// MAC?
	val client_key = ""
	val wrapped_key = ""
	var macKey: Option[MacKey] = None 
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
	val responseData = response.asString
	val lines = responseData.split("\\s")

	response.responseCode match {
	  case 200 => {}
	  case other => {
	    log.error("Request failed")
	    lists.foreach(list => storage.updateError(new Date(), list))
	    SERVER_ERROR
	  }
	}

	val last_update = new Date()
	var wait = 0;
	var list = ""
	val redirects = new ListBuffer[(String, String, String)]()
	var result = 0
	  
	val NextPattern = """^n:\s*(\d+)\s*$""".r
	val ListPattern = """^i:\s*(\S+)\s*$""".r
	val RedirectMacPattern = """^u:\s*(\S+),(\S+)\s*$""".r
	val RedirectPattern = """^u:\s*(\S+)\s*$""".r
	val DeleteAddPattern = """^ad:\s*(\S+)\s*$""".r
	val DeleteSubPattern = """^sd:\s*(\S+)\s*$""".r
	val MacPattern = """^m:\s*(\S+)\s*$""".r
	val ResKeyPattern = """^e:\s*pleaserekey\s*$""".r
	val ResetPattern = """^r:\s*pleasereset\s*$""".r
	
	lines foreach (line => {
	  line match {
	  case NextPattern(n) => log.debug("Next poll: {} seconds", n); wait = n.toInt
	  case ListPattern(l) => log.debug("List: {}", l); list = l
	  case RedirectMacPattern(url, mac) => log.debug("Redirection: {}:{}", url, mac); redirects + ((url, list, mac))
	  case RedirectPattern(url, mac) => log.debug("Redirection: {}", url, mac); redirects + ((url, list, ""))
	  case DeleteAddPattern(chunks) => {
	    log.debug("Delete Add Chunks: {}", chunks)
	    val nums = expand_range(chunks)
	    storage.deleteAddChunks(nums, list)
	    
	    // Delete full hash as well
	    storage.deleteFullHashes(nums, list)
	    result = 1
	  }
	  case DeleteSubPattern(chunks) => {
	    log.debug("Delete Sub Chunks: {}", chunks)
	    val nums = expand_range(chunks)
	    storage.deleteSubChunks(nums, list)
	    result = 1
	  }
	  case MacPattern(m) => {
	    macKey map (mac => {
	       log.debug("MAC of request: {}", m)
	    val data = responseData.replaceAll("""^m:\s*(\S+)\s*\n""", "")
	    if (! validate_data_mac(data, mac.getClientKey(), m)){
	      log.error("MAC error on main request")
	      return MAC_ERROR
	    }
	    })
	  }
	  case ResKeyPattern => {
	    log.debug("MAC key has been expired")
	    storage.delete_mac_keys()
	    return update(list, force, mac)
	  }
	  case ResetPattern => {
	    log.debug("Database must be reset")
	    storage.reset(list)
	    return DATABASE_RESET
	  }
	}
	})

	if (redirects.size > 0)
		result = 1

	redirects.toList foreach (e => {
	  val (redirection, list, hmac) = e
	  log.debug("Checking redirection http://{} ({})", redirection, list)
	  val res = Http("http://" + redirection)
	  res.responseCode match {
	    case 200 => {}
	    case _ => {
	      log.error("Request to {} failed", redirection)
	      lists foreach (list => {
	        storage.updateError(last_update, list)
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
	  
	  val result = parse_data(data, list)
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
   
   def parse_data(data: String, list: String) = {
//	val chunk_num = 0;
//    val hash_length = 0;
//	val chunk_length = 0;
//
//	while (data.length > 0) {
//	  println("Length 1: " + data.length)  // 58748
//	  val tpe = data.substring(0,2)
//			my $type = substr($data, 0, 2, ''); # s:34321:4:137
//	# 		print "Length 1.5: ", length $data, "\n"; # 58746 -2
//	
//			if ($data  =~ /^(\d+):(\d+):(\d+)\n/sgi) {
//				$chunk_num = $1;
//				$hash_length = $2;
//				$chunk_length = $3;
//	
//				# shorten data
//				substr($data, 0, length($chunk_num) + length($hash_length) + length($chunk_length) + 3, '');
//	# 			print "Remove ", length($chunk_num) + length($hash_length) + length($chunk_length) + 3, "\n";
//	# 			print "Length 2: ", length $data, "\n"; # 58741 -5
//	
//				my $encoded = substr($data, 0, $chunk_length, '');
//	# 			print "Length 3: ", length $data, "\n"; # 58604 -137
//	
//				if ($type eq 's:') {
//					my @chunks = $self->parse_s(value => $encoded, hash_length => $hash_length);
//
//					$self->{storage}->add_chunks(type => 's', chunknum => $chunk_num, chunks => [@chunks], list => $list); # Must happen all at once => not 100% sure
//				}
//				elsif ($type eq 'a:') {
//					my @chunks = $self->parse_a(value => $encoded, hash_length => $hash_length);
//					$self->{storage}->add_chunks(type => 'a', chunknum => $chunk_num, chunks => [@chunks], list => $list); # Must happen all at once => not 100% sure
//				}
//				else {
//					$self->error("Incorrect chunk type: $type, should be a: or s:\n");
//					return INTERNAL_ERROR;# failed
//				}
//	
//				$self->debug("$type$chunk_num:$hash_length:$chunk_length OK\n");
//			
//			}
//			else {
//				$self->error("could not parse header\n");
//				return INTERNAL_ERROR;# failed
//			}
//		}
//
//	return SUCCESSFUL;
}
}

