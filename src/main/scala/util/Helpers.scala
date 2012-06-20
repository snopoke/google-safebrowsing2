package util
import java.security.MessageDigest
import javax.crypto
import scala.Array.canBuildFrom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64

object Helpers {

  def sha256(s: String): Array[Byte] = {
    val sha = MessageDigest.getInstance("SHA-256")
    sha.digest(s.getBytes)
  }

  def sha256Hex(s: String): String = {
    bytes2Hex(sha256(s))
  }

  def bytes2Hex(buf: Seq[Byte]): String = {
    buf.map("%02X" format _).mkString
  }

  /** Convert from hex string into bytes */
  def hex2Bytes(hex: String): Array[Byte] = {
    val chunks = for { 
      i <- (0 to hex.length - 1 by 2); 
      if i > 0 || !hex.startsWith("0x") // discard initial 0x if exists
    } yield hex.substring(i, i + 2)
    
    chunks.map(Integer.parseInt(_, 16).toByte).toArray
  }
  
  def getMac(data: Array[Byte], key: String) = {
    val SHA1 = "HmacSHA1";
    val keySpec = new SecretKeySpec(key.getBytes(), SHA1)
    val mac = Mac.getInstance(SHA1)
    mac.init(keySpec)
    Base64.encodeBase64URLSafeString(mac.doFinal(data))
  }
}