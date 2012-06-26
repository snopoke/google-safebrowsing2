/* 
 * Copyright 2012 Simon Kelly
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    val keySpec = new SecretKeySpec(Base64.decodeBase64(key), SHA1)
    val mac = Mac.getInstance(SHA1)
    mac.init(keySpec)
    Base64.encodeBase64URLSafeString(mac.doFinal(data)) + "="
  }
}