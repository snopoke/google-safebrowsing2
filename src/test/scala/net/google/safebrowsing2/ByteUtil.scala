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

package net.google.safebrowsing2

import util.Helpers._

trait ByteUtil {
  
  def bytes(start: Int, end: Int) = { ((start until end toList).toArray).map(_.toByte) }
  def byteString(len: Int) = { new String(bytes(0, len)) }
  def hexString(len: Int): String = { hexString(0, len) }
  def hexString(start: Int, end: Int): String = { bytes2Hex(bytes(start, end)) }

}