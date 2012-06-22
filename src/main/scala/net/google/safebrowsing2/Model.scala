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
import java.util.Date
import org.joda.time.ReadableInstant
import org.joda.time.Period
import org.joda.time.DateTime

case class Hash(chunknum: Int, hash: String, list: String)
case class Chunk(chunknum: Int, prefix: String, hostkey: String, list: String, addChunknum: Int)
case class MacKey(clientKey: String, wrappedKey: String)
case class Status(val updateTime: DateTime, val waitPeriod: Period, val errors: Int) {
  lazy val waitUntil = updateTime.plus(waitPeriod)
}