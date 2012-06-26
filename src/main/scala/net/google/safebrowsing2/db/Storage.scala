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

package net.google.safebrowsing2.db

import java.util.{List => JavaList}
import net.google.safebrowsing2.MacKey
import net.google.safebrowsing2.Hash
import net.google.safebrowsing2.Chunk
import net.google.safebrowsing2.Status
import org.joda.time.DateTime
import net.google.safebrowsing2.Expression
import org.joda.time.DateTime

trait Storage {

  def addChunks_s(chunknum: Int, hostkey: String, chunks: Seq[(Int,String)], list: String)

  def addChunks_a(chunknum: Int, hostkey: String, prefixes: Seq[String], list: String)
  
  def getChunksForHostKey(hostkey: String): Seq[Chunk]

  def getAddChunksNums(list: String): Seq[Int]

  def getSubChunksNums(list: String): Seq[Int]

  def deleteAddChunks(chunknums: Seq[Int], list: String)

  def deleteSubChunks(chunknums: Seq[Int], list: String)

  def getFullHashes(chunknum: Int, timestamp: DateTime, list: String): Seq[String]

  def updateSuccess(lastAttempt: DateTime, nextAttempt: DateTime, list: String)

  def updateError(lastAttempt: DateTime, list: String)

  def getLastUpdate(list: String): Option[Status]

  def addFullHashes(timestamp: DateTime, full_hashes: Seq[Hash])

  def deleteFullHashes(chunknums: Seq[Int], list: String)

  def fullHashError(timestamp: DateTime, prefix: String)

  def clearFullhashErrors(expressions: Seq[Chunk])

  def getFullHashError(prefix: String): Option[Status]

  def getMacKey: Option[MacKey]

  def addMacKey(key: MacKey)

  def deleteMacKeys

  def reset(list: String)
  
  def clearExpiredHashes

}