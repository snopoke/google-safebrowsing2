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

import org.joda.time.DateTime

import net.google.safebrowsing2.Chunk
import net.google.safebrowsing2.Hash
import net.google.safebrowsing2.MacKey
import net.google.safebrowsing2.Status

/**
 * This trait represents the interface between the API and the database.
 */
abstract trait Storage {

  /**
   * Add 'sub chunks' to the database
   *
   * @param chunknum the chunks identifying number
   * @param hostkey the chunks host key
   * @param chunks tuple (add chunk number, prefix)
   * @param list the blacklist to add the chunk to
   */
  def addChunks_s(chunknum: Int, hostkey: String, chunks: Seq[(Int, String)], list: String)

  /**
   * Add 'add chunks' to the database
   *
   * @param chunknum the chunks identifying number
   * @param hostkey the chunks host key
   * @param prefixes list of prefixes to add
   * @param list the blacklist to add the chunk to
   */
  def addChunks_a(chunknum: Int, hostkey: String, prefixes: Seq[String], list: String)

  /**
   * Get all add chunks for the given host key that have not been
   * removed by sub chunks
   * @param hostkey
   * @return list of chunks
   */
  def getChunksForHostKey(hostkey: String): Seq[Chunk]

  /**
   * Get all add chunk identifying numbers for the given list
   * @param list
   * @return list of chunk id numbers
   */
  def getAddChunksNums(list: String): Seq[Int]

  /**
   * Get all sub chunk identifying numbers for the given list
   * @param list
   * @return list of chunk id numbers
   */
  def getSubChunksNums(list: String): Seq[Int]

  /**
   * Delete add chunks from a list
   * @param chunknums list of chunk identity numbers
   * @param list the list to remove them from
   */
  def deleteAddChunks(chunknums: Seq[Int], list: String)

  /**
   * Delete sub chunks from a list
   * @param chunknums list of chunk identity numbers
   * @param list the list to remove them from
   */
  def deleteSubChunks(chunknums: Seq[Int], list: String)

  /**
   * Get all full hashes for the given chunk that are newer than
   * the given date
   *
   * @param chunknum the chunk id to fetch hashes for
   * @param newerThan only fetch chunks newer thank this
   * @param list fetch chunks from this list
   * @return list of String hashes
   */
  def getFullHashes(chunknum: Int, newerThan: DateTime, list: String): Seq[String]

  /**
   * Record a successful update
   * @param thisAttempt the date of this update
   * @param nextAttempt the date that the next update should happen at
   * @param list the list that was updated
   */
  def updateSuccess(thisAttempt: DateTime, nextAttempt: DateTime, list: String)

  /**
   * Record a failed update. This method also calculated the next attempt time
   * using a back off algorithm
   *
   * @param thisAttempt the date of this update
   * @param list the list that was updated
   */
  def updateError(thisAttempt: DateTime, list: String)

  /**
   * Get the status of a list
   * @param list the list
   * @return A Status option or None
   */
  def getListStatus(list: String): Option[Status]

  /**
   * Add full hashes to the database
   * @param fetchTime the timestamp that these hashes were fetched
   * @param fullHashes the list of hashes
   *
   */
  def addFullHashes(fetchTime: DateTime, fullHashes: Seq[Hash])

  /**
   * Delete full hashes from the database
   * @param chunknums a list of chunk id's to delete hashes for
   * @param list the blacklist to delete from
   */
  def deleteFullHashes(chunknums: Seq[Int], list: String)

  /**
   * Record a full hash error in the database
   * @param timestamp the timestamp of the error
   * @param prefix the prefix for which the error occurred
   */
  def fullHashError(timestamp: DateTime, prefix: String)

  /**
   * Clear full hash errors from the database for the
   * given list of chunks
   * @param chunks the list of chunks to clear errors for
   */
  def clearFullhashErrors(chunks: Seq[Chunk])

  /**
   * Get the error status for the given prefix
   * @param prefix the prefix to get the status of
   * @return A Status option or None
   */
  def getFullHashError(prefix: String): Option[Status]

  /**
   * Get the MAC key
   * @return A MacKey option or None
   */
  def getMacKey: Option[MacKey]

  /**
   * Add a MAC key to the database
   * @param key
   */
  def addMacKey(key: MacKey)

  /**
   * Delete all MAC keys from the database
   */
  def deleteMacKeys

  /**
   * Reset all data for the given list
   * @param list the list to reset
   */
  def reset(list: String)

  /**
   * Remove full hashes that are older than 45 minutes
   */
  def clearExpiredHashes
  
  def getDatabaseStats: Map[String, String]

}