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
import net.google.safebrowsing2.db.MySQL
import net.google.safebrowsing2.db.Storage
import util.LiteDataSource
import db.DBI
import java.sql.Connection
import javax.sql.DataSource
import net.google.safebrowsing2.db.MSSQL

/**
 * Provides helper methods to make creating [[net.google.safebrowsing2.db.Storage]] classes easier from Java.
 */
object JavaHelper {

  def buildStorageMySQL(url: String, username: String, password: String, tablePrefix: String): Storage = {
    new MySQL(LiteDataSource.driverManager(url, username, password), tablePrefix)
  }
  
  def buildStorageMySQL(connection: Connection, tablePrefix: String): Storage = {
    new MySQL(LiteDataSource.singleConnection(connection), tablePrefix)
  }
  
  def buildStorageMySQL(dataSource: DataSource, tablePrefix: String): Storage = {
    new MySQL(dataSource, tablePrefix)
  }
  
  def buildStorageMSSQL(url: String, username: String, password: String, tablePrefix: String): Storage = {
    new MSSQL(LiteDataSource.driverManager(url, username, password), tablePrefix)
  }
  
  def buildStorageMSSQL(connection: Connection, tablePrefix: String): Storage = {
    new MSSQL(LiteDataSource.singleConnection(connection), tablePrefix)
  }
  
  def buildStorageMSSQL(dataSource: DataSource, tablePrefix: String): Storage = {
    new MSSQL(dataSource, tablePrefix)
  }
  
  def buildStorageGeneric(url: String, username: String, password: String, tablePrefix: String): Storage = {
    new DBI(LiteDataSource.driverManager(url, username, password), tablePrefix)
  }
  
  def buildStorageGeneric(connection: Connection, tablePrefix: String): Storage = {
    new DBI(LiteDataSource.singleConnection(connection), tablePrefix)
  }
  
  def buildStorageGeneric(dataSource: DataSource, tablePrefix: String): Storage = {
    new DBI(dataSource, tablePrefix)
  }
}