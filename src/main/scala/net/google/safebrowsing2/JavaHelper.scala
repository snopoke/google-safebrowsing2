package net.google.safebrowsing2
import net.google.safebrowsing2.db.MySQL
import net.google.safebrowsing2.db.Storage
import util.LiteDataSource
import db.DBI
import java.sql.Connection
import javax.sql.DataSource

object JavaHelper {

  def buildStorageMySQL(url: String, username: String, password: String): Storage = {
    new MySQL(LiteDataSource.driverManager(url, username, password))
  }
  
  def buildStorageMySQL(connection: Connection): Storage = {
    new MySQL(LiteDataSource.singleConnection(connection))
  }
  
  def buildStorageMySQL(dataSource: DataSource): Storage = {
    new MySQL(dataSource)
  }
  
  def buildStorageGeneric(url: String, username: String, password: String): Storage = {
    new DBI(LiteDataSource.driverManager(url, username, password))
  }
  
  def buildStorageGeneric(connection: Connection): Storage = {
    new DBI(LiteDataSource.singleConnection(connection))
  }
  
  def buildStorageGeneric(dataSource: DataSource): Storage = {
    new DBI(dataSource)
  }
}