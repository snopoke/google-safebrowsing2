package net.google.safebrowsing2.model
import java.util.Calendar
import java.util.Date

class Status(val updateTime: Int, val waitSecs: Int, val errors: Int) {
  
  lazy val waitMs = waitSecs * 1000
  
  lazy val waitDate = new Date(updateTime + waitMs)
  
  lazy val updateDate = new Date(updateTime) 

}