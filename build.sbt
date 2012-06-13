name := "Google Safebrowsing2"

version := "0.1"

scalaVersion := "2.9.1"

libraryDependencies ++= Seq(
  "org.slf4j" % "slf4j-api" % "1.6.4",
  "org.slf4j" % "slf4j-simple" % "1.6.4",
  "junit" % "junit" % "4.10" % "test",
  "org.specs2" %% "specs2" % "1.11" % "test",
  "org.scalatest" %% "scalatest" % "1.7.1" % "test"
)
