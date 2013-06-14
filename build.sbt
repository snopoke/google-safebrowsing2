organization := "com.github.snopoke"

name := "safebrowsing2"

version := "0.2.4"

scalaVersion := "2.9.1"

libraryDependencies ++= Seq(
  //"com.github.tototoshi" %% "scala-http-client" % "1.0",
  "net.liftweb" %% "lift-json" % "2.4",
  "net.liftweb" %% "lift-webkit" % "2.4",
  "org.apache.httpcomponents" % "httpclient" % "4.2.5",
  "org.apache.httpcomponents" % "httpcore" % "4.2.4",
  "org.apache.commons" % "commons-lang3" % "3.1",
  // Libs above are for scala-http-client
  "com.google.guava" % "guava" % "12.0.1",
  "org.slf4j" % "slf4j-api" % "1.6.6",
  "org.slf4j" % "slf4j-log4j12" % "1.6.6",
  "log4j" % "log4j" % "1.2.17",
  "joda-time" % "joda-time" % "1.6.2",
  "junit" % "junit" % "4.11" % "test",
  "org.mockito" % "mockito-core" % "1.9.5" % "test",
  "org.scalatest" %% "scalatest" % "1.9.1" % "test",
  "com.novocode" % "junit-interface" % "0.9" % "test",
  "org.hsqldb" % "hsqldb" % "2.2.9" % "test",
  "mysql" % "mysql-connector-java" % "5.1.25" % "test"
)

testOptions += Tests.Argument(TestFrameworks.JUnit, "-q", "-v")

resolvers ++= Seq(
  "Maven Central" at "http://repo1.maven.org/maven2"
)
