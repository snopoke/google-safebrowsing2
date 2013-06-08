resolvers += Resolver.mavenLocal

organization := "com.github.snopoke"

name := "safebrowsing2"

version := "0.1.0"

scalaVersion := "2.9.1"

libraryDependencies ++= Seq(
  "com.google.guava" % "guava" % "12.0.1",
  "org.slf4j" % "slf4j-api" % "1.6.4",
  "org.slf4j" % "slf4j-log4j12" % "1.6.4" % "provided",
  "log4j" % "log4j" % "1.2.16" % "provided",
  "joda-time" % "joda-time" % "1.6.2",
  //"com.github.tototoshi" %% "scala-http-client" % "1.0",
  "junit" % "junit" % "4.10" % "test",
  "org.mockito" % "mockito-core" % "1.9.0" % "test",
  "org.scalatest" %% "scalatest" % "1.7.1" % "test",
  "com.novocode" % "junit-interface" % "0.8" % "test",
  "org.hsqldb" % "hsqldb" % "2.2.8" % "test",
  "mysql" % "mysql-connector-java" % "5.1.20" % "test"
)

testOptions += Tests.Argument(TestFrameworks.JUnit, "-q", "-v")

resolvers <<= (resolvers) { r =>
  (Option(System.getenv("SBT_PROXY_REPO")) map { url =>
    Seq("proxy-repo" at url, Resolver.defaultLocal, Resolver.mavenLocal)
  } getOrElse {
    r ++ Seq(
      "scala-tools" at "http://scala-tools.org/repo-releases/",
      "maven" at "http://repo1.maven.org/maven2/"
    ) ++ Seq(Resolver.defaultLocal, Resolver.mavenLocal)
  })
}