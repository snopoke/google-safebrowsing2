package net.google.safebrowsing2
import java.net.URL
import scala.collection.mutable
import scala.util.control.Breaks._
import com.buildabrand.gsb.util.URLUtils
import scala.math.min
import util.Logging
import util.Helpers._

/**
 * Class does the conversion url -> list of SafeBrowsing expressions.
 *
 * This class converts a given url into the list of all SafeBrowsing host-suffix,
 * path-prefix expressions for that url.  These are expressions that are on the
 * SafeBrowsing lists.
 * 
 * Loosely based on http://code.google.com/p/google-safe-browsing/source/browse/trunk/python/expression.py
 */
class ExpressionGenerator(inputUrl: String) extends Logging {

  class UrlParseException extends Exception("Failed to parse URL: " + inputUrl)

  val canonical_url = canonicalizeUrl(inputUrl)

  val url = new URL(canonical_url)
  val canonical_host = url.getHost()

  // Each element is a list of host components used to build expressions.
  val host_list = makeHostList(canonical_host)
  
  // A list of paths used to build expressions.
  val path_exprs = makePathList(url)

  lazy val hostKey = bytes2Hex(sha256(makeHostKey(canonical_host)).take(4))

  def expressions: Seq[Expression] = {
    for (
      host <- host_list;
      path <- path_exprs
    ) yield new Expression(host, path)
  }

  /**
   * Get the first three directory path components and create the 4 path
   * expressions starting at the root (/) and successively appending directory
   * path components, including the trailing slash. E.g.:
   * /a/b/c/d.html -> [/, /a/, /a/b/, /a/b/c/]
   *
   * @param url the canonicalized URL
   */
  def makePathList(url: URL): Seq[String] = {
    val paths = new mutable.ListBuffer[String]()

    val canonical_path = url.getPath()

    if (url.getQuery() != null) {
      paths += canonical_path + "?" + url.getQuery()
    }
    paths += canonical_path

    var path_parts = canonical_path.stripPrefix("/").stripSuffix("/").split("/").take(3)

    if (canonical_path.count(_ == '/') < 4) {
      //if the last component in not a directory we remove it.
      path_parts = path_parts.dropRight(1)
    }

    while (!path_parts.isEmpty) {
      paths += "/" + path_parts.mkString("/") + "/"
      path_parts = path_parts.dropRight(1)
    }

    if (!canonical_path.equals("/"))
      paths += "/"

    paths.seq
  }

  def canonicalizeUrl(url: String): String = {
    val cleanurl = URLUtils.getInstance().canonicalizeURL(url)
    if (cleanurl == null)
      throw new UrlParseException

    cleanurl
  }

  /**
   * Find all canonical domains for a domain.
   */
  def makeHostList(domain: String): Seq[String] = {

    if (domain.matches("""\d+\.\d+\.\d+\.\d+""")) {
      // loose check for IP address, should be enough
      return Seq(domain);
    }

    var parts = domain.split("""\.""")
    parts = parts.takeRight(min(5, parts.length - 1))

    val domains = mutable.MutableList[String](domain)
    while (parts.length >= 2) {
      domains += parts.mkString(".")
      parts = parts.drop(1)
    }

    domains.seq
  }

  /**
   * Take the three most significant host components if there are three or more components,
   * or two host components if a third does not exist and
   * append a trailing slash (/) to this string.
   *
   * @param host the canonicalized host
   * @return host key
   */
  def makeHostKey(host: String): String = {

    if (host.matches("""\d+\.\d+\.\d+\.\d+""")) {
      // loose check for IP address, should be enough
      return host
    }

    val parts = host.split("""\.""")
    val hostKey = parts.takeRight(3).mkString(".")
    logger.debug("HostKey: {} -> {}", host, hostKey)
    hostKey + "/" // Don't forget trailing slash
  }
}

case class Expression(host: String, path: String) {
  val value = host + path
  lazy val rawHash = sha256(value)
  lazy val hexHash = bytes2Hex(rawHash)
//  lazy val rawPrefix = rawHash.take(4)
//  lazy val hexPrefix = hexHash.take(8)
}