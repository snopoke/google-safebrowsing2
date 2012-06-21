package net.google.safebrowsing2
import java.net.URL
import scala.collection.mutable.ListBuffer
import scala.util.control.Breaks._

/**
 * Class does the conversion url -> list of SafeBrowsing expressions.
 * 
 * This class converts a given url into the list of all SafeBrowsing host-suffix,
  path-prefix expressions for that url.  These are expressions that are on the
  SafeBrowsing lists.
 */
class ExpressionGenerator(inputUrl: String) {
  
  val HEX = """^0x([a-fA-F0-9]+)$""".r
  val OCT = """^0([0-7]+)$""".r
  val DEC = """^(\d+)$""".r
  val IP_WITH_TRAILING_SPACE = """^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) """.r
  val POSSIBLE_IP = """^(?i)((?:0x[0-9a-f]+|[0-9\\.])+)$""".r
  val FIND_BAD_OCTAL_REGEXP = """(^|\.)0\d*[89]""".r
  // This regular expression parses the host and port from a hostname.  Note: any
  // user and password are removed from the hostname.
  val HOST_PORT_REGEXP = """^(?:.*@)?(?P<host>[^:]*)(:(?P<port>\d+))?$""".r
  // Dict that maps supported schemes to their default port number.
  val DEFAULT_PORTS = Map("http" -> "80", "https" -> "443", "ftp" -> "21")
  
  //parse_exception = UrlParseError('failed to parse URL "%s"' % (url,))
  val canonical_url = canonicalizeUrl(inputUrl).getOrElse(throw new Exception(""))

   // Each element is a list of host components used to build expressions.
   val host_lists = new ListBuffer[String]()
   // A list of paths used to build expressions.
   val path_exprs = new ListBuffer[String]()

   val url = new URL(canonical_url)
   val canonical_host = url.getHost()
   val canonical_path = url.getPath()
    
   makeHostLists(canonical_host)
   
   if (url.getQuery() != null){
     path_exprs += canonical_path + "?" + url.getQuery()
   }
   path_exprs += canonical_path
   
   var path_parts = canonical_path.stripPrefix("/").stripSuffix("/").split("/").takeRight(3)
   if (canonical_path.count(_=='/') < 4){
     //if the last component in not a directory we remove it.
     path_parts = path_parts.dropRight(1)
   }
   
   while (!path_parts.isEmpty) {
     path_exprs += "/" + path_parts.mkString("/") + "/"
     path_parts.dropRight(1)
   }
     
   val parts = canonical_path.split("""\/""").dropRight(1)
    var previous = ""
    breakable {
      for (i <- 0 until parts.length) {
        previous += parts(i) + "/"
        path_exprs += previous
        if (path_exprs.length >= 6) break
      }
    }
//
//     Get the first three directory path components and create the 4 path
//     expressions starting at the root (/) and successively appending directory
//     path components, including the trailing slash. E.g.:
//     /a/b/c/d.html -> [/, /a/, /a/b/, /a/b/c/]
//    path_parts = canonical_path.rstrip('/').lstrip('/').split('/')[:3]
//    if canonical_path.count('/') < 4:
//      # If the last component in not a directory we remove it.
//      path_parts.pop()
//    while path_parts:
//      self._path_exprs.append('/' + '/'.join(path_parts) + '/')
//      path_parts.pop()
//
//    if canonical_path != '/':
//      self._path_exprs.append('/')

    def canonicalizeUrl(url: String): Option[String] = {
      None
    }
    
    def makeHostLists(host: String) = {
      
    }
}