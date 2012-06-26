# Google Safebrowsing API v2 for Scala and Java

This project implements the [Google Safebrowsing API v2](https://developers.google.com/safe-browsing/) in Scala.

## Usage in Scala
### Safe Browsing API
	val apikey = "123456"
	val dburl = "jdbc:mysql://localhost:3306/googlesafebrowsing2"
	val tablePrefix = "gsb2_"
	val storage = new MySQL(LiteDataSource.driverManager(dburl, "user", "pass"), tablePrefix)
	val sb2 = new SafeBrowsing2(apikey, storage)
	
	// update database
	val forceUpdate = false
	val useMac = false
	val secondsToWaitBeforeNextUpdate = sb2.update("", forceUpdate, useMac)
	
	// lookup url in database
	val list = "" // lookup in all lists
	val listMatch = sb2.lookup("http://ianfette.org", list, useMac)
	listMatch match {
	  case Some(list) => println("Match found in list: " + list)
	  case None => println("No match found")
	}

### Lookup API
	val resp = new Lookup(apikey).lookup(Array("http://www.google.com/", "http://ianfette.org/"))
	resp.foreach(a => {
	  println(a._1 + " -> " + a._2)
	})
	
Outputs:

	http://www.google.com/ -> ok
	http://ianfette.org/ -> malware
	
## Usage in Java
### Safe Browsing API
	String apikey = "123456";
	String url = "jdbc:mysql://localhost:3306/googlesafebrowsing2";
	String tablePrefix = "gsb2_";
	Storage storage = JavaHelper.buildStorageMySQL(url, "user", "password", tablePrefix);
	SafeBrowsing2 sb2 = new SafeBrowsing2(apikey, storage);
	
	// update the database
	boolean forceUpdate = false;
	boolean useMac = false;
	int secondsToWaitBeforeNextUpdate = sb2.update("", forceUpdate, useMac);
	
	// lookup url in database
	String list = ""; // lookup in all lists
	String match = sb2.jlookup("http://ianfette.org", list, useMac);
	if (match != null)
		System.out.println("Match found in list: " + list);
	
### Lookup API
	Lookup lookup = new Lookup(apikey, "appname");
	Map<String, String> r = lookup.jlookup(new String[]{"http://ianfette.org"});
	for (String key : r.keySet()) {
		System.out.println(key + " -> " + r.get(key));
	}

## Database support
The following databases are currently supported:
* MySQL
* MS SQL
* HSQLDB

New Storage classes can be added by extending the net.google.safebrowsing2.db.DBI class or the net.google.safebrowsing2.db.Storage trait. 

## Dependencies
* slf4j-api-1.6
* joda-time-1.6.2
* scala-http-client-1.0 [link](https://github.com/snopoke/scala-http-client)
* Apache httpclient-4.1.x
* Apache httpcore-4.1.x
* Apache commons-codec-1.4
* scala-library-2.9.1

## Attributions
* The is based off Julien Sobrier's [Net-Google-SafeBrowsing2](https://github.com/juliensobrier/Net-Google-SafeBrowsing2) perl module.
* URL Canonicalization by Dave Shanley as part of [jgooglesafebrowsing](http://code.google.com/p/jgooglesafebrowsing/).
* ExpressionGenerator inspired by the [google-safe-browsing](http://code.google.com/p/google-safe-browsing/) python module.
* JDBC API by [Stepan Koltsov](https://bitbucket.org/stepancheg/scala-misc/)