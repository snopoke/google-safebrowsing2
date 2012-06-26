# Google Safebrowsing API v2 for Scala and Java

This project implements the [Google Safebrowsing API v2](https://developers.google.com/safe-browsing/) in Scala.

## Usage in Scala
### Safe Browsing API
	val apikey = "123456"
	val storage = new MySQL(LiteDataSource.driverManager("jdbc:mysql://localhost:3306/googlesafebrowsing2", "user", "pass"), "gsb2_")
	val sb2 = new SafeBrowsing2(apikey, storage)
	
	// update database
	val secondsToWaitBeforeNextUpdate = sb2.update("", false, false)
	
	// lookup url in database
	val listMatch = sb2.lookup("http://ianfette.org", "", false)
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
	Storage storage = JavaHelper.buildStorageMySQL("jdbc:mysql://localhost:3306/googlesafebrowsing2", "user", "password", "gsb2_");
	SafeBrowsing2 sb2 = new SafeBrowsing2(apikey, storage);
	
	// update the database
	int secondsToWaitBeforeNextUpdate = sb2.update("", false, false);
	
	// lookup url in database
	String match = sb2.jlookup("http://ianfette.org","",false);
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
 
## Attributions
* The is based off Julien Sobrier's [Net-Google-SafeBrowsing2](https://github.com/juliensobrier/Net-Google-SafeBrowsing2) perl module.
* URL Canonicalization by Dave Shanley as part of [jgooglesafebrowsing](http://code.google.com/p/jgooglesafebrowsing/).
* ExpressionGenerator inspired by [google-safe-browsing](http://code.google.com/p/google-safe-browsing/) python module.