package com.buildabrand.gsb.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.net.InetAddresses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * URLUtils
 * Canonicalisation and processing of URL's to be matched in database.
 *
 * <h4>Copyright and License</h4>
 * This code is copyright (c) Buildabrand Ltd, 2011 except where
 * otherwise stated. It is released as
 * open-source under the Creative Commons NC-SA license. See
 * <a href="http://creativecommons.org/licenses/by-nc-sa/2.5/">http://creativecommons.org/licenses/by-nc-sa/2.5/</a>
 * for license details. This code comes with no warranty or support.
 *
 * @author Dave Shanley <dave@buildabrand.com>
 */
public class URLUtils {
	
	protected final Logger logger = LoggerFactory.getLogger(getClass());
	
	private static UrlEncoder codec = new UrlEncoder();
	private static URLUtils instance;
	
	/* singleton */
	private URLUtils() {}
	
	public static URLUtils getInstance() {
		if(instance==null) {
			instance = new URLUtils();
		}
		return instance;
	}
	
	
	/** Unscapes a string repeatedly to remove all escaped characters. Returns null if the string is invalid.
	 * @param url
	 * @return
	 * @throws GSBException
	 */
	private String unescape(String url) {
		
		if (url == null)
			return null;

		StringBuffer text1 = new StringBuffer(url);
		url = text1.toString();

		String text2 = url;
		
			for(int x = 0; x < 50; x++) { // keep iterating to make sure all those encodings are killed.
				
				text2 = codec.decode(text2); // Unescape repeatedly until no more percent signs left
			}	
		
			logger.debug("returning URL: {}", text2);
		
		return text2;
	}
	
	/**
	 * Decode a host, If it is a hostname, return it, if it is an IP decode (encoding, including octal & hex)
	 * @param host
	 * @return
	 */
	private String decodeHost(String host) {
        try {
            long ipInt = Long.parseLong(host);
            return InetAddresses.fromInteger((int)ipInt).getHostAddress();
        } catch (NumberFormatException e) {
            // It is ok not to be integer.
            return host.toLowerCase();
        }
	}
		
	
	/** Returns the canonicalized form of a URL, core logic written by Henrik Sjostrand, heavily modified for v2 by Dave Shanley.
	 * @author Henrik Sjostrand, Netvouz, http://www.netvouz.com/, info@netvouz.com & Dave Shanley <dave@buildabrand.com>
	 * @param queryURL
	 * @return
	 * @throws GSBException
	 */
	public String canonicalizeURL(String queryURL) {
		
		if (queryURL == null)
			return null;

		String url = queryURL;
		
		try {

			/* first of all extract the components of the URL to make sure that it has a protocol! */
			if(url.indexOf("http://") <=-1 && url.indexOf("https://")<=-1) url = "http://"+url;
			
			url = url.replaceAll("[\\t\\n\\r\\f\\e]*", ""); // replace all whitespace and escape characters.

			URL theURL = new URL(url);
			String host = theURL.getHost();
			String path = theURL.getPath();
			String query = theURL.getQuery();
			String protocol = theURL.getProtocol();
			if(protocol==null||protocol.isEmpty()) protocol = "http";
			int port = theURL.getPort();
			String user = theURL.getUserInfo();

			/* escape host */
			logger.debug("pre-escaped host: {}", host);
			host = unescape(host);
			logger.debug("post-escaped host: {}", host);

			/* decode host / IP */
			host = decodeHost(host);
			logger.debug("decoded host: {}", host);


			/* escape non standard characters for host */
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < host.length(); i++) {
				char c = host.charAt(i);
				if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || c == '.' || c == '-')
					sb.append(c);
				else
					sb.append(codec.encode(String.valueOf(c))); // Escape using UTF-8
			}
			host = sb.toString();

			/* remove leading and trailing dots */
			while (host.startsWith("."))
				host = host.substring(1);
			while (host.endsWith("."))
				host = host.substring(0, host.length() - 1);

			/* replace consecutive dots with a single dot */
			int p = 0;
			while ((p = host.indexOf("..")) != -1)
				host = host.substring(0, p + 1) + host.substring(p + 2);

			/* add a trailing slash if the path is empty */
			if ("".equals(path))
				host = host + "/";
			
			/* find and replace any dodgy decoded escape characters */
			Pattern pattern =  Pattern.compile("([a-z]{1})([0-9]{2})");
			Matcher matcher = pattern.matcher(host);
		    String val = "$2";
		    while (matcher.find()) {
		    	logger.debug(":::TEXT FOUND {} starting at index {} and ending at index {}", 
		    			new Object[] {matcher.group(), matcher.start(), matcher.end()});
	               host = matcher.replaceAll(val);
	              logger.debug("::TEXT {}", host);
		    }

			/* replace any encoded percentage signs */
		    host = host.replaceAll("(?i)%5C", "%");

			/* unescape path to remove all hex encodings */
		    logger.debug("pre-escaped path: {}", path);
			path = unescape(path);
			logger.debug("post-escaped path: {}", path);

			/* remove double slashes from path  */
			while ((p = path.indexOf("//")) != -1)
				path = path.substring(0, p + 1) + path.substring(p + 2);

			/* remove /./ occurences from path */
			while ((p = path.indexOf("/./")) != -1)
				path = path.substring(0, p + 1) + path.substring(p + 3);

			/* resolve /../ occurences in path */
			while ((p = path.indexOf("/../")) != -1) {
				int previousSlash = path.lastIndexOf("/", p-1);
				// if (previousSlash == -1) previousSlash = 0; // If path begins with /../
				path = path.substring(0, previousSlash) + path.substring(p + 3);
				p = previousSlash;
			}

			/* use URI class to normalise the URL */
			URI uri = null;
			try {

				/* only normalise if the host doesn't contain some odd hex */
				if(!host.contains("%") && !host.matches("[\\s].*")) { 
					logger.debug("normalising URL......");
					uri = new URI(protocol, user, host, -1, path, query, null);
					logger.debug("{} <-- normalised path", uri.normalize().getPath().toString());
				}

			} catch (URISyntaxException exp) {
				
				try {

					/* only normalise if the host doesn't contain some odd hex */
					if(!host.contains("%") && !host.matches(".*[\\s].*")) { 
						logger.debug("error normalising URL");
						uri = new URI(protocol, user, unescape(host), -1, path, query, null);
						logger.debug("{} <-- normalised path after error debug", uri.normalize().getPath().toString());
					}

				} catch (URISyntaxException e) {
					
					// total fail, forget it.
				}
			}

			/* only use URI normalized URL if it's not a total failure */
			if(uri!=null && !uri.normalize().getPath().toString().trim().isEmpty()) {
				logger.debug("normalized path is: empty!");
				path = uri.normalize().getPath().toString();
			}  

			/* debug code */
			logger.debug("post-cleaned path: {}", path);
			logger.debug("post-processed host: {}", host);
			
			
			/* escape the path */
			path = escape(path);

			/* replace all semi-colons */
			path = path.replaceAll("[;]*", ""); 

			/* unescape the query */
			query = unescape(query);

			/* re-escape the query */
			query = escape(query);


			/* re-assemble the URL */
			sb.setLength(0);
			sb.append(protocol + ":");
		
			sb.append("//");
			if (user != null)
				sb.append(user + "@");

			if (port != -1) {

				/* remove slash from host */
				logger.debug("removing last slash: {}", host.lastIndexOf("/",host.length()));
				
				if(host.lastIndexOf("/",host.length())>8) {
					logger.debug("new host name: {}", host.substring(0,host.length()-1));
					
					host = host.substring(0,host.length()-1);
				}
				sb.append(host);
				sb.append(":");
				sb.append(port);
			} else {
				sb.append(host);
			}
			
			/* make sure any hashes are re-encoded back to %23*/
			path = path.replaceAll("#","%23");
			
			sb.append(path);
			if(sb.toString().endsWith("//")) sb = sb.replace(sb.length()-1, sb.length(), "");
			
			if (query != null)
				sb.append("?" + query);
			
			url = sb.toString();

			logger.debug("canonicalised url is: {}", url);
			
			
		} catch (Exception e) {
			e.printStackTrace();
			// TODO handle exception
			//throw new GSBException("Could not canonicalise URL: " + queryURL);
		}
		
		
		logger.debug("final decoding URL: {}", url);

		return url;
	}
	
	/** Escapes a string by replacing characters having ASCII <=32, >=127, or % with their UTF-8-escaped codes 
	 * 
	 * @param url
	 * @return escaped url
	 * @author Henrik Sjostrand, Netvouz, http://www.netvouz.com/, info@netvouz.com
	 */
	private String escape(String url) {
		if (url == null)
			return null;
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < url.length(); i++) {
			char c = url.charAt(i);
			if (c == ' ')
				sb.append("%20");
			else if (c <= 32 || c >= 127 || c == '%') {
					sb.append(codec.encode(String.valueOf(c))); // replace crappy URLDecoder form v1 with something a little more useful.
			} else
				sb.append(c);
		}
		return sb.toString();
	}
}