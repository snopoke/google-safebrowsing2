package com.buildabrand.gsb.util;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.net.InetAddresses;
import org.apache.commons.lang3.StringUtils;
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
	
	private UrlEncoder codec = new UrlEncoder();

    // (?P<host>[^:]*)(:(?P<port>\d+))?$
    private Pattern HOST_PORT_REGEXP = Pattern.compile("^(?:.*@)?([^:]*)(:(\\d+))?$");
    private Pattern IP_WITH_TRAILING_SPACE = Pattern.compile("^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) ");
    private Pattern POSSIBLE_IP = Pattern.compile("^(?i)((?:0x[0-9a-f]+|[0-9\\\\.])+)");
    private Pattern FIND_BAD_OCTAL_REGEXP = Pattern.compile("(^|\\.)0\\d*[89]");
    private Pattern HEX = Pattern.compile("^0x([a-fA-F0-9]+)$");
    private Pattern OCT = Pattern.compile("^0([0-7]+)$");
    private Pattern DEC = Pattern.compile("^(\\d+)$");

    private String SAFE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

	private static URLUtils instance;
	
	/* singleton */
	private URLUtils() {}
	
	public static URLUtils getInstance() {
		if(instance==null) {
			instance = new URLUtils();
		}
		return instance;
	}

	/** Returns the canonicalized form of a URL, core logic written by Henrik Sjostrand, heavily modified for v2 by Dave Shanley.
	 * @author Henrik Sjostrand, Netvouz, http://www.netvouz.com/, info@netvouz.com & Dave Shanley <dave@buildabrand.com>
	 * @param queryURL
	 * @return
	 */
	public String canonicalizeURL(String queryURL) {
		if (StringUtils.isEmpty(queryURL)) {
			return null;
        }

        // Start by stripping off the fragment identifier.
        queryURL = StringUtils.substringBefore(queryURL, "#");
        // Stripping off leading and trailing white spaces.
        queryURL = StringUtils.trim(queryURL);
        // Remove any embedded tabs and CR/LF characters which aren't escaped.
        queryURL = StringUtils.remove(queryURL, '\t');
        queryURL = StringUtils.remove(queryURL, '\r');
        queryURL = StringUtils.remove(queryURL, '\n');

        // Un-escape and re-escpae the URL just in case there are some encoded
        // characters in the url scheme for example.
        queryURL = escape(queryURL);


        URL url;
        try {
            url = new URL(queryURL);
        } catch (MalformedURLException e) {
            // Try again with "http://"
            try {
                url = new URL("http://" + queryURL);
            } catch (MalformedURLException e2) {
                logger.error("Malformed url", e);
                return null;
            }
        }

        if (!(url.getProtocol().equalsIgnoreCase("http") ||
                url.getProtocol().equalsIgnoreCase("https") ||
                url.getProtocol().equalsIgnoreCase("ftp"))) {
            return null;
        }

        // Note: applying HOST_PORT_REGEXP also removes any user and password.
        Matcher hostMatcher = HOST_PORT_REGEXP.matcher(url.getHost());

        if (!hostMatcher.find()) {
            return null;
        }

        String host = hostMatcher.group(1);

        String canonicalHost = canonicalizeHost(host);
        if (canonicalHost == null) {
            return null;
        }

        // Now that the host is canonicalized we add the port back if it's not the
        // default port for that url scheme
        if (url.getPort() != -1 &&
                ((url.getProtocol().equalsIgnoreCase("http") && url.getPort() != 80) ||
                (url.getProtocol().equalsIgnoreCase("https") && url.getPort() != 443) ||
                (url.getProtocol().equalsIgnoreCase("ftp") && url.getPort() != 21))) {
            canonicalHost = canonicalHost + ":" + url.getPort();
        }

        String canonicalPath = canonicalizePath(url.getPath());

        String canonicalUrl = url.getProtocol() + "://" + canonicalHost + canonicalPath;
        if (StringUtils.isNotEmpty(url.getQuery()) || queryURL.endsWith("?")) {
            canonicalUrl += "?" + url.getQuery();
        }

        return canonicalUrl;
	}

    private String canonicalizePath(String path) {
        if (StringUtils.isEmpty(path)) {
            return "/";
        }

        // There are some cases where the path will not start with '/'.  Example:
        // "ftp://host.com?q"  -- the hostname is 'host.com' and the path '%3Fq'.
        // Browsers typically do prepend a leading slash to the path in this case,
        // we'll do the same.
        if (!path.startsWith("/")) {
            path = "/" + path;
        }

        path = escape(path);

        Stack<String> pathComponents = new Stack<String>();
        for (String pathComponent : StringUtils.split(path, '/')) {
             // If the path component is '..' we skip it and remove the preceding path
            // component if there are any.
            if (pathComponent.equals("..")) {
                if (!pathComponents.isEmpty()) {
                    pathComponents.pop();
                }
            } else if (!pathComponent.equals(".") && !pathComponent.equals("")) {
                // We skip empty path components to remove successive slashes (i.e.,
                // // -> /).  Note: this means that the leading and trailing slash will
                // also be removed and need to be re-added afterwards.
                //
                // If the path component is '.' we also skip it (i.e., /./ -> /).
                pathComponents.add(pathComponent);
            }
        }

        // Put the path components back together and re-add the leading slash which
        // got stripped by removing empty path components.
        String canonicalPath = "/" + StringUtils.join(pathComponents, "/");
        // If necessary we also re-add the trailing slash.
        if (path.endsWith("/") && !canonicalPath.endsWith("/")) {
            canonicalPath += "/";
        }

        return canonicalPath;
    }

    private String escape(String unescaped) {
        try {
            String unquoted = codec.decode(unescaped);
            while (!unquoted.equals(unescaped)) {
                unescaped = unquoted;
                unquoted = codec.decode(unquoted);
            }

            return codec.encode(unquoted);

            /*
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < unquoted.length(); i++) {
                char c = unquoted.charAt(i);

                if (SAFE_CHARS.contains(c + "")) {
                    sb.append(c);
                } else {
                    sb.append(URLEncoder.encode(String.valueOf(c), "UTF-8"));
                }
            }
            return sb.toString();
            */
        } catch (Exception e) {
            logger.error("fail to escape", e);
            return null;
        }
    }

    public String canonicalizeHost(String host) {
        if (StringUtils.isEmpty(host)) {
            return null;
        }

        host = escape(StringUtils.lowerCase(host));

        String ip = canonicalizeIp(host);
        if (ip != null) {
            return ip;
        } else {
            // Host is a normal hostname.
            // Skip trailing, leading and consecutive dots.
            String[] hostSplit = StringUtils.split(host, '.');
            if (hostSplit.length < 2) {
                return null;
            } else {
                return StringUtils.join(hostSplit, '.');
            }
        }
    }

    public String canonicalizeIp(String host) {
        if (StringUtils.length(host) <= 15) {
            // The Windows resolver allows a 4-part dotted decimal IP address to have a
            // space followed by any old rubbish, so long as the total length of the
            // string doesn't get above 15 characters. So, "10.192.95.89 xy" is
            // resolved to 10.192.95.89.
            // If the string length is greater than 15 characters,
            // e.g. "10.192.95.89 xy.wildcard.example.com", it will be resolved through
            // DNS.
            Matcher ipWithTrailingSpaceMatched = IP_WITH_TRAILING_SPACE.matcher(host);

            if (ipWithTrailingSpaceMatched.find()) {
                host = ipWithTrailingSpaceMatched.group(1);
            }
        }

        if (!POSSIBLE_IP.matcher(host).find()) {
            return null;
        }

        // Skip trailing, leading and consecutive dots.
        return convertIpAddress(host);
    }

    private String convertIpAddress(String ipAddr) {
        String[] ipAddrSplit = StringUtils.split(ipAddr, '.');

        if (ipAddrSplit.length > 4) {
            return null;
        }

        // Basically we should parse octal if we can, but if there are illegal octal
        // numbers, i.e. 08 or 09, then we should just look at decimal and hex.
        boolean allowOctal = !FIND_BAD_OCTAL_REGEXP.matcher(ipAddr).find();

        BigInteger ipNumeric = BigInteger.ZERO;
        int i = 0;
        while (i < ipAddrSplit.length - 1) {
            ipNumeric = ipNumeric.shiftLeft(8);
            BigInteger componentBigInt = convertComponent(ipAddrSplit[i], allowOctal);
            if (componentBigInt == null) {
                return null;
            }

            ipNumeric = ipNumeric.add(componentBigInt);
            i++;
        }
        while (i < 4) {
            ipNumeric = ipNumeric.shiftLeft(8);
            i++;
        }
        BigInteger componentBigInt = convertComponent(ipAddrSplit[ipAddrSplit.length - 1], allowOctal);
        if (componentBigInt == null) {
            return null;
        }
        ipNumeric = ipNumeric.add(componentBigInt);

        return InetAddresses.fromInteger((ipNumeric.intValue())).getHostAddress();
    }

    private BigInteger convertComponent(String component, boolean allowOctal) {
        Matcher matcher;

        if ((matcher = HEX.matcher(component)).find()) {
            return new BigInteger(matcher.group(1), 16);
        } else if (allowOctal && (matcher = OCT.matcher(component)).find()) {
            return new BigInteger(matcher.group(1), 8);
        } else if (((matcher = DEC.matcher(component)).find())) {
            return new BigInteger(matcher.group(1));
        } else {
            return null;
        }
    }
}