package com.buildabrand.gsb;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.buildabrand.gsb.util.URLUtils;

/**
 * Test Canonicalisation
 * @author Dave Shanley
 *
 */
public class CanonicalizationTest {
	
	private Logger log = LoggerFactory.getLogger(CanonicalizationTest.class);
	
	@Rule
	public ErrorCollector collector = new ErrorCollector();
	private URLUtils utils = URLUtils.getInstance();
	
	@Test
	public void testURLCanoniconialization() {
        testCannicalize("http://google.com/", "http://google.com/");
        testCannicalize("http://google.com:80/a/b", "http://google.com/a/b");
        testCannicalize("http://google.com:80/a/b/c/", "http://google.com/a/b/c/");
        testCannicalize("http://GOOgle.com", "http://google.com/");
        testCannicalize("http://..google..com../", "http://google.com/");
        testCannicalize("http://google.com/%25%34%31%25%31%46", "http://google.com/A%1F");
        testCannicalize("http://google^.com/", "http://google^.com/");
        testCannicalize("http://google.com/1/../2/././", "http://google.com/2/");
        testCannicalize("http://google.com/1//2?3//4", "http://google.com/1/2?3//4");
        // Some more examples of our url lib unittest.
        testCannicalize("http://host.com/%25%32%35", "http://host.com/%25");
        testCannicalize("http://host.com/%25%32%35%25%32%35", "http://host.com/%25%25");
        testCannicalize("http://host.com/%2525252525252525", "http://host.com/%25");
        testCannicalize("http://host.com/asdf%25%32%35asd", "http://host.com/asdf%25asd");
        testCannicalize("http://host.com/%%%25%32%35asd%%", "http://host.com/%25%25%25asd%25%25");
        testCannicalize("http://www.google.com/", "http://www.google.com/");
        testCannicalize("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/", "http://168.188.99.26/.secure/www.ebay.com/");
        testCannicalize("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/", "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/");
        testCannicalize("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B", "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+");
        testCannicalize("http://3279880203/blah", "http://195.127.0.11/blah");
        testCannicalize("http://www.google.com/blah/..", "http://www.google.com/");
        testCannicalize("http://a.com/../b", "http://a.com/b");
        testCannicalize("www.google.com/", "http://www.google.com/");
        testCannicalize("www.google.com", "http://www.google.com/");
        testCannicalize("http://www.evil.com/blah#frag", "http://www.evil.com/blah");
        testCannicalize("http://www.GOOgle.com/", "http://www.google.com/");
        testCannicalize("http://www.google.com.../", "http://www.google.com/");
        testCannicalize("http://www.google.com/foo\tbar\rbaz\n2", "http://www.google.com/foobarbaz2");
        testCannicalize("http://www.google.com/q?", "http://www.google.com/q?");
        testCannicalize("http://www.google.com/q?r?", "http://www.google.com/q?r?");
        testCannicalize("http://www.google.com/q?r?s", "http://www.google.com/q?r?s");
        testCannicalize("http://evil.com/foo#bar#baz", "http://evil.com/foo");
        testCannicalize("http://evil.com/foo;", "http://evil.com/foo;");
        testCannicalize("http://evil.com/foo?bar;", "http://evil.com/foo?bar;");
        testCannicalize("http://\u0001\u0080.com/", "http://%01%80.com/");
        testCannicalize("http://notrailingslash.com", "http://notrailingslash.com/");
        testCannicalize("http://www.gotaport.com:1234/", "http://www.gotaport.com:1234/");
        testCannicalize("http://www.google.com:443/", "http://www.google.com:443/");
        testCannicalize("  http://www.google.com/  ", "http://www.google.com/");
        testCannicalize("http:// leadingspace.com/", "http://%20leadingspace.com/");
        testCannicalize("http://%20leadingspace.com/", "http://%20leadingspace.com/");
        testCannicalize("%20leadingspace.com/", "http://%20leadingspace.com/");
        testCannicalize("https://www.securesite.com:443/", "https://www.securesite.com/");
        testCannicalize("ftp://ftp.myfiles.com:21/", "ftp://ftp.myfiles.com/");
        testCannicalize("http://some%1Bhost.com/%1B", "http://some%1Bhost.com/%1B");
        // Test NULL character
        //testCannicalize("http://test%00\\x00.com/", "http://test%00%00.com/");
        // Username and password should be removed
        testCannicalize("http://user:password@google.com/", "http://google.com/");
        //All of these cases are missing a valid hostname and should return ""
        testCannicalize("", null);
        testCannicalize(":", null);
        testCannicalize("/blah", null);
        testCannicalize("#ref", null);
        testCannicalize("/blah#ref", null);
        testCannicalize("?query#ref", null);
        testCannicalize("/blah?query#ref", null);
        testCannicalize("/blah;param", null);
        testCannicalize("http://#ref", null);
        testCannicalize("http:///blah#ref", null);
        testCannicalize("http://?query#ref", null);
        testCannicalize("http:///blah?query#ref", null);
        testCannicalize("http:///blah;param", null);
        testCannicalize("http:///blah;param?query#ref", null);
        testCannicalize("mailto:bryner@google.com", null);
        // If the protocol is unrecognized, the URL class does not parse out a hostname.
        testCannicalize("myprotocol://site.com/", null);
        // This URL should _not_ have hostname shortening applied to it.
        testCannicalize("http://i.have.way.too.many.dots.com/", "http://i.have.way.too.many.dots.com/");
        // WholeSecurity escapes parts of the scheme
        testCannicalize("http%3A%2F%2Fwackyurl.com:80/", "http://wackyurl.com/");
        testCannicalize("http://W!eird<>Ho$^.com/", "http://w!eird<>ho$^.com/");
        // The path should have a leading "/" even if the hostname was terminated
        // by something other than a "/".
        testCannicalize("ftp://host.com?q", "ftp://host.com/?q");
	}

    @Test
    public void testCanonicalizeIp() {
        assertEquals("1.2.3.4", utils.canonicalizeIp("1.2.3.4"));
        assertEquals("10.28.1.45", utils.canonicalizeIp("012.034.01.055"));
        assertEquals("18.67.68.1", utils.canonicalizeIp("0x12.0x43.0x44.0x01"));
        assertEquals("10.1.2.3", utils.canonicalizeIp("167838211"));
        assertEquals("12.18.2.156", utils.canonicalizeIp("12.0x12.01234"));
        assertEquals("0.0.0.11", utils.canonicalizeIp("0x10000000b"));
        assertNull(utils.canonicalizeIp("asdf.com"));
        assertNull(utils.canonicalizeIp("0x120x34"));
        assertNull(utils.canonicalizeIp("123.123.0.0.1"));
        assertNull(utils.canonicalizeIp("1.2.3.00x0"));
        assertNull(utils.canonicalizeIp("fake ip"));
        assertNull(utils.canonicalizeIp("123.123.0.0.1"));
        assertEquals("255.0.0.1", utils.canonicalizeIp("255.0.0.1"));
        assertEquals("12.18.2.156", utils.canonicalizeIp("12.0x12.01234"));
        assertEquals("20.2.0.3", utils.canonicalizeIp("276.2.3"));
        assertEquals("10.28.1.45", utils.canonicalizeIp("012.034.01.055"));
        assertEquals("18.67.68.1", utils.canonicalizeIp("0x12.0x43.0x44.0x01"));
        assertEquals("10.1.2.3", utils.canonicalizeIp("167838211"));
        assertEquals("195.127.0.11", utils.canonicalizeIp("3279880203"));
        assertEquals("255.255.255.255", utils.canonicalizeIp("4294967295"));
        assertEquals("10.192.95.89", utils.canonicalizeIp("10.192.95.89 xy"));
        assertNull(utils.canonicalizeIp("1.2.3.00x0"));
        // If we find bad octal parse the whole IP as decimal or hex.
        assertEquals("12.160.1.89", utils.canonicalizeIp("012.0xA0.01.089"));
    }

    @Test
    public void testCanonicalizeHost() {
        // IP Address
        assertEquals("10.1.2.3", utils.canonicalizeIp("167838211"));
    }
	
	private void testCannicalize(String url, String expected) {
		String result = utils.canonicalizeURL(url);
		log.debug("{} => {}", url, result);
		collector.checkThat(result, is(expected));
	}
	
}