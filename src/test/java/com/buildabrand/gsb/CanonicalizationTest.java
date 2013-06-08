package com.buildabrand.gsb;

import static org.hamcrest.CoreMatchers.is;

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
        testCannicalize("http://host/%25%32%35","http://host/%25");
		testCannicalize("http://host/%25%32%35%25%32%35","http://host/%25%25");
		testCannicalize("http://host/%2525252525252525","http://host/%25");
		testCannicalize("http://host/asdf%25%32%35asd","http://host/asdf%25asd");
		testCannicalize("http://www.google.com","http://www.google.com/");
		testCannicalize("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/","http://168.188.99.26/.secure/www.ebay.com/");
		testCannicalize("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/", "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/");
		testCannicalize("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B", "http://host%23.com/~a!b@c%23d$e%25f%255E00&11*22(33)44_55+");
		testCannicalize("http://3279880203/blah","http://195.127.0.11/blah");
		testCannicalize("http://www.google.com/blah/..","http://www.google.com/");
		testCannicalize("www.google.com","http://www.google.com/");
		testCannicalize("http://www.evil.com/blah#frag","http://www.evil.com/blah");
		testCannicalize("http://www.GOOgle.com/","http://www.google.com/");
		testCannicalize("http://www.google.com.../","http://www.google.com/");
		testCannicalize("http://www.google.com/foo\tbar\rbaz\n2","http://www.google.com/foobarbaz2");
		testCannicalize("http://www.google.com/q?","http://www.google.com/q?");
		testCannicalize("http://www.google.com/q?r?","http://www.google.com/q?r?");
		testCannicalize("http://evil.com/foo#bar#baz","http://evil.com/foo");
		testCannicalize("http://evil.com/foo;","http://evil.com/foo");
		testCannicalize("http://evil.com/foo?bar;","http://evil.com/foo?bar;");
		testCannicalize("http://\\x01\\x80.com/","http://%01%80.com/");
		testCannicalize("http://www.gotaport.com:1234","http://www.gotaport.com:1234/");
		testCannicalize("  http://www.google.com/  ","http://www.google.com/");
		testCannicalize("http:// leadingspace.com/","http://%20leadingspace.com/");
		testCannicalize("http://%20leadingspace.com/","http://%20leadingspace.com/");
		testCannicalize("%20leadingspace.com/","http://%20leadingspace.com/");
		testCannicalize("https://www.securesite.com/","https://www.securesite.com/");
		testCannicalize("http://host.com/ab%23cd","http://host.com/ab%23cd");
		testCannicalize("http://host.com//twoslashes?more//slashes","http://host.com/twoslashes?more//slashes");
		testCannicalize("http://what youtalking.....com/there?value=moo#there","http://what%20youtalking.com/there?value=moo");
		testCannicalize("http://host.com/what/do/../think/..","http://host.com/what/");
		testCannicalize("http://host.com/what/do/./think/../hello","http://host.com/what/do/hello");
	}

    @Test
    public void testIpAddress() {
        testCannicalize("http://1.2.3.4/", "http://1.2.3.4/");
        testCannicalize("http://012.034.01.055/", "http://10.28.1.45/");
        testCannicalize("http://0x12.0x43.0x44.0x01/", "http://18.67.68.1/");
        testCannicalize("http://167838211/", "http://10.1.2.3/");
        testCannicalize("http://12.0x12.01234/", "http://12.18.2.156/");
        testCannicalize("http://276.2.3/", "http://20.2.0.3/");
        testCannicalize("http://0x10000000b/", "http://0.0.0.11/");
        testCannicalize("http://0x120x34/", "http://012034/");
        testCannicalize("http://123.123.0.0.1/", "http://123.123.0.0.1/");
        testCannicalize("http://1.2.3.00x0/", "http://1.2.3.00x0/");
    }
	
	private void testCannicalize(String url, String expected) {
		String result = utils.canonicalizeURL(url);
		log.debug("{} => {}", url, result);
		collector.checkThat(result, is(expected));
	}
	
}