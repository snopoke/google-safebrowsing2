package net.google.safebrowsing;

import java.util.Map;

import net.google.safebrowsing2.Expression;
import net.google.safebrowsing2.ExpressionGenerator;
import net.google.safebrowsing2.JavaHelper;
import net.google.safebrowsing2.Lookup;
import net.google.safebrowsing2.SafeBrowsing2;
import net.google.safebrowsing2.db.Storage;

public class JavaCompatabilityTest {
	
	String apikey = "123456";
	String url = "jdbc:mysql://localhost:3306/googlesafebrowsing2";
	String tablePrefix = "gsb2_";
	
	public void safebrowsing2() throws Exception {
		Storage storage = JavaHelper.buildStorageMySQL(url, "user", "password", tablePrefix);
		SafeBrowsing2 sb2 = new SafeBrowsing2(apikey, storage);
		
		// update the database
		boolean forceUpdate = false;
		boolean useMac = false;
		String[] updateLists = null; // update all lists
		int wait = sb2.update(updateLists, forceUpdate, useMac);
		System.out.println("Seconds to wait before next update: " + wait);
		
		// lookup url in database
		String[] lookupLists = null; // lookup in all lists
		String match = sb2.jlookup("http://ianfette.org", lookupLists, useMac);
		if (match != null)
			System.out.println("Match found in list: " + match);
	}
	
	public void lookup(String baseUrl) {
		if (baseUrl == null || baseUrl.isEmpty()){
			baseUrl = "https://sb-ssl.google.com/safebrowsing/api/";
		}
		Lookup lookup = new Lookup(apikey, "appname", baseUrl, "3.0");
		Map<String, String> r = lookup.jlookup(new String[]{"http://ianfette.org"}, 0);
		for (String key : r.keySet()) {
			System.out.println(key + " -> " + r.get(key));
		}
	}
	
	public void getKeys() {
		String url = "http://www.google.com";
		ExpressionGenerator gen = new ExpressionGenerator(url);
		System.out.println("Host key for url: " + gen.getHostKey());
		System.out.println("Expressions for URL:");
		for (Expression exp : gen.getExpressions()) {
			System.out.println("	" + exp.value() + " -> " + exp.hexHash());
		}
	}
	
	public static void main(String[] args) {
		new JavaCompatabilityTest().lookup("http://192.168.1.114:8082/");
	}
}
