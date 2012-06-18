package net.google.safebrowsing2.model;

public class MacKey {

	private String clientKey;
	private String wrappedKey;
	
	public MacKey() {
	}

	public MacKey(String clientKey, String wrappedKey) {
		super();
		this.clientKey = clientKey;
		this.wrappedKey = wrappedKey;
	}

	public String getClientKey() {
		return clientKey;
	}

	public void setClientKey(String clientKey) {
		this.clientKey = clientKey;
	}

	public String getWrappedKey() {
		return wrappedKey;
	}

	public void setWrappedKey(String wrappedKey) {
		this.wrappedKey = wrappedKey;
	}

	@Override
	public String toString() {
		return "MacKey [clientKey=" + clientKey + ", wrappedKey=" + wrappedKey
				+ "]";
	}
}
