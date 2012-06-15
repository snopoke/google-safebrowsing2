package net.google.safebrowsing2.model;

public class Hash {

	private int chunknum;
	private String hash;
	private String list;

	public Hash(int chunknum, String hash, String list) {
		super();
		this.chunknum = chunknum;
		this.hash = hash;
		this.list = list;
	}

	public int getChunknum() {
		return chunknum;
	}

	public void setChunknum(int chunknum) {
		this.chunknum = chunknum;
	}

	public String getHash() {
		return hash;
	}

	public void setHash(String hash) {
		this.hash = hash;
	}

	public String getList() {
		return list;
	}

	public void setList(String list) {
		this.list = list;
	}

}
