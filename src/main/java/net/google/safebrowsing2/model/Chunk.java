package net.google.safebrowsing2.model;

public class Chunk {
	
	private int chunknum;
	private String prefix;
	private String hostkey;
	private String list;
	private int addChunknum;
	
	public Chunk(int chunknum, String prefix, String hostkey, String list) {
		super();
		this.chunknum = chunknum;
		this.prefix = prefix;
		this.hostkey = hostkey;
		this.list = list;
	}
	
	public Chunk(int chunknum, String prefix, int addChunknum, String list) {
		super();
		this.chunknum = chunknum;
		this.prefix = prefix;
		this.addChunknum = addChunknum;
		this.list = list;
	}
	
	public int getChunknum() {
		return chunknum;
	}
	public void setChunknum(int chunknum) {
		this.chunknum = chunknum;
	}
	public String getPrefix() {
		return prefix;
	}
	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}
	public String getHostkey() {
		return hostkey;
	}
	public void setHostkey(String hostkey) {
		this.hostkey = hostkey;
	}
	public String getList() {
		return list;
	}
	public void setList(String list) {
		this.list = list;
	}

	public int getAddChunknum() {
		return addChunknum;
	}

	public void setAddChunknum(int addChunknum) {
		this.addChunknum = addChunknum;
	}

	
}
