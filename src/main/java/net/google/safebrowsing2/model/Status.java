package net.google.safebrowsing2.model;

import java.util.Date;

public class Status {

	private int time;
	private int wait;
	private int errors;

	public Status(int time, int wait, int errors) {
		super();
		this.time = time;
		this.wait = wait;
		this.errors = errors;
	}

	public int getTime() {
		return time;
	}

	public void setTime(int time) {
		this.time = time;
	}

	public int getWait() {
		return wait;
	}

	public void setWait(int wait) {
		this.wait = wait;
	}

	public int getErrors() {
		return errors;
	}

	public void setErrors(int errors) {
		this.errors = errors;
	}

}
