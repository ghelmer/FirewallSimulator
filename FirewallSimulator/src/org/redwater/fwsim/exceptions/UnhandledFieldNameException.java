package org.redwater.fwsim.exceptions;

public class UnhandledFieldNameException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = -4698543173526893452L;

	public UnhandledFieldNameException() {
		super();
	}
	public UnhandledFieldNameException(String message) {
		super(message);
	}
}
