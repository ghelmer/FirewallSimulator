package org.redwater.fwsim.exceptions;

public class InvalidFieldValueException extends Exception {
	/**
	 * Announce invalid rule field name error.
	 */

	private static final long serialVersionUID = -3699110502620854656L;

	public InvalidFieldValueException() {
		super();
	}
	public InvalidFieldValueException(String message) {
		super(message);
	}

}
