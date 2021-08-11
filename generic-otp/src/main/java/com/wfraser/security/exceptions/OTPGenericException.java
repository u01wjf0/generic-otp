package com.wfraser.security.exceptions;
/**
 * OTPGenericException is the RuntimeException for all caught exceptions 
 * created by the library
 * 
 * 
 * @author 	William Frasewr
 * @version	%I%, %G%
 * @since 	1.0
 *
 */

public class OTPGenericException extends RuntimeException {
	
	/*
	 *	List of default error messages
	 */
	public static final String _USER_AND_KEY_BLANK = "FATAL: OTPUserCredentailProvider not properly populated.";
	public static final String _KEY_BLANK = "FATAL: OTPUserCredentailProvider does not contain Secret Key.";
	public static final String _ERROR_GETTING_URL = "FATAL: Error in getting URL for Google Authenticator";
	public static String _ERROR_GETTING_QRCODE = "FATAL: Error in getting QRCode for Google Authenticator";
	public static String _ERROR_CREATING_OTP_INSTANCE = "FATAL: Error creating instacnce of OTPImplementation";
	
	private static final long serialVersionUID = 5180940924673148608L;

	/**
	 * Class Constructor
	 * 
	 * @param errorMessage	the String of the error message
	 */
	public OTPGenericException(String errorMessage)
	{
		super(errorMessage);
	}
	
	/**
	 * Class Constructor
	 * 
	 * @param errorMessage	the String of the error message
	 * @param err			the Throwable being wrapped
	 */
	public OTPGenericException(String errorMessage, Throwable err) {
	    super(errorMessage, err);
	}
	
	
}
