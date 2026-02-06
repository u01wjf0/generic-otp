package com.wfraser.security.exceptions;
/**
 * OTPGenericException is the checked exception for all library errors.
 * 
 * 
 * @author 	William Fraser
 * @version	2.0
 * @since 	1.0
 *
 */

public class OTPGenericException extends Exception {
	
	/*
	 * List of default error messages.
	 */
	public static final String _USER_AND_KEY_BLANK = "FATAL: OTPUserCredentailProvider not properly populated.";
	public static final String _KEY_BLANK = "FATAL: OTPUserCredentailProvider does not contain Secret Key.";
	public static final String _KEY_INVALID = "FATAL: OTPUserCredentailProvider contains invalid Secret Key.";
	public static final String _ALLOWED_STEPS_INVALID = "FATAL: Allowed steps must be greater than zero.";
	public static final String _CONFIG_INVALID = "FATAL: OTP configuration is invalid.";
	public static final String _CONFIG_NULL = "FATAL: OTP configuration must not be null.";
	public static final String _ALGORITHM_NULL = "FATAL: OTP algorithm must not be null.";
	public static final String _DIGITS_INVALID = "FATAL: OTP digits must be 6 or 8.";
	public static final String _PERIOD_INVALID = "FATAL: OTP period must be greater than zero.";
	public static final String _LOOKAHEAD_INVALID = "FATAL: HOTP lookAhead must be greater than or equal to zero.";
	public static final String _HMAC_FAILED = "FATAL: Error computing HMAC.";
	public static final String _ERROR_GETTING_URL = "FATAL: Error in getting URL for Google Authenticator";
	public static final String _ERROR_GETTING_QRCODE = "FATAL: Error in getting QRCode for Google Authenticator";
	public static final String _ERROR_CREATING_OTP_INSTANCE = "FATAL: Error creating instance of OTPImplementation";
	public static final String _ERROR_CREATING_HOTP_INSTANCE = "FATAL: Error creating instance of HOTPImplementation";
	
	private static final long serialVersionUID = 5180940924673148608L;

	/**
	 * Class Constructor
	 * 
	 * @param errorMessage	the String of the error message
	 */
	public OTPGenericException( String errorMessage )
	{
		super( errorMessage );
	}
	
	/**
	 * Class Constructor
	 * 
	 * @param errorMessage	the String of the error message
	 * @param err			the Throwable being wrapped
	 */
	public OTPGenericException( String errorMessage, Throwable err ) {
	    super( errorMessage, err );
	}
	
	
}
