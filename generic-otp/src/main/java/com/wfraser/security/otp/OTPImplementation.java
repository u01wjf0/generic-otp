package com.wfraser.security.otp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.digest.HmacAlgorithms;

import com.wfraser.security.exceptions.OTPGenericException;

/**
 * OTPImplementation is the core implementation class
 * for all the OTP functionality.
 * 
 * Public methods include
 * <ul>
 * <li> <code>createInstance()</code>
 * <li> <code>getOTP()</code>
 * <li> <code>validate()</code>
 * </ul>
 * 
 * This class is used by calling the static createInstance
 * 
 * 
 * @author 	William Frasewr
 * @version	%I%, %G%
 * @since 	1.0
 *
 */
public final class OTPImplementation {


	private final String _OTP_METHOD_ALGO = HmacAlgorithms.HMAC_SHA_1.getName();
	private final OTPUserCredentialProvider authenticatingUser;
	private final Mac mac;

	/**
	 * Creates an instance of {@link OTPImplementation} using a given {@link OTPUserCredentialProvider}
	 * 
	 * @param authUser		{@link OTPUserCredentialProvider} preconfigured 
	 * 
	 * @return instance of {@link OTPImplementation} preconfigured for OTP generation and validation 
	 * 
	 * @throws OTPGenericException 
	 */
	public static OTPImplementation createInstance( OTPUserCredentialProvider authUser ) throws OTPGenericException {

		try {
			return new OTPImplementation( authUser );
		} catch ( InvalidKeyException | NoSuchAlgorithmException e ) {
			throw new OTPGenericException( OTPGenericException._ERROR_CREATING_OTP_INSTANCE, e );
		}
	}

	/**
	 * Generates an OTP based on the RFC 6238 and RFC 4226
	 * 
	 * @return String representing 6 digit code
	 */
	public String getOTP()
	{
		return getOTP( getStepAsBytes( getCurrentStep() ) );
	}
	
	/**
	 * Validates a given code against the valid generated codes
	 * 
	 * @param input String of the code to compare
	 * 
	 * @return 	True - A valid code has been used
	 * 			False - A valid code was not used
	 */
	public Boolean validate(String input) {
		input = padding(input, 6);
		long step = getCurrentStep(); 
		long lastStep = step - authenticatingUser.getAllowedSteps() +1;
		while( lastStep <= step )
		{
			String currentOTP = getOTP( getStepAsBytes( lastStep ) );
			if( input.compareTo( currentOTP ) ==0 )
			{
				return true;
			}
			lastStep++;
		}
		return false;
	}

	/**
	 * Private constructor to prevent instantiation
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private OTPImplementation() throws NoSuchAlgorithmException, InvalidKeyException {
		this.authenticatingUser = null;
		this.mac = null;
	}

	/**
	 * Private constructor to prevent instantiation
	 * takes {@link OTPUserCredentialProvider} to configure the implimentation
	 * with the required user details
	 * 
	 * @param authUser		{@link OTPUserCredentialProvider} for configuration
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws OTPGenericException
	 */
	private OTPImplementation( OTPUserCredentialProvider authUser ) throws NoSuchAlgorithmException, InvalidKeyException, OTPGenericException {
		this.authenticatingUser = authUser;
		mac = Mac.getInstance( _OTP_METHOD_ALGO );
		if( this.authenticatingUser != null && this.authenticatingUser.getSecretKey() != null ) 
		{
			mac.init(new SecretKeySpec(this.authenticatingUser.getSecretByteArray(), "RAW"));
		} else {
			throw new OTPGenericException(OTPGenericException._USER_AND_KEY_BLANK);
		}
	}

	/**
	 * Gets the current 30s step in time 
	 * from the beginning of the epoc
	 * 
	 * @return long of the time step
	 */
	private long getCurrentStep() {
		return System.currentTimeMillis() / 30000;
	}

	/**
	 * Converts the long form of step into a byte array needed for processing
	 * 
	 * @param step long of the time step
	 * 
	 * @return byte[] of the time step for processing
	 */
	private byte[] getStepAsBytes(long step) {
		String steps = Long.toHexString( step ).toUpperCase();
		steps = padding(steps, 16);
		final byte[] cleanupArray = new BigInteger( "10" + steps, 16 ).toByteArray();
		final byte[] stepAsByte = new byte[cleanupArray.length - 1];
		System.arraycopy( cleanupArray, 1, stepAsByte, 0, stepAsByte.length );
		return stepAsByte;
	}

	/**
	 * carry out the cryptographic function for HMAC SHA 1
	 * 
	 * @param text byte[] to be processed
	 * 
	 * @return byte[] representation of the hash
	 */
	private byte[] doHMACSHA1(final byte[] text)
	{
		return mac.doFinal( text );
	}

	/**
	 * Generate the OTP by
	 * 1) Call the hash function
	 * 2) Getting the relevant information from the hash to generate the OTP
	 * 3) Convert the value to a String
	 * 4) Pad the string to 6 chars 
	 * 
	 * @param stepsBytes - bytes representing the steps
	 * 
	 * @return 6 char representing the OTP
	 */
	private String getOTP( final byte[] stepsBytes )
	{
		String otp = "";
		final byte[] hash = doHMACSHA1( stepsBytes );
		final int offset = hash[hash.length - 1] & 0xf;
		final int binary = ( ( hash[offset] & 0x7f) << 24 ) 
				| ( ( hash[offset + 1] & 0xff ) << 16 ) 
				| ( ( hash[offset + 2] & 0xff ) << 8 ) 
				| ( hash[offset + 3] & 0xff );
		final int otpVal = binary % 1000000;

		otp = Integer.toString( otpVal );
		otp = padding(otp, 6);
		return otp;
	}

	/**
	 * Helper method designed to pad a given string by a given length
	 * Uses "0" for padding
	 * 
	 * @param input String for padding
	 * @param length int of end length
	 * 
	 * @return String with padding if required
	 */
	private String padding(String input, int length)
	{
		while ( input.length() < length ) {
			input = "0" + input;
		}
		return input;
	}
}
