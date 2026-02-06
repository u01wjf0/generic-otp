package com.wfraser.security.otp;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.wfraser.security.exceptions.OTPGenericException;

/**
 * Core implementation class for OTP functionality.
 * 
 * Public methods include
 * <ul>
 * <li> <code>createInstance()</code>
 * <li> <code>getOTP()</code>
 * <li> <code>validate()</code>
 * </ul>
 * 
 * This class is used by calling the static createInstance method.
 * 
 * 
 * @author 	William Fraser
 * @version	2.0
 * @since 	1.0
 *
 */
public final class OTPImplementation {


	private final OTPUserCredentialProvider authenticatingUser;
	private final byte[] secretKeyBytes;
	private final OTPConfig otpConfig;

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
			return new OTPImplementation( authUser, OTPConfig.defaults() );
		} catch ( InvalidKeyException | NoSuchAlgorithmException e ) {
			throw new OTPGenericException( OTPGenericException._ERROR_CREATING_OTP_INSTANCE, e );
		} catch ( IllegalArgumentException e ) {
			throw new OTPGenericException( OTPGenericException._CONFIG_INVALID, e );
		}
	}

	/**
	 * Creates an instance of {@link OTPImplementation} using a given {@link OTPUserCredentialProvider}
	 * and {@link OTPConfig}
	 * 
	 * @param authUser		{@link OTPUserCredentialProvider} preconfigured 
	 * @param config		{@link OTPConfig} for algorithm/digits/period configuration
	 * 
	 * @return instance of {@link OTPImplementation} preconfigured for OTP generation and validation 
	 * 
	 * @throws OTPGenericException 
	 */
	public static OTPImplementation createInstance( OTPUserCredentialProvider authUser, OTPConfig config ) throws OTPGenericException {
		try {
			return new OTPImplementation( authUser, config );
		} catch ( InvalidKeyException | NoSuchAlgorithmException e ) {
			throw new OTPGenericException( OTPGenericException._ERROR_CREATING_OTP_INSTANCE, e );
		} catch ( IllegalArgumentException e ) {
			throw new OTPGenericException( OTPGenericException._CONFIG_INVALID, e );
		}
	}

	/**
	 * Creates an instance using {@link OTPUserDetails}.
	 *
	 * @param authUser {@link OTPUserDetails} preconfigured
	 * @return instance of {@link OTPImplementation}
	 * @throws OTPGenericException
	 */
	public static OTPImplementation createInstance( OTPUserDetails authUser ) throws OTPGenericException {
		return createInstance( authUser, OTPConfig.defaults() );
	}

	/**
	 * Creates an instance using {@link OTPUserDetails} and {@link OTPConfig}.
	 *
	 * @param authUser {@link OTPUserDetails} preconfigured
	 * @param config {@link OTPConfig} for algorithm/digits/period configuration
	 * @return instance of {@link OTPImplementation}
	 * @throws OTPGenericException
	 */
	public static OTPImplementation createInstance( OTPUserDetails authUser, OTPConfig config ) throws OTPGenericException {
		return createInstance( OTPUserCredentialProvider.from(authUser), config );
	}

	/**
	 * Generates an OTP based on RFC 6238 (TOTP).
	 * 
	 * @return String representing the configured digit code
	 */
	public String getOTP()
	{
		return getOTP( getStepAsBytes( getCurrentStep() ), otpConfig.getDigits() );
	}
	
	/**
	 * Validates a given code against the valid generated codes.
	 * 
	 * @param input String of the code to compare
	 * 
	 * @return 	True - a valid code has been used
	 * 			False - a valid code was not used
	 */
	public Boolean validate(String input) {
		if (input == null) {
			return false;
		}
		input = padding(input, otpConfig.getDigits());
		long step = getCurrentStep(); 
		long lastStep = step - authenticatingUser.getAllowedSteps() +1;
		while( lastStep <= step )
		{
			String currentOTP = getOTP( getStepAsBytes( lastStep ), otpConfig.getDigits() );
			if( constantTimeEquals( input, currentOTP ) )
			{
				return true;
			}
			lastStep++;
		}
		return false;
	}

	/**
	 * Private constructor to prevent instantiation.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private OTPImplementation() throws NoSuchAlgorithmException, InvalidKeyException {
		this.authenticatingUser = null;
		this.secretKeyBytes = null;
		this.otpConfig = OTPConfig.defaults();
	}

	/**
	 * Private constructor to prevent instantiation.
	 * Takes {@link OTPUserCredentialProvider} to configure the implementation
	 * with the required user details.
	 * 
	 * @param authUser		{@link OTPUserCredentialProvider} for configuration
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws OTPGenericException
	 */
	private OTPImplementation( OTPUserCredentialProvider authUser, OTPConfig config ) throws NoSuchAlgorithmException, InvalidKeyException, OTPGenericException {
		this.authenticatingUser = authUser;
		if (config == null)
			throw new IllegalArgumentException(OTPGenericException._CONFIG_NULL);
		this.otpConfig = config;
		if( this.authenticatingUser != null && this.authenticatingUser.getSecretKey() != null ) 
		{
			this.secretKeyBytes = this.authenticatingUser.getSecretByteArray();
		} else {
			throw new OTPGenericException(OTPGenericException._USER_AND_KEY_BLANK);
		}
	}

	/**
	 * Gets the current time step from the Unix epoch.
	 * 
	 * @return time step value
	 */
	private long getCurrentStep() {
		return System.currentTimeMillis() / ( otpConfig.getPeriodSeconds() * 1000L );
	}

	/**
	 * Converts the step value into the byte array required for processing.
	 * 
	 * @param step time step value
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
	 * Runs the configured HMAC algorithm.
	 * 
	 * @param text byte[] to be processed
	 * 
	 * @return byte[] representation of the hash
	 */
	private byte[] doHMAC(final byte[] text)
	{
		try {
			Mac mac = Mac.getInstance( otpConfig.getAlgorithm().getHmacName() );
			mac.init(new SecretKeySpec(secretKeyBytes, "RAW"));
			return mac.doFinal( text );
		} catch ( InvalidKeyException | NoSuchAlgorithmException e ) {
			throw new IllegalStateException(OTPGenericException._HMAC_FAILED, e);
		}
	}

	/**
	 * Generate the OTP by
	 * 1) Call the hash function
	 * 2) Extract the dynamic truncation value
	 * 3) Convert the value to a String
	 * 4) Pad the string to the configured digits
	 * 
	 * @param stepsBytes bytes representing the steps
	 * 
	 * @return code representing the configured digits
	 */
	private String getOTP( final byte[] stepsBytes, final int digits )
	{
		String otp = "";
		final byte[] hash = doHMAC( stepsBytes );
		final int offset = hash[hash.length - 1] & 0xf;
		final int binary = ( ( hash[offset] & 0x7f) << 24 ) 
				| ( ( hash[offset + 1] & 0xff ) << 16 ) 
				| ( ( hash[offset + 2] & 0xff ) << 8 ) 
				| ( hash[offset + 3] & 0xff );
		final int otpVal = binary % (int) Math.pow(10, digits);

		otp = Integer.toString( otpVal );
		otp = padding(otp, digits);
		return otp;
	}

	/**
	 * Helper method to pad a given string with leading zeros.
	 * 
	 * @param input String for padding
	 * @param length target length
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

	/**
	 * Compares two strings in constant time.
	 *
	 * @param left left value
	 * @param right right value
	 * @return true when equal
	 */
	private static boolean constantTimeEquals(String left, String right) {
		if (left == null || right == null) {
			return false;
		}
		byte[] leftBytes = left.getBytes(StandardCharsets.US_ASCII);
		byte[] rightBytes = right.getBytes(StandardCharsets.US_ASCII);
		return MessageDigest.isEqual(leftBytes, rightBytes);
	}
}
