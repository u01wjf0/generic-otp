package com.wfraser.security.otp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.wfraser.security.exceptions.OTPGenericException;

/**
 * Counter-based OTP (HOTP) implementation based on RFC 4226.
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
 * @author 	William Fraser
 * @version	2.0
 * @since 	2.0
 */
public final class HOTPImplementation {

	private final OTPUserCredentialProvider authenticatingUser;
	private final byte[] secretKeyBytes;
	private final OTPConfig otpConfig;

	public static HOTPImplementation createInstance( OTPUserCredentialProvider authUser ) throws OTPGenericException {
		return createInstance( authUser, OTPConfig.defaults() );
	}

	public static HOTPImplementation createInstance( OTPUserCredentialProvider authUser, OTPConfig config ) throws OTPGenericException {
		try {
			return new HOTPImplementation( authUser, config );
		} catch ( InvalidKeyException | NoSuchAlgorithmException e ) {
			throw new OTPGenericException( OTPGenericException._ERROR_CREATING_HOTP_INSTANCE, e );
		} catch ( IllegalArgumentException e ) {
			throw new OTPGenericException( OTPGenericException._CONFIG_INVALID, e );
		}
	}

	/**
	 * Creates an instance using {@link OTPUserDetails}.
	 *
	 * @param authUser {@link OTPUserDetails} preconfigured
	 * @return instance of {@link HOTPImplementation}
	 * @throws OTPGenericException
	 */
	public static HOTPImplementation createInstance( OTPUserDetails authUser ) throws OTPGenericException {
		return createInstance( authUser, OTPConfig.defaults() );
	}

	/**
	 * Creates an instance using {@link OTPUserDetails} and {@link OTPConfig}.
	 *
	 * @param authUser {@link OTPUserDetails} preconfigured
	 * @param config {@link OTPConfig} for algorithm/digits configuration
	 * @return instance of {@link HOTPImplementation}
	 * @throws OTPGenericException
	 */
	public static HOTPImplementation createInstance( OTPUserDetails authUser, OTPConfig config ) throws OTPGenericException {
		return createInstance( OTPUserCredentialProvider.from(authUser), config );
	}

	/**
	 * Generates an HOTP based on RFC 4226.
	 * 
	 * @param counter counter value
	 * @return String representing the configured digit code
	 */
	public String getOTP(long counter)
	{
		return getOTP( getCounterAsBytes( counter ), otpConfig.getDigits() );
	}

	/**
	 * Validates a given code against a counter value, with optional look-ahead.
	 * 
	 * @param input String of the code to compare
	 * @param counter current counter value
	 * @param lookAhead number of future counters to check
	 * 
	 * @return 	True - a valid code has been used
	 * 			False - a valid code was not used
	 */
	public Boolean validate(String input, long counter, int lookAhead) {
		if (input == null) {
			return false;
		}
		if (lookAhead < 0)
			throw new IllegalArgumentException(OTPGenericException._LOOKAHEAD_INVALID);
		input = padding(input, otpConfig.getDigits());
		long lastCounter = counter + lookAhead;
		while( counter <= lastCounter )
		{
			String currentOTP = getOTP( getCounterAsBytes( counter ), otpConfig.getDigits() );
			if( constantTimeEquals( input, currentOTP ) )
			{
				return true;
			}
			counter++;
		}
		return false;
	}

	/**
	 * Private constructor to prevent instantiation.
	 *
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private HOTPImplementation() throws NoSuchAlgorithmException, InvalidKeyException {
		this.authenticatingUser = null;
		this.secretKeyBytes = null;
		this.otpConfig = OTPConfig.defaults();
	}

	/**
	 * Private constructor to prevent instantiation.
	 *
	 * @param authUser {@link OTPUserCredentialProvider} for configuration
	 * @param config {@link OTPConfig} for algorithm/digits configuration
	 *
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws OTPGenericException
	 */
	private HOTPImplementation( OTPUserCredentialProvider authUser, OTPConfig config ) throws NoSuchAlgorithmException, InvalidKeyException, OTPGenericException {
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
	 * Converts the counter value into a byte array for processing.
	 *
	 * @param counter counter value
	 * @return byte[] of the counter value
	 */
	private byte[] getCounterAsBytes(long counter) {
		return ByteBuffer.allocate(8).putLong(counter).array();
	}

	/**
	 * Runs the configured HMAC algorithm.
	 *
	 * @param text byte[] to be processed
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
	 * Generates an HOTP from counter bytes.
	 *
	 * @param counterBytes bytes representing the counter
	 * @param digits number of digits
	 * @return code representing the configured digits
	 */
	private String getOTP( final byte[] counterBytes, final int digits )
	{
		String otp = "";
		final byte[] hash = doHMAC( counterBytes );
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
	 * Pads a given string with leading zeros.
	 *
	 * @param input String for padding
	 * @param length target length
	 * @return padded string
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
