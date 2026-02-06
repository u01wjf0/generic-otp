package com.wfraser.security.otp;

import java.math.BigInteger;
import java.util.Locale;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.utils.OTPUtils;

/**
 * User credential provider for OTP/TOTP configuration.
 *  
 * 
 * @author 	William Fraser
 * @version	2.0
 * @since 	1.0
 *
 */
public class OTPUserCredentialProvider implements OTPUserDetails {

	private static final Pattern BASE32_PATTERN = Pattern.compile("^[A-Z2-7]+={0,6}$");

	private String secretKey; 
	private String userID;
	private String company; 
	private int allowedSteps;

	/**
	 * Private constructor to prevent instantiation.
	 */
	private OTPUserCredentialProvider() {

	}

	/**
	 * Private constructor to prevent instantiation.
	 * 
	 * @param secretKey		the String representing the secret key (base32 as String)
	 * @param userID		the String for the User's ID 
	 * @param company		the String for the company name
	 * @param steps			the number of 30s steps to be valid for
	 * @throws OTPGenericException 
	 */
	private OTPUserCredentialProvider( final String secretKey, final String userID, final String company, final int steps ) throws OTPGenericException {
		if( secretKey == null || secretKey.equals( "" ) || userID == null || userID.equals( "" ) )
			throw new OTPGenericException( OTPGenericException._USER_AND_KEY_BLANK );
		if (!isValidBase32Secret(secretKey))
			throw new OTPGenericException( OTPGenericException._KEY_INVALID );
		if (steps <= 0)
			throw new OTPGenericException( OTPGenericException._ALLOWED_STEPS_INVALID );
		this.secretKey = normalizeSecretKey(secretKey);
		this.userID = userID;
		allowedSteps = steps;
		this.company = company;
	}

	/**
	 * Creates an OTPUserCredentialProvider for Google Authenticator.
	 * 
	 * @param secretKey		the String representing the secret key (base32 as String)
	 * @param userID		the String for the User's ID 
	 * @param company		the String for the company name
	 * @param steps			the number of 30s steps to be valid for
	 * 
	 * @return 				instance of OTPUserCredentialProvider with configuration
	 * 
	 * throws 				OTPGenericException when the secretKey is blank (as this is needed and unique for a user)
	 * @throws OTPGenericException 
	 */
	public static OTPUserCredentialProvider createAuthenticatorUserObject( final String secretKey, final String userID, final String company, final int steps ) throws OTPGenericException {
		if( company == null || company.equals("") )
			throw new OTPGenericException( OTPGenericException._USER_AND_KEY_BLANK );
		var user = new OTPUserCredentialProvider( secretKey, userID, company, steps );
		return user;
	}

	/**
	 * Creates an OTPUserCredentialProvider from explicit secret details.
	 *
	 * @param secretKey the Base32 secret key
	 * @param userID the user's ID
	 * @param company the company/issuer name (may be null)
	 * @param steps number of allowed steps
	 * @return instance of OTPUserCredentialProvider with configuration
	 * @throws OTPGenericException
	 */
	public static OTPUserCredentialProvider createUserObject( final String secretKey, final String userID, final String company, final int steps ) throws OTPGenericException {
		return new OTPUserCredentialProvider( secretKey, userID, company, steps );
	}

	/**
	 * Creates an OTPUserCredentialProvider for generating OTP codes only.
	 * 
	 * @param userID		the String for the User's ID 
	 * @param steps			the number of 30s steps to be valid for
	 * 
	 * @return				instance of OTPUserCredentialProvider with configuration
	 * @throws OTPGenericException 
	 */
	public static OTPUserCredentialProvider createBasicUserObject( final String userID, final int steps ) throws OTPGenericException {
		var user = new OTPUserCredentialProvider( OTPUtils.generateSecretKey(), userID, null, steps );
		return user;
	}

	/**
	 * Creates an OTPUserCredentialProvider for a new Google Authenticator user.
	 * 
	 * @param userID		the String for the User's ID 
	 * @param steps			the int for the number of 30s steps to be valid for
	 * @param companyName	the String for the Users company name
	 * 
	 * @return				instance of OTPUserCredentialProvider with configuration 
	 */
	public static OTPUserCredentialProvider createNewAuthenticatorUserObject( final String userID, final int steps, final String companyName ) throws OTPGenericException {
		if( companyName == null || companyName.equals("") )
			throw new OTPGenericException( OTPGenericException._USER_AND_KEY_BLANK );
		var user = new OTPUserCredentialProvider( OTPUtils.generateSecretKey(), userID, companyName, steps );
		return user;
	}

	/**
	 * Creates a provider from an {@link OTPUserDetails} instance.
	 *
	 * @param userDetails user details
	 * @return provider instance
	 * @throws OTPGenericException
	 */
	public static OTPUserCredentialProvider from(OTPUserDetails userDetails) throws OTPGenericException {
		if (userDetails == null) {
			throw new OTPGenericException( OTPGenericException._USER_AND_KEY_BLANK );
		}
		if (userDetails instanceof OTPUserCredentialProvider) {
			return (OTPUserCredentialProvider) userDetails;
		}
		return createUserObject(
				userDetails.getSecretKey(),
				userDetails.getUserID(),
				userDetails.getCompany(),
				userDetails.getAllowedSteps()
		);
	}

	/**
	 * Getter for secret key.
	 * 
	 * @return the String representing the key in base32
	 */
	public String getSecretKey() {
		return secretKey;
	}

	/**
	 * Getter for the secret key as a byte array.
	 * 
	 * As key will be handled in Base32 String this is needed to convert back to
	 * array for processing.
	 * 
	 * @return secret key in a form usable by the OTPImplementation
	 */
	public byte[] getSecretByteArray() {
		var base = new Base32();
		var normalizedSecret = normalizeSecretKey(secretKey);
		var base32 = base.decode(normalizedSecret);
		var hexString = Hex.encodeHexString(base32);
		var hexToByte = new BigInteger("10" + hexString, 16).toByteArray();
		var keyBytes = new byte[hexToByte.length - 1];
		System.arraycopy(hexToByte, 1, keyBytes, 0, keyBytes.length);
		return keyBytes;
	}

	/**
	 * Getter for user ID.
	 * 
	 * @return the String of the user's ID
	 */
	public String getUserID() {
		return userID;
	}

	/**
	 * Getter for allowed steps.
	 * 
	 * @return the int of the allowedSteps
	 */
	public int getAllowedSteps() {
		return allowedSteps;
	}

	/**
	 * Getter for company name.
	 * 
	 * @return the String of the company name
	 */
	public String getCompany() {
		return company;
	}

	/**
	 * Validates a Base32 secret key.
	 *
	 * @param secret secret key
	 * @return true when valid
	 */
	private static boolean isValidBase32Secret(String secret) {
		String normalized = normalizeSecretKey(secret);
		if (normalized.isEmpty()) {
			return false;
		}
		if (!BASE32_PATTERN.matcher(normalized).matches()) {
			return false;
		}
		Base32 base32 = new Base32();
		byte[] decoded = base32.decode(normalized);
		return decoded != null && decoded.length > 0;
	}

	/**
	 * Normalizes a secret key for storage/decoding.
	 *
	 * @param secret secret key
	 * @return normalized secret key
	 */
	private static String normalizeSecretKey(String secret) {
		return secret.replaceAll("\\s+", "").toUpperCase(Locale.US);
	}

}
