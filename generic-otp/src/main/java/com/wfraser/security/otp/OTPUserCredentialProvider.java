package com.wfraser.security.otp;

import java.math.BigInteger;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.utils.OTPUtils;

/**
 * OTPUserCredentialProvider is the object to be added to users
 * when looking to add OTP ability to a user
 *  
 * 
 * @author 	William Fraser
 * @version	%I%, %G%
 * @since 	1.0
 *
 */
public class OTPUserCredentialProvider {

	private String secretKey; 
	private String userID;
	private String company; 
	private int allowedSteps;

	/**
	 * Private Constructor to prevent instantiation
	 */
	private OTPUserCredentialProvider() {

	}

	/**
	 * Private Constructor to prevent instantiation
	 * 
	 * @param secretKey		the String representing the secret key (base32 as String)
	 * @param userID		the String for the User's ID 
	 * @param company		the String for the company name
	 * @param steps			the int for the number of 30s steps to be valid for
	 * @throws OTPGenericException 
	 */
	private OTPUserCredentialProvider( final String secretKey, final String userID, final String company, final int steps ) throws OTPGenericException {
		if( secretKey == null || secretKey.equals( "" ) || userID == null || userID.equals( "" ) )
			throw new OTPGenericException( OTPGenericException._USER_AND_KEY_BLANK );
		this.secretKey = secretKey;
		this.userID = userID;
		allowedSteps = steps;
		this.company = company;
	}

	/**
	 * Static method for creating a OTPUserCredentialProvider for the use with 
	 * the Google Authenticator APP 
	 * 
	 * @param secretKey		the String representing the secret key (base32 as String)
	 * @param userID		the String for the User's ID 
	 * @param company		the String for the company name
	 * @param steps			the int for the number of 30s steps to be valid for
	 * 
	 * @return 				instance of OTPUserCredentialProvider with configuration
	 * 
	 * throws 				OTPGenericException when the secretKey is blank (as this is needed and unique for a user
	 * @throws OTPGenericException 
	 */
	public static OTPUserCredentialProvider createAuthenticatorUserObject( final String secretKey, final String userID, final String company, final int steps ) throws OTPGenericException {
		if( company == null || company.equals("") )
			throw new OTPGenericException( OTPGenericException._USER_AND_KEY_BLANK );
		var user = new OTPUserCredentialProvider( secretKey, userID, company, steps );
		return user;
	}

	/**
	 * Static method for creating OTPUserCredentialProvider for generating just
	 * OTP codes.
	 * 
	 * @param userID		the String for the User's ID 
	 * @param steps			the int for the number of 30s steps to be valid for
	 * 
	 * @return				instance of OTPUserCredentialProvider with configuration
	 * @throws OTPGenericException 
	 */
	public static OTPUserCredentialProvider createBasicUserObject( final String userID, final int steps ) throws OTPGenericException {
		var user = new OTPUserCredentialProvider( OTPUtils.generateSecretKey(), userID, null, steps );
		return user;
	}

	/**
	 * Static method for creating OTPUserCredentialProvider for generating a new Google Auth User
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
	 * Getter for Secret Key
	 * 
	 * @return the String representing the key in base32
	 */
	public String getSecretKey() {
		return secretKey;
	}

	/**
	 * Getter for the secret key as a byte array
	 * 
	 * As key will be handled in Base32 String this is needed to convert back to
	 * array for processing
	 * 
	 * @return secret key in a form usable by the OTPImplementation
	 */
	public byte[] getSecretByteArray() {
		var base = new Base32();
		var base32 = base.decode(secretKey);
		var hexString = Hex.encodeHexString(base32);
		var hexToByte = new BigInteger("10" + hexString, 16).toByteArray();
		var keyBytes = new byte[hexToByte.length - 1];
		System.arraycopy(hexToByte, 1, keyBytes, 0, keyBytes.length);
		return keyBytes;
	}

	/**
	 * Getter for UserID
	 * 
	 * @return the String of the User's ID
	 */
	public String getUserID() {
		return userID;
	}

	/**
	 * Getter for the allowed steps
	 * 
	 * @return the int of the allowedSteps
	 */
	public int getAllowedSteps() {
		return allowedSteps;
	}

	/**
	 * Getter for the company name
	 * 
	 * @return the String of the company name
	 */
	public String getCompany() {
		return company;
	}

}