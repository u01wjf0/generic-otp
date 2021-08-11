package com.wfraser.security.otp;

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
	private int allowedSteps = 3;

	/**
	 * Private Constructor to prevent instantiation
	 */
	private OTPUserCredentialProvider() {

	}

	/**
	 * Private Constructor to prevent instantiation
	 * 
	 * @param secretKey		the String representing the secret key (base32)
	 * @param userID		the String for the User's ID 
	 * @param company		the String for the company name
	 * @param steps			the int for the number of 30s steps to be valid for
	 */
	private OTPUserCredentialProvider(String secretKey, String userID, String company, int steps) {
		this.secretKey = secretKey;
		this.userID = userID;
		allowedSteps = steps;
		this.company = company;
	}

	/**
	 * Static method for creating a OTPUserCredentialProvider for the use with 
	 * the Google Authenticator APP 
	 * 
	 * @param secretKey		the String representing the secret key (base32)
	 * @param userID		the String for the User's ID 
	 * @param company		the String for the company name
	 * @param steps			the int for the number of 30s steps to be valid for
	 * 
	 * @return 				instance of OTPUserCredentialProvider with configuration
	 * 
	 * throws 				OTPGenericException when the secretKey is blank (as this is needed and unique for a user
	 */
	public static OTPUserCredentialProvider createAuthenticatorUserObject(String secretKey, String userID, String company, int steps) throws OTPGenericException {
		if(secretKey == null || secretKey.equals(""))
			throw new OTPGenericException(OTPGenericException._USER_AND_KEY_BLANK);
		OTPUserCredentialProvider user = new OTPUserCredentialProvider(secretKey, userID, company, steps);
		return user;
	}

	/**
	 * Static method for creating OTPUserCredentialProvider for generating just
	 * OTP codes.
	 * 
	 * @param userID		the String for the User's ID 
	 * @param steps			the int for the number of 30s steps to be valid for
	 * @return
	 */
	public static OTPUserCredentialProvider createBasicUserObject(String userID, int steps) {
		OTPUserCredentialProvider user = new OTPUserCredentialProvider(OTPUtils.generateSecretKey(), userID, null, steps);
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