package com.wfraser.security.otp;

/**
 * Interface for user credential details required by OTP generators.
 *
 * @since 2.0
 */
public interface OTPUserDetails {

	/**
	 * @return Base32 secret key
	 */
	String getSecretKey();

	/**
	 * @return user identifier
	 */
	String getUserID();

	/**
	 * @return company/issuer name (may be null for non-authenticator use)
	 */
	String getCompany();

	/**
	 * @return number of allowed steps
	 */
	int getAllowedSteps();
}
