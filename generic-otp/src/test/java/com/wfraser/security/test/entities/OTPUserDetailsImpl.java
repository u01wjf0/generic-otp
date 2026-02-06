package com.wfraser.security.test.entities;

import com.wfraser.security.otp.OTPUserDetails;

/**
 * Simple OTPUserDetails implementation for tests.
 */
public class OTPUserDetailsImpl implements OTPUserDetails {

	private final String secretKey;
	private final String userID;
	private final String company;
	private final int allowedSteps;

	public OTPUserDetailsImpl(String secretKey, String userID, String company, int allowedSteps) {
		this.secretKey = secretKey;
		this.userID = userID;
		this.company = company;
		this.allowedSteps = allowedSteps;
	}

	@Override
	public String getSecretKey() {
		return secretKey;
	}

	@Override
	public String getUserID() {
		return userID;
	}

	@Override
	public String getCompany() {
		return company;
	}

	@Override
	public int getAllowedSteps() {
		return allowedSteps;
	}
}
