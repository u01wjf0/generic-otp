package com.wfraser.security;

import org.junit.Test;

import com.wfraser.security.otp.HOTPImplementation;
import com.wfraser.security.otp.OTPConfig;
import com.wfraser.security.test.entities.OTPUserImpl;

/**
 * Test menu:
 * - Runtime exception paths (IllegalArgumentException)
 */
public class RuntimeExceptionTests {

	/**
	 * Verifies invalid digits throw IllegalArgumentException.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testOtpConfigInvalidDigitsThrows() {
		OTPConfig.builder().digits(7).build();
	}

	/**
	 * Verifies invalid period throws IllegalArgumentException.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testOtpConfigInvalidPeriodThrows() {
		OTPConfig.builder().periodSeconds(0).build();
	}

	/**
	 * Verifies null algorithm throws IllegalArgumentException.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testOtpConfigNullAlgorithmThrows() {
		OTPConfig.builder().algorithm(null).build();
	}

	/**
	 * Verifies negative look-ahead throws IllegalArgumentException.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testHotpNegativeLookAheadThrows() throws Exception {
		HOTPImplementation hotp = HOTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		hotp.validate(hotp.getOTP(0), 0, -1);
	}
}
