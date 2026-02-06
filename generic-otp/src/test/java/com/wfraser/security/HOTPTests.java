package com.wfraser.security;

import static org.junit.Assert.*;

import org.junit.Test;

import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.HOTPImplementation;
import com.wfraser.security.otp.OTPConfig;
import com.wfraser.security.otp.OTPUserCredentialProvider;

import com.wfraser.security.test.entities.OTPUserImpl;
import com.wfraser.security.test.entities.OTPUserDetailsImpl;

/**
 * Test menu:
 * - RFC 4226 HOTP vectors
 * - HOTP validation with look-ahead
 * - HOTP null input and error handling
 * - HOTP custom config behavior
 */
public class HOTPTests {

	/**
	 * Verifies RFC 4226 HOTP test vectors.
	 */
	@Test
	public void testRfc4226HotpVectors() throws Exception
	{
		String secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		OTPUserCredentialProvider provider = OTPUserCredentialProvider
				.createAuthenticatorUserObject(secretBase32, "USERA", "COMPANYA", 1);
		HOTPImplementation hotp = HOTPImplementation.createInstance(provider);
		int[] expected = new int[] {
				755224, 287082, 359152, 969429, 338314,
				254676, 287922, 162583, 399871, 520489
		};
		for (int counter = 0; counter < expected.length; counter++) {
			String actual = hotp.getOTP(counter);
			assertEquals(String.format("%06d", expected[counter]), actual);
		}
	}

	/**
	 * Verifies look-ahead behavior for HOTP validation.
	 */
	@Test
	public void testHotpValidationLookAhead() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(false, false);
		HOTPImplementation hotp = HOTPImplementation.createInstance(user.getProvider());
		String otpAtThree = hotp.getOTP(3);
		assertTrue(hotp.validate(otpAtThree, 0, 5));
		assertFalse(hotp.validate(otpAtThree, 0, 2));
	}

	/**
	 * Verifies null input returns false.
	 */
	@Test
	public void testHotpValidationNullInputReturnsFalse() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(false, false);
		HOTPImplementation hotp = HOTPImplementation.createInstance(user.getProvider());
		assertFalse(hotp.validate(null, 0, 0));
	}

	/**
	 * Verifies negative look-ahead is rejected.
	 */
	@Test
	public void testHotpValidationNegativeLookAhead() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(false, false);
		HOTPImplementation hotp = HOTPImplementation.createInstance(user.getProvider());
		try {
			hotp.validate(hotp.getOTP(0), 0, -1);
			fail("Expected IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("lookAhead"));
		}
	}

	/**
	 * Verifies HOTP with custom config settings.
	 */
	@Test
	public void testHotpWithCustomConfig() throws OTPGenericException
	{
		OTPConfig config = OTPConfig.builder()
				.algorithm(OTPConfig.Algorithm.SHA512)
				.digits(8)
				.periodSeconds(30)
				.build();
		OTPUserImpl user = new OTPUserImpl(false, false);
		HOTPImplementation hotp = HOTPImplementation.createInstance(user.getProvider(), config);
		String otp = hotp.getOTP(7);
		assertEquals(8, otp.length());
		assertTrue(hotp.validate(otp, 7, 0));
	}

	/**
	 * Verifies createInstance works with OTPUserDetails.
	 */
	@Test
	public void testCreateInstanceWithUserDetails() throws OTPGenericException
	{
		String secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		OTPUserDetailsImpl details = new OTPUserDetailsImpl(secretBase32, "USERA", "COMPANYA", 1);
		HOTPImplementation hotp = HOTPImplementation.createInstance(details);
		assertTrue(hotp.validate(hotp.getOTP(0), 0, 0));
	}

	/**
	 * Verifies createInstance rejects null config.
	 */
	@Test
	public void testCreateInstanceNullConfig()
	{
		try {
			HOTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider(), null);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies createInstance rejects null user details.
	 */
	@Test
	public void testCreateInstanceNullUserDetails()
	{
		try {
			HOTPImplementation.createInstance((com.wfraser.security.otp.OTPUserDetails) null);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies negative look-ahead error message is consistent.
	 */
	@Test
	public void testHotpNegativeLookAheadErrorMessage() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(false, false);
		HOTPImplementation hotp = HOTPImplementation.createInstance(user.getProvider());
		try {
			hotp.validate(hotp.getOTP(0), 0, -5);
			fail("Expected IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("lookAhead"));
		}
	}
}
