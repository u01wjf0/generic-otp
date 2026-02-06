package com.wfraser.security;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Test;

import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.OTPConfig;
import com.wfraser.security.otp.OTPImplementation;
import com.wfraser.security.otp.OTPUserCredentialProvider;

import com.wfraser.security.test.entities.OTPUserImpl;
import com.wfraser.security.test.entities.OTPUserDetailsImpl;

/**
 * Test menu:
 * - Basic TOTP generation and validation
 * - Credential validation and secret normalization
 * - Time window boundary checks
 * - Configurable TOTP parameters and config validation
 */
public class TOTPTests {

	/**
	 * Verifies default OTP length is 6 digits.
	 */
	@Test
	public void testBasicOtpLength() throws OTPGenericException {
		OTPImplementation otp = OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		assertEquals(6, otp.getOTP().length());
	}

	/**
	 * Verifies validation succeeds for a fresh code.
	 */
	@Test
	public void testValidation() throws OTPGenericException
	{
		OTPImplementation otp = OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		String input = otp.getOTP();
		assertTrue(otp.validate(input));
	}

	/**
	 * Verifies createInstance works with OTPUserDetails.
	 */
	@Test
	public void testCreateInstanceWithUserDetails() throws OTPGenericException
	{
		String secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		OTPUserDetailsImpl details = new OTPUserDetailsImpl(secretBase32, "USERA", "COMPANYA", 1);
		OTPImplementation otp = OTPImplementation.createInstance(details);
		assertTrue(otp.validate(otp.getOTP()));
	}

	/**
	 * Verifies null input returns false.
	 */
	@Test
	public void testValidationNullInputReturnsFalse() throws OTPGenericException
	{
		OTPImplementation otp = OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		assertFalse(otp.validate(null));
	}

	/**
	 * Verifies invalid credential inputs are rejected.
	 */
	@Test
	public void testCredentialProviderValidation()
	{
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createBasicUserObject("", 1));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createBasicUserObject("USERA", 0));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createAuthenticatorUserObject("KEY", "USERA", "", 1));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createAuthenticatorUserObject("", "USERA", "COMPANYA", 1));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createAuthenticatorUserObject("INVALID!", "USERA", "COMPANYA", 1));
	}

	/**
	 * Verifies secrets are normalized on creation.
	 */
	@Test
	public void testSecretNormalizationIsApplied() throws OTPGenericException
	{
		String secretBase32 = " gezdgnbvgy3tqojqgez dgnbvgy3tqojq ";
		OTPUserCredentialProvider provider = OTPUserCredentialProvider
				.createAuthenticatorUserObject(secretBase32, "USERA", "COMPANYA", 1);
		assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", provider.getSecretKey());
	}

	/**
	 * Verifies the validation window includes current step and excludes previous when steps=1.
	 */
	@Test
	public void testValidationWindowBounds() throws OTPGenericException
	{
		OTPUserCredentialProvider provider = OTPUserCredentialProvider
				.createBasicUserObject("USERA", 1);
		OTPImplementation otp = OTPImplementation.createInstance(provider);
		boolean verified = false;
		for (int attempt = 0; attempt < 2; attempt++) {
			long step = System.currentTimeMillis() / 30000;
			String currentOtp = TestHelpers.computeOtp(provider, step);
			String previousOtp = TestHelpers.computeOtp(provider, step - 1);
			boolean currentValid = otp.validate(currentOtp);
			boolean previousValid = otp.validate(previousOtp);
			long stepAfter = System.currentTimeMillis() / 30000;
			if (step == stepAfter) {
				assertTrue(currentValid);
				assertFalse(previousValid);
				verified = true;
				break;
			}
		}
		if (!verified) {
			fail("Step changed during validation; retry failed");
		}
	}

	/**
	 * Verifies leading zero padding for OTPs.
	 */
	@Test
	public void testOtpLeadingZeroPadding() throws Exception
	{
		String secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		OTPUserCredentialProvider provider = OTPUserCredentialProvider
				.createAuthenticatorUserObject(secretBase32, "USERA", "COMPANYA", 1);
		long stepWithLeadingZero = TestHelpers.findStepWithLeadingZero(provider, 0, 200000);
		String actual = TestHelpers.computeOtp(provider, stepWithLeadingZero);
		assertEquals(6, actual.length());
		assertTrue(actual.startsWith("0"));
	}

	/**
	 * Verifies Base32 decoding matches known ASCII bytes.
	 */
	@Test
	public void testSecretKeyConversion() throws OTPGenericException
	{
		String secretAscii = "12345678901234567890";
		String secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		OTPUserCredentialProvider provider = OTPUserCredentialProvider
				.createAuthenticatorUserObject(secretBase32, "USERA", "COMPANYA", 1);
		byte[] expected = secretAscii.getBytes(StandardCharsets.US_ASCII);
		assertTrue(Arrays.equals(expected, provider.getSecretByteArray()));
	}

	/**
	 * Verifies configurable SHA256/8-digit OTP validation.
	 */
	@Test
	public void testConfigurableOtpSha256Digits8() throws OTPGenericException
	{
		OTPConfig config = OTPConfig.builder()
				.algorithm(OTPConfig.Algorithm.SHA256)
				.digits(8)
				.periodSeconds(30)
				.build();
		OTPUserImpl user = new OTPUserImpl(false, false);
		OTPImplementation otp = OTPImplementation.createInstance(user.getProvider(), config);
		String input = otp.getOTP();
		assertEquals(8, input.length());
		assertTrue(otp.validate(input));
	}

	/**
	 * Verifies configurable 60-second period OTP validation.
	 */
	@Test
	public void testConfigurableOtpPeriod60() throws OTPGenericException
	{
		OTPConfig config = OTPConfig.builder()
				.algorithm(OTPConfig.Algorithm.SHA1)
				.digits(6)
				.periodSeconds(60)
				.build();
		OTPUserImpl user = new OTPUserImpl(false, false);
		OTPImplementation otp = OTPImplementation.createInstance(user.getProvider(), config);
		String input = otp.getOTP();
		assertTrue(otp.validate(input));
	}

	/**
	 * Verifies config validation failures.
	 */
	@Test
	public void testConfigValidation()
	{
		try {
			OTPConfig.builder().digits(7).build();
			fail("Expected IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("digits"));
		}
		try {
			OTPConfig.builder().periodSeconds(0).build();
			fail("Expected IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("period"));
		}
		try {
			OTPConfig.builder().algorithm(null).build();
			fail("Expected IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("algorithm"));
		}
	}

	/**
	 * Verifies createInstance rejects null config.
	 */
	@Test
	public void testCreateInstanceNullConfig()
	{
		try {
			OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider(), null);
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
			OTPImplementation.createInstance((com.wfraser.security.otp.OTPUserDetails) null);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies createUserObject rejects invalid parameters.
	 */
	@Test
	public void testCreateUserObjectInvalidInputs()
	{
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createUserObject("", "USERA", "COMPANYA", 1));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createUserObject("INVALID!", "USERA", "COMPANYA", 1));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createUserObject("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "", "COMPANYA", 1));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createUserObject("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "USERA", "COMPANYA", 0));
	}

	/**
	 * Verifies provider adaptation rejects null details.
	 */
	@Test
	public void testProviderFromNullUserDetails()
	{
		assertThrowsOtpException(() -> OTPUserCredentialProvider.from(null));
	}

	/**
	 * Verifies provider adaptation rejects invalid details.
	 */
	@Test
	public void testProviderFromInvalidUserDetails()
	{
		OTPUserDetailsImpl details = new OTPUserDetailsImpl("", "USERA", "COMPANYA", 1);
		assertThrowsOtpException(() -> OTPUserCredentialProvider.from(details));
	}

	/**
	 * Helper to assert OTPGenericException is thrown.
	 */
	private static void assertThrowsOtpException(ThrowingRunnable action) {
		try {
			action.run();
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Runnable that can throw OTPGenericException.
	 */
	private interface ThrowingRunnable {
		void run() throws OTPGenericException;
	}
}
