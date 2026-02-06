package com.wfraser.security;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;

import org.junit.Test;

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.OTPConfig;
import com.wfraser.security.utils.OTPUtils;
import com.wfraser.security.utils.OtpAuthUriBuilder;

import com.wfraser.security.test.entities.OTPUserImpl;
import com.wfraser.security.test.entities.OTPUserDetailsImpl;

/**
 * Test menu:
 * - TOTP/HOTP URL generation helpers
 * - OtpAuthUriBuilder behavior
 * - QR code output generation
 * - Input validation and error paths
 */
public class OTPUtilsTests {

	/**
	 * Verifies default TOTP URL structure.
	 */
	@Test
	public void testGoogleAuthURL() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String url = OTPUtils.getAuthenticatorURL(user.getProvider());
		assertTrue(url.startsWith("otpauth://totp/"));
		assertTrue(url.contains("secret="));
		assertTrue(url.contains("issuer="));
	}

	/**
	 * Verifies URL generation works with OTPUserDetails.
	 */
	@Test
	public void testGoogleAuthURLWithUserDetails() throws OTPGenericException
	{
		OTPUserDetailsImpl details = new OTPUserDetailsImpl("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "USERA", "COMPANYA", 1);
		String url = OTPUtils.getAuthenticatorURL(details);
		assertTrue(url.startsWith("otpauth://totp/"));
	}

	/**
	 * Verifies TOTP URL includes non-default config parameters.
	 */
	@Test
	public void testAuthenticatorUrlWithConfig() throws OTPGenericException
	{
		OTPConfig config = OTPConfig.builder()
				.algorithm(OTPConfig.Algorithm.SHA512)
				.digits(8)
				.periodSeconds(60)
				.build();
		OTPUserImpl user = new OTPUserImpl(true, false);
		String url = OTPUtils.getAuthenticatorURL(user.getProvider(), config);
		assertTrue(url.contains("algorithm=SHA512"));
		assertTrue(url.contains("digits=8"));
		assertTrue(url.contains("period=60"));
	}

	/**
	 * Verifies default config produces same URL as legacy helper.
	 */
	@Test
	public void testConfigDefaultsMatchLegacyUrl() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String urlDefault = OTPUtils.getAuthenticatorURL(user.getProvider());
		String urlConfig = OTPUtils.getAuthenticatorURL(user.getProvider(), OTPConfig.defaults());
		assertEquals(urlDefault, urlConfig);
	}

	/**
	 * Verifies HOTP URL includes counter.
	 */
	@Test
	public void testHotpUrlWithCounter() throws OTPGenericException
	{
		OTPConfig config = OTPConfig.builder()
				.algorithm(OTPConfig.Algorithm.SHA1)
				.digits(6)
				.periodSeconds(30)
				.build();
		OTPUserImpl user = new OTPUserImpl(true, false);
		String url = OTPUtils.getAuthenticatorHotpURL(user.getProvider(), config, 42);
		assertTrue(url.startsWith("otpauth://hotp/"));
		assertTrue(url.contains("counter=42"));
	}

	/**
	 * Verifies TOTP builder output includes configured params.
	 */
	@Test
	public void testOtpAuthBuilderTotp() throws OTPGenericException
	{
		String url = OtpAuthUriBuilder.totp()
				.issuer("Company")
				.accountName("USERA")
				.secret("SECRET")
				.period(60)
				.digits(8)
				.algorithm(OTPConfig.Algorithm.SHA256)
				.build();
		assertTrue(url.startsWith("otpauth://totp/"));
		assertTrue(url.contains("issuer=Company"));
		assertTrue(url.contains("secret=SECRET"));
		assertTrue(url.contains("period=60"));
		assertTrue(url.contains("digits=8"));
		assertTrue(url.contains("algorithm=SHA256"));
	}

	/**
	 * Verifies HOTP builder output includes counter.
	 */
	@Test
	public void testOtpAuthBuilderHotp() throws OTPGenericException
	{
		String url = OtpAuthUriBuilder.hotp()
				.issuer("Company")
				.accountName("USERA")
				.secret("SECRET")
				.counter(7)
				.build();
		assertTrue(url.startsWith("otpauth://hotp/"));
		assertTrue(url.contains("counter=7"));
	}

	/**
	 * Verifies HOTP builder rejects missing counter.
	 */
	@Test
	public void testOtpAuthBuilderHotpMissingCounter()
	{
		try {
			OtpAuthUriBuilder.hotp()
					.issuer("Company")
					.accountName("USERA")
					.secret("SECRET")
					.build();
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies QR generation outputs data.
	 */
	@Test
	public void testBarcodeWritesBytes() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String barcode = OTPUtils.getAuthenticatorURL(user.getProvider());
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		OTPUtils.getAuthenticatorQRCode(barcode, outputStream, 150);
		assertTrue(outputStream.size() > 0);
	}

	/**
	 * Verifies QR generation with error correction outputs data.
	 */
	@Test
	public void testBarcodeWritesBytesWithErrorCorrection() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String barcode = OTPUtils.getAuthenticatorURL(user.getProvider());
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		OTPUtils.getAuthenticatorQRCode(barcode, outputStream, 150, ErrorCorrectionLevel.H);
		assertTrue(outputStream.size() > 0);
	}

	/**
	 * Verifies QR generation with margin outputs data.
	 */
	@Test
	public void testBarcodeWritesBytesWithMargin() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String barcode = OTPUtils.getAuthenticatorURL(user.getProvider());
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		OTPUtils.getAuthenticatorQRCode(barcode, outputStream, 150, ErrorCorrectionLevel.M, 2);
		assertTrue(outputStream.size() > 0);
	}

	/**
	 * Verifies null user input is rejected.
	 */
	@Test
	public void testAuthenticatorUrlNullInputs()
	{
		try {
			OTPUtils.getAuthenticatorURL(null);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies null config input is rejected.
	 */
	@Test
	public void testAuthenticatorUrlNullConfig()
	{
		try {
			OTPUtils.getAuthenticatorURL(new OTPUserImpl(true, false).getProvider(), null);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies URL generation rejects null user details.
	 */
	@Test
	public void testAuthenticatorUrlNullUserDetails()
	{
		try {
			OTPUtils.getAuthenticatorURL((com.wfraser.security.otp.OTPUserDetails) null);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies URL generation rejects missing company in user details.
	 */
	@Test
	public void testAuthenticatorUrlMissingCompany()
	{
		try {
			OTPUserDetailsImpl details = new OTPUserDetailsImpl("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "USERA", null, 1);
			OTPUtils.getAuthenticatorURL(details);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies negative counter is rejected.
	 */
	@Test
	public void testHotpUrlNegativeCounter()
	{
		try {
			OTPConfig config = OTPConfig.defaults();
			OTPUtils.getAuthenticatorHotpURL(new OTPUserImpl(true, false).getProvider(), config, -1);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies HOTP URL rejects null user details.
	 */
	@Test
	public void testHotpUrlNullUserDetails()
	{
		try {
			OTPConfig config = OTPConfig.defaults();
			OTPUtils.getAuthenticatorHotpURL((com.wfraser.security.otp.OTPUserDetails) null, config, 0);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies HOTP URL rejects null config.
	 */
	@Test
	public void testHotpUrlNullConfig()
	{
		try {
			OTPUtils.getAuthenticatorHotpURL(new OTPUserImpl(true, false).getProvider(), null, 0);
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies builder rejects invalid digit count.
	 */
	@Test
	public void testOtpAuthBuilderInvalidDigits()
	{
		try {
			OtpAuthUriBuilder.totp()
					.issuer("Company")
					.accountName("USERA")
					.secret("SECRET")
					.digits(7)
					.build();
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies builder rejects invalid period.
	 */
	@Test
	public void testOtpAuthBuilderInvalidPeriod()
	{
		try {
			OtpAuthUriBuilder.totp()
					.issuer("Company")
					.accountName("USERA")
					.secret("SECRET")
					.period(0)
					.build();
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies builder rejects negative counter.
	 */
	@Test
	public void testOtpAuthBuilderNegativeCounter()
	{
		try {
			OtpAuthUriBuilder.hotp()
					.issuer("Company")
					.accountName("USERA")
					.secret("SECRET")
					.counter(-1)
					.build();
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	/**
	 * Verifies builder rejects missing fields.
	 */
	@Test
	public void testOtpAuthBuilderMissingFields()
	{
		try {
			OtpAuthUriBuilder.totp().issuer("Company").build();
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}
}
