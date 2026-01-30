import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.OTPImplementation;
import com.wfraser.security.otp.OTPUserCredentialProvider;
import com.wfraser.security.utils.OTPUtils;

import test.entities.OTPUserImpl;


public class OTPTests {

	@Test
	public void test() throws OTPGenericException {
		OTPImplementation otp = OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		assertTrue(otp.getOTP().length() == 6);
	}

	@Test
	public void testValidation() throws OTPGenericException
	{
		OTPImplementation otp = OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		String input = otp.getOTP();
		assertTrue(otp.validate(input));
	}

	@Test
	public void testValidationAfterOneStep() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(false, false);
		OTPImplementation otp = OTPImplementation.createInstance(user.getProvider());
		long currentStep = System.currentTimeMillis() / 30000;
		String input = computeOtp(user.getProvider(), currentStep - 1);
		assertTrue(otp.validate(input));
	}

	@Test
	public void testValidationAfterAllStep() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(false, false);
		OTPImplementation otp = OTPImplementation.createInstance(user.getProvider());
		long currentStep = System.currentTimeMillis() / 30000;
		String otpCode = computeOtp(user.getProvider(), currentStep - user.getAllowedSteps());
		assertFalse(otp.validate(otpCode));
	}

	@Test
	public void testValidationWindowBounds() throws OTPGenericException
	{
		OTPUserCredentialProvider provider = OTPUserCredentialProvider
				.createBasicUserObject("USERA", 1);
		OTPImplementation otp = OTPImplementation.createInstance(provider);
		long currentStep = System.currentTimeMillis() / 30000;
		String currentOtp = computeOtp(provider, currentStep);
		String previousOtp = computeOtp(provider, currentStep - 1);
		assertTrue(otp.validate(currentOtp));
		assertFalse(otp.validate(previousOtp));
	}

	@Test
	public void testRfc4226HotpVectors() throws Exception
	{
		String secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		OTPUserCredentialProvider provider = OTPUserCredentialProvider
				.createAuthenticatorUserObject(secretBase32, "USERA", "COMPANYA", 1);
		OTPImplementation otp = OTPImplementation.createInstance(provider);
		int[] expected = new int[] {
				755224, 287082, 359152, 969429, 338314,
				254676, 287922, 162583, 399871, 520489
		};
		for (int counter = 0; counter < expected.length; counter++) {
			String actual = reflectOtpForStep(otp, counter);
			assertEquals(String.format("%06d", expected[counter]), actual);
		}
	}

	@Test
	public void testOtpLeadingZeroPadding() throws Exception
	{
		String secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		OTPUserCredentialProvider provider = OTPUserCredentialProvider
				.createAuthenticatorUserObject(secretBase32, "USERA", "COMPANYA", 1);
		OTPImplementation otp = OTPImplementation.createInstance(provider);
		long stepWithLeadingZero = findStepWithLeadingZero(provider, 0, 200000);
		String actual = reflectOtpForStep(otp, stepWithLeadingZero);
		assertEquals(6, actual.length());
		assertTrue(actual.startsWith("0"));
	}

	@Test
	public void testGoogleAuthURL() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String url = OTPUtils.getAuthenticatorURL(user.getProvider());
		assertTrue(url.startsWith("otpauth://totp/"));
		assertTrue(url.contains("secret="));
		assertTrue(url.contains("issuer="));
	}

	@Test
	public void testBarcode() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String barcode =  OTPUtils.getAuthenticatorURL(user.getProvider());
		Path tempFile = null;
		try {
			tempFile = Files.createTempFile("otp-", ".png");
			try (OutputStream fileOut = Files.newOutputStream(tempFile)) {
				OTPUtils.getAuthenticatorQRCode(barcode, fileOut, 150);
			}
		} catch (IOException e) {
			fail("Failed to write QR code: " + e.getMessage());
		}
		assertTrue(tempFile != null && Files.exists(tempFile));
	}

	@Test
	public void testBarcodeWritesBytes() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String barcode = OTPUtils.getAuthenticatorURL(user.getProvider());
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		OTPUtils.getAuthenticatorQRCode(barcode, outputStream, 150);
		assertTrue(outputStream.size() > 0);
	}

	@Test
	public void testGoogleAuth() throws OTPGenericException {
		OTPUserImpl user = new OTPUserImpl(false, true);
		OTPImplementation otp = OTPImplementation.createInstance(user.getProvider());
		long currentStep = System.currentTimeMillis() / 30000;
		String input = computeOtp(user.getProvider(), currentStep);
		assertTrue(otp.validate(input));
	}

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

	@Test
	public void testCredentialProviderValidation()
	{
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createBasicUserObject("", 1));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createBasicUserObject("USERA", 0));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createAuthenticatorUserObject("KEY", "USERA", "", 1));
		assertThrowsOtpException(() -> OTPUserCredentialProvider.createAuthenticatorUserObject("", "USERA", "COMPANYA", 1));
	}

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

	private static String computeOtp(OTPUserCredentialProvider provider, long step) {
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(new SecretKeySpec(provider.getSecretByteArray(), "RAW"));
			byte[] stepBytes = ByteBuffer.allocate(8).putLong(step).array();
			byte[] hash = mac.doFinal(stepBytes);
			int offset = hash[hash.length - 1] & 0xf;
			int binary = ((hash[offset] & 0x7f) << 24)
					| ((hash[offset + 1] & 0xff) << 16)
					| ((hash[offset + 2] & 0xff) << 8)
					| (hash[offset + 3] & 0xff);
			int otpVal = binary % 1000000;
			return String.format("%06d", otpVal);
		} catch (Exception e) {
			throw new IllegalStateException("Failed to compute OTP", e);
		}
	}

	private static String reflectOtpForStep(OTPImplementation otp, long step) throws Exception {
		var method = OTPImplementation.class.getDeclaredMethod("getOTP", byte[].class);
		method.setAccessible(true);
		byte[] stepBytes = ByteBuffer.allocate(8).putLong(step).array();
		return (String) method.invoke(otp, (Object) stepBytes);
	}

	private static long findStepWithLeadingZero(OTPUserCredentialProvider provider, long start, long end) {
		for (long step = start; step <= end; step++) {
			String otp = computeOtp(provider, step);
			if (otp.startsWith("0")) {
				return step;
			}
		}
		throw new IllegalStateException("No OTP with leading zero found in range");
	}

	private static void assertThrowsOtpException(ThrowingRunnable action) {
		try {
			action.run();
			fail("Expected OTPGenericException");
		} catch (OTPGenericException e) {
			assertTrue(e.getMessage().contains("FATAL"));
		}
	}

	private interface ThrowingRunnable {
		void run() throws OTPGenericException;
	}

}
