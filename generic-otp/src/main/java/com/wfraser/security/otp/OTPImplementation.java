package com.wfraser.security.otp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacAlgorithms;

import com.wfraser.security.exceptions.OTPGenericException;

/**
 * OTPImplementation is the core implementation class
 * for all the OTP functionality.
 * 
 * Public methods include
 * <ul>
 * <li> <code>createInstance()</code>
 * <li> <code>getOTP()</code>
 * <li> <code>validate()</code>
 * </ul>
 * 
 * This class is used by calling the static createInstance
 * 
 * 
 * @author 	William Frasewr
 * @version	%I%, %G%
 * @since 	1.0
 *
 */
public final class OTPImplementation {

	
	private final String _OTP_METHOD_ALGO = HmacAlgorithms.HMAC_SHA_1.getName();
	private final Long _TIMER_COUNT = 30000L; //30s
	private final OTPUserCredentialProvider authenticatingUser;
	private final Mac mac;
	
	
	private OTPImplementation() throws NoSuchAlgorithmException, InvalidKeyException {
		this.authenticatingUser = null;
		this.mac = null;
	}
	
	private OTPImplementation(OTPUserCredentialProvider authUser) throws NoSuchAlgorithmException, InvalidKeyException {
		this.authenticatingUser = authUser;
		mac = Mac.getInstance(_OTP_METHOD_ALGO);
		if(this.authenticatingUser != null && this.authenticatingUser.getSecretKey() != null) 
		{
			Base32 base32 = new Base32();
			byte[] bytes = base32.decode(this.authenticatingUser.getSecretKey().toUpperCase());
			final byte[] array2 = new BigInteger("10" + Hex.encodeHexString(bytes), 16).toByteArray();
			final byte[] secretKeyBytes = new byte[array2.length - 1];
			System.arraycopy(array2, 1, secretKeyBytes, 0, secretKeyBytes.length);
			mac.init(new SecretKeySpec(secretKeyBytes, "RAW"));
		} else {
			throw new OTPGenericException(OTPGenericException._USER_AND_KEY_BLANK);
		}
	}
	
	public static OTPImplementation createInstance(OTPUserCredentialProvider authUser) {
		
		try {
			return new OTPImplementation(authUser);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			throw new OTPGenericException(OTPGenericException._ERROR_CREATING_OTP_INSTANCE, e);
		}
	}
	
	private long getCurrentStep() {
		return System.currentTimeMillis() / _TIMER_COUNT;
	}
	
	private String getStepAsString(long step) {
		String steps = Long.toHexString(step).toUpperCase();
		while (steps.length() < 16) {
			steps = "0" + steps;
		}
		return steps;
	}
	
	private byte[] getStepAsBytes(String step) {
		final byte[] cleanupArray = new BigInteger("10" + step, 16).toByteArray();
		final byte[] stepAsByte = new byte[cleanupArray.length - 1];
		System.arraycopy(cleanupArray, 1, stepAsByte, 0, stepAsByte.length);
		return stepAsByte;
	}
	
	private byte[] doHMACSHA1(final byte[] text)
	{
			return mac.doFinal(text);
	}
	
	private String getOTP(final byte[] stepsBytes)
	{
		String otp = "";
		final byte[] hash = doHMACSHA1(stepsBytes);
		final int offset = hash[hash.length - 1] & 0xf;
		final int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
		final int otpVal = binary % 1000000;

		otp = Integer.toString(otpVal);
		while (otp.length() < 6) {
			otp = "0" + otp;
		}
		return otp;
	}
	
	public String getOTP()
	{
		String currentStep = getStepAsString(getCurrentStep());
		byte[] stepsAsBytes = getStepAsBytes(currentStep);
		return getOTP(stepsAsBytes);
	}
	
	public Boolean validate(String input) {
		while (input.length() < 6) {
			input = "0" + input;
		}
		long step = getCurrentStep();
		long lastStep = step - authenticatingUser.getAllowedSteps() + 1;
		while(lastStep <= step)
		{
			if(input.compareTo(getOTP(getStepAsBytes(getStepAsString(lastStep))))==0)
			{
				return true;
			}
			lastStep++;
		}
		
		return false;
	}
	
}
