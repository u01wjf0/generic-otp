package com.wfraser.security;

import java.nio.ByteBuffer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.wfraser.security.otp.OTPConfig;
import com.wfraser.security.otp.OTPUserCredentialProvider;

/**
 * Test menu:
 * - Deterministic OTP computation helpers
 * - Step scanning helpers for leading-zero cases
 */
final class TestHelpers {
	private TestHelpers() {
	}

	/**
	 * Computes an OTP for the provided step using the given config.
	 */
	static String computeOtp(OTPUserCredentialProvider provider, long step, OTPConfig config) {
		try {
			Mac mac = Mac.getInstance(config.getAlgorithm().getHmacName());
			mac.init(new SecretKeySpec(provider.getSecretByteArray(), "RAW"));
			byte[] stepBytes = ByteBuffer.allocate(8).putLong(step).array();
			byte[] hash = mac.doFinal(stepBytes);
			int offset = hash[hash.length - 1] & 0xf;
			int binary = ((hash[offset] & 0x7f) << 24)
					| ((hash[offset + 1] & 0xff) << 16)
					| ((hash[offset + 2] & 0xff) << 8)
					| (hash[offset + 3] & 0xff);
			int otpVal = binary % (int) Math.pow(10, config.getDigits());
			return String.format("%0" + config.getDigits() + "d", otpVal);
		} catch (Exception e) {
			throw new IllegalStateException("Failed to compute OTP", e);
		}
	}

	/**
	 * Computes an OTP using default config.
	 */
	static String computeOtp(OTPUserCredentialProvider provider, long step) {
		return computeOtp(provider, step, OTPConfig.defaults());
	}

	/**
	 * Finds a step that produces a leading zero OTP.
	 */
	static long findStepWithLeadingZero(OTPUserCredentialProvider provider, long start, long end) {
		for (long step = start; step <= end; step++) {
			String otp = computeOtp(provider, step);
			if (otp.startsWith("0")) {
				return step;
			}
		}
		throw new IllegalStateException("No OTP with leading zero found in range");
	}
}
