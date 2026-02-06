package com.wfraser.security.otp;

import com.wfraser.security.exceptions.OTPGenericException;

/**
 * Configuration for OTP generation and validation.
 *
 * @since 2.0
 */
public final class OTPConfig {

	/**
	 * Supported HMAC algorithms.
	 */
	public enum Algorithm {
		SHA1("HmacSHA1", "SHA1"),
		SHA256("HmacSHA256", "SHA256"),
		SHA512("HmacSHA512", "SHA512");

		private final String hmacName;
		private final String otpauthName;

		Algorithm(String hmacName, String otpauthName) {
			this.hmacName = hmacName;
			this.otpauthName = otpauthName;
		}

		public String getHmacName() {
			return hmacName;
		}

		public String getOtpauthName() {
			return otpauthName;
		}
	}

	private final Algorithm algorithm;
	private final int digits;
	private final int periodSeconds;

	/**
	 * Creates a new OTP configuration.
	 *
	 * @param algorithm HMAC algorithm
	 * @param digits number of digits
	 * @param periodSeconds period in seconds
	 */
	private OTPConfig(Algorithm algorithm, int digits, int periodSeconds) {
		if (algorithm == null)
			throw new IllegalArgumentException(OTPGenericException._ALGORITHM_NULL);
		if (digits != 6 && digits != 8)
			throw new IllegalArgumentException(OTPGenericException._DIGITS_INVALID);
		if (periodSeconds <= 0)
			throw new IllegalArgumentException(OTPGenericException._PERIOD_INVALID);
		this.algorithm = algorithm;
		this.digits = digits;
		this.periodSeconds = periodSeconds;
	}

	/**
	 * Returns the default configuration (SHA1 / 6 digits / 30 seconds).
	 *
	 * @return default OTPConfig
	 */
	public static OTPConfig defaults() {
		return new OTPConfig(Algorithm.SHA1, 6, 30);
	}

	/**
	 * Returns a builder for OTPConfig.
	 *
	 * @return builder instance
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * @return configured algorithm
	 */
	public Algorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * @return configured digits (6 or 8)
	 */
	public int getDigits() {
		return digits;
	}

	/**
	 * @return configured period in seconds
	 */
	public int getPeriodSeconds() {
		return periodSeconds;
	}

	/**
	 * Builder for OTPConfig.
	 */
	public static final class Builder {
		private Algorithm algorithm = Algorithm.SHA1;
		private int digits = 6;
		private int periodSeconds = 30;

		/**
		 * Creates a new builder with default values.
		 */
		private Builder() {
		}

		/**
		 * Sets the HMAC algorithm.
		 *
		 * @param algorithm algorithm
		 * @return builder
		 */
		public Builder algorithm(Algorithm algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		/**
		 * Sets the number of digits (6 or 8).
		 *
		 * @param digits digits
		 * @return builder
		 */
		public Builder digits(int digits) {
			this.digits = digits;
			return this;
		}

		/**
		 * Sets the period in seconds.
		 *
		 * @param periodSeconds period
		 * @return builder
		 */
		public Builder periodSeconds(int periodSeconds) {
			this.periodSeconds = periodSeconds;
			return this;
		}

		/**
		 * Builds the OTPConfig.
		 *
		 * @return OTPConfig
		 */
		public OTPConfig build() {
			return new OTPConfig(algorithm, digits, periodSeconds);
		}
	}
}
