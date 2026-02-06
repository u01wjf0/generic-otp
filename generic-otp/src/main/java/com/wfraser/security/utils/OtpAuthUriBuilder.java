package com.wfraser.security.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.OTPConfig;

/**
	 * Builder for otpauth:// URIs (TOTP and HOTP).
 * 
 * @since 2.0
 */
public final class OtpAuthUriBuilder {

	public enum Type {
		TOTP("totp"),
		HOTP("hotp");

		private final String value;

		/**
		 * Creates a type with a URI path value.
		 *
		 * @param value path segment
		 */
		Type(String value) {
			this.value = value;
		}
	}

	private final Type type;
	private String issuer;
	private String accountName;
	private String secret;
	private Integer digits;
	private Integer period;
	private OTPConfig.Algorithm algorithm;
	private Long counter;

	/**
	 * Creates a builder for the given type.
	 *
	 * @param type TOTP or HOTP
	 */
	private OtpAuthUriBuilder(Type type) {
		this.type = type;
	}

	/**
	 * Creates a builder for TOTP URIs.
	 *
	 * @return builder instance
	 */
	public static OtpAuthUriBuilder totp() {
		return new OtpAuthUriBuilder(Type.TOTP);
	}

	/**
	 * Creates a builder for HOTP URIs.
	 *
	 * @return builder instance
	 */
	public static OtpAuthUriBuilder hotp() {
		return new OtpAuthUriBuilder(Type.HOTP);
	}

	/**
	 * Sets the issuer.
	 *
	 * @param issuer issuer name
	 * @return builder
	 */
	public OtpAuthUriBuilder issuer(String issuer) {
		this.issuer = issuer;
		return this;
	}

	/**
	 * Sets the account name.
	 *
	 * @param accountName account name
	 * @return builder
	 */
	public OtpAuthUriBuilder accountName(String accountName) {
		this.accountName = accountName;
		return this;
	}

	/**
	 * Sets the Base32 secret.
	 *
	 * @param secret secret key
	 * @return builder
	 */
	public OtpAuthUriBuilder secret(String secret) {
		this.secret = secret;
		return this;
	}

	/**
	 * Sets the number of digits (6 or 8).
	 *
	 * @param digits digits
	 * @return builder
	 */
	public OtpAuthUriBuilder digits(int digits) {
		this.digits = digits;
		return this;
	}

	/**
	 * Sets the period in seconds (TOTP only).
	 *
	 * @param period period in seconds
	 * @return builder
	 */
	public OtpAuthUriBuilder period(int period) {
		this.period = period;
		return this;
	}

	/**
	 * Sets the HMAC algorithm.
	 *
	 * @param algorithm algorithm
	 * @return builder
	 */
	public OtpAuthUriBuilder algorithm(OTPConfig.Algorithm algorithm) {
		this.algorithm = algorithm;
		return this;
	}

	/**
	 * Sets the counter value (HOTP only).
	 *
	 * @param counter counter value
	 * @return builder
	 */
	public OtpAuthUriBuilder counter(long counter) {
		this.counter = counter;
		return this;
	}

	/**
	 * Builds the otpauth URI.
	 *
	 * @return otpauth URI string
	 * @throws OTPGenericException when required fields are missing or invalid
	 */
	public String build() throws OTPGenericException {
		validate();
		try {
			String label = encode(issuer + ":" + accountName);
			StringBuilder url = new StringBuilder();
			url.append("otpauth://")
				.append(type.value)
				.append("/")
				.append(label)
				.append("?secret=")
				.append(encode(secret))
				.append("&issuer=")
				.append(encode(issuer));

			if (digits != null) {
				url.append("&digits=").append(digits);
			}
			if (period != null && type == Type.TOTP) {
				url.append("&period=").append(period);
			}
			if (algorithm != null) {
				url.append("&algorithm=").append(algorithm.getOtpauthName());
			}
			if (type == Type.HOTP) {
				url.append("&counter=").append(counter);
			}
			return url.toString();
		} catch (UnsupportedEncodingException e) {
			throw new OTPGenericException(OTPGenericException._ERROR_GETTING_URL, e);
		}
	}

	/**
	 * Validates builder fields before building the URI.
	 *
	 * @throws OTPGenericException when required fields are missing or invalid
	 */
	private void validate() throws OTPGenericException {
		if (issuer == null || issuer.isEmpty() || accountName == null || accountName.isEmpty() || secret == null || secret.isEmpty()) {
			throw new OTPGenericException(OTPGenericException._USER_AND_KEY_BLANK);
		}
		if (digits != null && digits != 6 && digits != 8) {
			throw new OTPGenericException(OTPGenericException._CONFIG_INVALID);
		}
		if (period != null && period <= 0) {
			throw new OTPGenericException(OTPGenericException._CONFIG_INVALID);
		}
		if (type == Type.HOTP && (counter == null || counter < 0)) {
			throw new OTPGenericException(OTPGenericException._CONFIG_INVALID);
		}
	}

	/**
	 * URL-encodes a value for otpauth URIs.
	 *
	 * @param value value to encode
	 * @return encoded value
	 * @throws UnsupportedEncodingException when UTF-8 is unavailable
	 */
	private static String encode(String value) throws UnsupportedEncodingException {
		return URLEncoder.encode(value, "UTF-8").replace("+", "%20");
	}
}
