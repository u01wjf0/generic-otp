package com.wfraser.security.utils;

/**
 * Utility methods for the OTP generator.
 * 
 * <ul>
 * <li> Generating a new random secret key 
 * <li> Generating a Google Authenticator Bar Code
 * <li> Generating a Google Authenticator QR Code
 * </ul>
 * 
 * 
 * @author 	William Fraser
 * @version	2.0
 * @since 	1.0
 *
 */

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base32;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.google.zxing.EncodeHintType;
import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.OTPConfig;
import com.wfraser.security.otp.OTPUserCredentialProvider;
import com.wfraser.security.otp.OTPUserDetails;

public class OTPUtils {

	private final static Object locker = new Object();

	/**
	 * Generates a new random secret key using {@link SecureRandom}.
	 * The random key is Base32 encoded as a String.
	 * 
	 * @return 	the String representation of a {@link Base32} SecretKey
	 */
	public static String generateSecretKey() {
		synchronized( locker ) {
			SecureRandom random = new SecureRandom();
			byte[] bytes = new byte[20];
			random.nextBytes( bytes );
			Base32 base32 = new Base32();
			return base32.encodeToString( bytes );
		}
	}

	/**
	 * Generates an otpauth URL for Google Authenticator.
	 * 
	 * @param user		the {@link OTPUserCredentialProvider} representing the authenticating user
	 * 
	 * @return			the String containing the URL for the Google Authenticator App
	 * @throws OTPGenericException 
	 */
	public static String getAuthenticatorURL(OTPUserCredentialProvider user) throws OTPGenericException {
		return getAuthenticatorURL((OTPUserDetails) user, OTPConfig.defaults());
	}

	/**
	 * Generates an otpauth URL for Google Authenticator.
	 *
	 * @param user		the {@link OTPUserDetails} representing the authenticating user
	 * @return			the String containing the URL for the Google Authenticator App
	 * @throws OTPGenericException
	 */
	public static String getAuthenticatorURL(OTPUserDetails user) throws OTPGenericException {
		return getAuthenticatorURL(user, OTPConfig.defaults());
	}

	/**
	 * Generates a URL representation of a Google Authenticator otpauth.
	 * 
	 * @param user		the {@link OTPUserCredentialProvider} representing the authenticating user
	 * @param config	{@link OTPConfig} for algorithm/digits/period configuration
	 * 
	 * @return			the String containing the URL for the Google Authenticator App
	 * @throws OTPGenericException 
	 */
	public static String getAuthenticatorURL(OTPUserCredentialProvider user, OTPConfig config) throws OTPGenericException {
		return getAuthenticatorURL((OTPUserDetails) user, config);
	}

	/**
	 * Generates a URL representation of a Google Authenticator otpauth.
	 *
	 * @param user		the {@link OTPUserDetails} representing the authenticating user
	 * @param config	{@link OTPConfig} for algorithm/digits/period configuration
	 *
	 * @return			the String containing the URL for the Google Authenticator App
	 * @throws OTPGenericException
	 */
	public static String getAuthenticatorURL(OTPUserDetails user, OTPConfig config) throws OTPGenericException {
		synchronized( locker ) {
			if (user == null || user.getCompany() == null || user.getUserID() == null || user.getSecretKey() == null) {
				throw new OTPGenericException( OTPGenericException._USER_AND_KEY_BLANK );
			}
			if (config == null) {
				throw new OTPGenericException( OTPGenericException._CONFIG_INVALID );
			}
			OtpAuthUriBuilder builder = OtpAuthUriBuilder.totp()
					.issuer(user.getCompany())
					.accountName(user.getUserID())
					.secret(user.getSecretKey());

			OTPConfig defaults = OTPConfig.defaults();
			if (config.getAlgorithm() != defaults.getAlgorithm()) {
				builder.algorithm(config.getAlgorithm());
			}
			if (config.getDigits() != defaults.getDigits()) {
				builder.digits(config.getDigits());
			}
			if (config.getPeriodSeconds() != defaults.getPeriodSeconds()) {
				builder.period(config.getPeriodSeconds());
			}
				return builder.build();
		}
	}

	/**
	 * Generates an otpauth HOTP URL for Google Authenticator.
	 * 
	 * @param user		the {@link OTPUserCredentialProvider} representing the authenticating user
	 * @param config	{@link OTPConfig} for algorithm/digits configuration
	 * @param counter	start counter value
	 * 
	 * @return			the String containing the URL for the Google Authenticator App
	 * @throws OTPGenericException 
	 */
	public static String getAuthenticatorHotpURL(OTPUserCredentialProvider user, OTPConfig config, long counter) throws OTPGenericException {
		return getAuthenticatorHotpURL((OTPUserDetails) user, config, counter);
	}

	/**
	 * Generates an otpauth HOTP URL for Google Authenticator.
	 *
	 * @param user		the {@link OTPUserDetails} representing the authenticating user
	 * @param config	{@link OTPConfig} for algorithm/digits configuration
	 * @param counter	start counter value
	 *
	 * @return			the String containing the URL for the Google Authenticator App
	 * @throws OTPGenericException
	 */
	public static String getAuthenticatorHotpURL(OTPUserDetails user, OTPConfig config, long counter) throws OTPGenericException {
		synchronized( locker ) {
			if (user == null || user.getCompany() == null || user.getUserID() == null || user.getSecretKey() == null) {
				throw new OTPGenericException( OTPGenericException._USER_AND_KEY_BLANK );
			}
			if (config == null) {
				throw new OTPGenericException( OTPGenericException._CONFIG_INVALID );
			}
			if (counter < 0) {
				throw new OTPGenericException( OTPGenericException._CONFIG_INVALID );
			}
			OtpAuthUriBuilder builder = OtpAuthUriBuilder.hotp()
					.issuer(user.getCompany())
					.accountName(user.getUserID())
					.secret(user.getSecretKey())
					.counter(counter);

			OTPConfig defaults = OTPConfig.defaults();
			if (config.getAlgorithm() != defaults.getAlgorithm()) {
				builder.algorithm(config.getAlgorithm());
			}
			if (config.getDigits() != defaults.getDigits()) {
				builder.digits(config.getDigits());
			}
				return builder.build();
		}
	}

	/**
	 * Takes a Google Authenticator URL and generates a QR Code representation,
	 * writing it to the chosen {@link OutputStream}. Finally closes the output stream.
	 * 
	 * IMPORTANT: the provided OutputStream is closed on completion.
	 * 
	 * 
	 * @param url				the String of the Google Authenticator URL
	 * @param outputStream		the chosen {@link OutputStream} type to feed to
	 * @param heightAndWidth	the chosen height and width of the QRCode
	 * @throws OTPGenericException 
	 */
	public static void getAuthenticatorQRCode( String url, OutputStream outputStream, int heightAndWidth ) throws OTPGenericException {
		synchronized( locker ) {
			try {
				BitMatrix matrix = new MultiFormatWriter().encode( url, BarcodeFormat.QR_CODE,
						heightAndWidth, heightAndWidth );
				try {
					MatrixToImageWriter.writeToStream( matrix, "png", outputStream );
				} finally {
					outputStream.close();
				}
			} catch ( IOException | WriterException pe ) {
				throw new OTPGenericException( OTPGenericException._ERROR_GETTING_QRCODE, pe );
			} 
		}
	}

	/**
	 * Generates a QR Code with a chosen error correction level.
	 * 
	 * IMPORTANT: the provided OutputStream is closed on completion.
	 * 
	 * @param url				the String of the Google Authenticator URL
	 * @param outputStream		the chosen {@link OutputStream} type to feed to
	 * @param heightAndWidth	the chosen height and width of the QRCode
	 * @param errorCorrection	the QR error correction level
	 * @throws OTPGenericException 
	 */
	public static void getAuthenticatorQRCode( String url, OutputStream outputStream, int heightAndWidth, ErrorCorrectionLevel errorCorrection ) throws OTPGenericException {
		getAuthenticatorQRCode(url, outputStream, heightAndWidth, errorCorrection, null);
	}

	/**
	 * Generates a QR Code with chosen error correction level and margin.
	 * 
	 * IMPORTANT: the provided OutputStream is closed on completion.
	 * 
	 * @param url				the String of the Google Authenticator URL
	 * @param outputStream		the chosen {@link OutputStream} type to feed to
	 * @param heightAndWidth	the chosen height and width of the QRCode
	 * @param errorCorrection	the QR error correction level
	 * @param margin			the QR margin (quiet zone) size; null uses default
	 * @throws OTPGenericException 
	 */
	public static void getAuthenticatorQRCode( String url, OutputStream outputStream, int heightAndWidth, ErrorCorrectionLevel errorCorrection, Integer margin ) throws OTPGenericException {
		synchronized( locker ) {
			try {
				Map<EncodeHintType, Object> hints = new HashMap<>();
				if (errorCorrection != null) {
					hints.put(EncodeHintType.ERROR_CORRECTION, errorCorrection);
				}
				if (margin != null) {
					hints.put(EncodeHintType.MARGIN, margin);
				}
				BitMatrix matrix = new MultiFormatWriter().encode( url, BarcodeFormat.QR_CODE,
						heightAndWidth, heightAndWidth, hints );
				try {
					MatrixToImageWriter.writeToStream( matrix, "png", outputStream );
				} finally {
					outputStream.close();
				}
			} catch ( IOException | WriterException pe ) {
				throw new OTPGenericException( OTPGenericException._ERROR_GETTING_QRCODE, pe );
			} 
		}
	}

}
