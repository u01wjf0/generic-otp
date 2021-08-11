package com.wfraser.security.utils;

/**
 * OTPUtils is a Util class for the OTP generator
 * this class contains utility for
 * 
 * <ul>
 * <li> Generating a new random secret key 
 * <li> Generating a Google Authenticator Bar Code
 * <li> Generating a Google Authenticator QR Code
 * </ul>
 * 
 * 
 * @author 	William Fraser
 * @version	%I%, %G%
 * @since 	1.0
 *
 */

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.net.URLEncoder;

import org.apache.commons.codec.binary.Base32;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.OTPUserCredentialProvider;

public class OTPUtils {

	private final static Object locker = new Object();

	/**
	 * Generates a new random Secret Key using {@link SecureRandom}
	 * The random key is in Base32 presented as a String
	 * 
	 * @return 	the String representation of a {@link Base32} SecretKey
	 */
	public static String generateSecretKey() {
		synchronized(locker) {
			SecureRandom random = new SecureRandom();
			byte[] bytes = new byte[20];
			random.nextBytes(bytes);
			Base32 base32 = new Base32();
			return base32.encodeToString(bytes);
		}
	}

	/**
	 * Generates a url representation of a Google Authenticator 
	 * otpauth
	 * 
	 * @param user		the {@link OTPUserCredentialProvider} representing the authenticating user
	 * 
	 * @return			the String containing the URL for the Google Authenticator App
	 */
	public static String getAuthenticatorURL(OTPUserCredentialProvider user) {
		synchronized(locker) {
			try {
				String totpuser = URLEncoder.encode(user.getCompany() + ":" + user.getUserID(), "UTF-8").replace("+", "%20");
				String totpKey =  URLEncoder.encode(user.getSecretKey(), "UTF-8").replace("+", "%20");
				String totpIssuer  = URLEncoder.encode(user.getCompany(), "UTF-8").replace("+", "%20");
				return "otpauth://totp/" + totpuser + "?secret=" + totpKey + "&issuer=" + totpIssuer;
			} catch (UnsupportedEncodingException e) {
				throw new OTPGenericException(OTPGenericException._ERROR_GETTING_URL, e);
			}
		}
	}

	/**
	 * Takes a Google Authenticator barcode @see#getGoogleAuthenticatorBarCode()
	 * and generates a QR Code representation then feeds that representation to the chosen 
	 * {@link OutputStream}. Finally closing the output stream. 
	 * 
	 * IMPORTANT the provided OutputStream is closed on completion!
	 * 
	 * 
	 * @param barCodeData		the String of the Google Authenticator URL
	 * @param filePath			the chosen {@link OutputStream} type to feed to
	 * @param heightAndWidth	the chosen hight and width of the QRCode
	 */
	public static void getAuthenticatorQRCode(String url, OutputStream outputStream, int heightAndWidth) {
		synchronized(locker) {
			try {
				BitMatrix matrix = new MultiFormatWriter().encode(url, BarcodeFormat.QR_CODE,
						heightAndWidth, heightAndWidth);
				try {
					MatrixToImageWriter.writeToStream(matrix, "png", outputStream);
				} finally {
					outputStream.close();
				}
			} catch (IOException | WriterException pe) {
				throw new OTPGenericException(OTPGenericException._ERROR_GETTING_QRCODE, pe);
			} 
		}
	}

}
