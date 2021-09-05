import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.OTPImplementation;
import com.wfraser.security.utils.OTPUtils;

import test.entities.OTPUserImpl;


public class OTPTests {

	@Test
	public void test() throws OTPGenericException {
		OTPImplementation otp;
		otp = OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		System.out.println(otp.getOTP());
		assertTrue(otp.getOTP().length() == 6);
	}

	@Test
	public void testValidation() throws OTPGenericException
	{
		OTPImplementation otp = null;
		String input = "";
		otp = OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		input = otp.getOTP();
		System.out.println(input);
		if(otp.validate(input))
		{
			System.out.println("they match");
		}		
		assertTrue(otp.validate(input));
	}

	@Test
	public void testValidationAfterOneStep() throws OTPGenericException
	{
		OTPImplementation otp = null;
		String input = "";
		otp = OTPImplementation.createInstance(new OTPUserImpl(false, false).getProvider());
		input = otp.getOTP();
		System.out.println(input);
		System.out.println("Please wait 30 seconds");
		try {
			TimeUnit.SECONDS.sleep(30);
		} catch (InterruptedException e1) {
		}
		if(otp.validate(input))
		{
			System.out.println("they match");
		}		
		assertTrue(otp.validate(input));
	}

	@Test
	public void testValidationAfterAllStep() throws OTPGenericException
	{
		OTPImplementation otp = null;
		String otpCode = "";
		OTPUserImpl user = new OTPUserImpl(false, false);
		otp = OTPImplementation.createInstance(user.getProvider());
		otpCode = otp.getOTP();
		System.out.println(otpCode);
		System.out.println("Please wait " + ((user.getAllowedSteps()) * 30) + " Seconds");
		try {
			TimeUnit.SECONDS.sleep(user.getAllowedSteps() * 30);
		} catch (InterruptedException e1) {
		}
		if(!otp.validate(otpCode))
		{
			System.out.println("they dont match");
		}		
		assertTrue(!otp.validate(otpCode));
	}

	@Test
	public void testGoogleAuthURL() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		System.out.println( OTPUtils.getAuthenticatorURL(user.getProvider()) );
		assertTrue(true);
	}

	@Test
	public void testBarcode() throws OTPGenericException
	{
		OTPUserImpl user = new OTPUserImpl(true, false);
		String barcode =  OTPUtils.getAuthenticatorURL(user.getProvider());
		FileOutputStream fileOut = null;
		try {
			fileOut = new FileOutputStream("C:\\tmp\\temp.png");
			OTPUtils.getAuthenticatorQRCode(barcode, fileOut, 150);
		} catch (FileNotFoundException e) {
		} finally {
			try {
				fileOut.close();
			} catch (IOException e) {
			}
		}
		File file = new File("C:\\tmp\\temp.png");
		assertTrue(file.exists());
	}

	@Test
	public void testGoogleAuth() throws OTPGenericException {

		OTPUserImpl user = new OTPUserImpl(false, true);
		String barcode =  OTPUtils.getAuthenticatorURL(user.getProvider());		
		FileOutputStream fileOut = null;
		System.out.println(user.getProvider().getSecretKey());
		try {
			fileOut = new FileOutputStream("C:\\tmp\\temp.png");
			OTPUtils.getAuthenticatorQRCode(barcode, fileOut, 150);
		} catch (FileNotFoundException e) {
		} finally {
			try {
				fileOut.close();
			} catch (IOException e) {
			}
		}
		System.out.println("Open C:\\tmp\\temp.png and scan with google auth");
		String input = "";
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		try {
			input = reader.readLine();
		} catch (IOException e) {
		}
		OTPImplementation otp = OTPImplementation.createInstance(user.getProvider());
		assertTrue(otp.validate(input));

	}


}
