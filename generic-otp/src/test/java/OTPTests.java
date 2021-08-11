import static org.junit.Assert.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.wfraser.security.otp.OTPImplementation;
import com.wfraser.security.utils.OTPUtils;

import test.entities.OTPUserImpl;


public class OTPTests {

	@Test
	public void test() {
		OTPImplementation otp;
		otp = OTPImplementation.createInstance(new OTPUserImpl(false).getProvider());
		System.out.println(otp.getOTP());
		assertTrue(true);
	}

	@Test
	public void testValidation()
	{
		OTPImplementation otp = null;
		String input = "";
		otp = OTPImplementation.createInstance(new OTPUserImpl(false).getProvider());
		input = otp.getOTP();
		System.out.println(input);
		if(otp.validate(input))
		{
			System.out.println("they match");
		}		
		assertTrue(otp.validate(input));
	}

	@Test
	public void testValidationAfterOneStep()
	{
		OTPImplementation otp = null;
		String input = "";
		otp = OTPImplementation.createInstance(new OTPUserImpl(false).getProvider());
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
	public void testValidationAfterAllStep()
	{
		OTPImplementation otp = null;
		String otpCode = "";
		OTPUserImpl user = new OTPUserImpl(false);
		otp = OTPImplementation.createInstance(user.getProvider());
		otpCode = otp.getOTP();
		System.out.println(otpCode);
		System.out.println("Please wait " + ((user.getAllowedSteps()+1) * 30) + " Seconds");
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
	public void testGoogleAuthURL()
	{
		OTPUserImpl user = new OTPUserImpl(true);
		System.out.println( OTPUtils.getAuthenticatorURL(user.getProvider()) );
		assertTrue(true);
	}
	
	@Test
	public void testBarcode()
	{
		OTPUserImpl user = new OTPUserImpl(true);
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
}
