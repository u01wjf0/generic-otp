package test.entities;

import com.wfraser.security.otp.OTPUserCredentialProvider;

public class OTPUserImpl {

	OTPUserCredentialProvider provider;
	public OTPUserImpl(boolean forGoogleAuth)
	{
		if(forGoogleAuth)
			provider = OTPUserCredentialProvider.createAuthenticatorUserObject(getSecretKey(), getUserID(), getCompany(), getAllowedSteps());
		else
			provider = OTPUserCredentialProvider.createBasicUserObject(getUserID(), getAllowedSteps());
	}

	public String getSecretKey() {

		return "UQCWFOUOSMFWPFPAGFDDPEVZ5SZDMOSJ";
	}

	public String getUserID() {
		return "USERA";
	}
	
	public String getCompany() {
		return "COMPANYA";
	}

	public int getAllowedSteps() {
		return 2;
	}
	
	public OTPUserCredentialProvider getProvider()
	{
		return provider;
	}

}
