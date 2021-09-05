package test.entities;

import com.wfraser.security.exceptions.OTPGenericException;
import com.wfraser.security.otp.OTPUserCredentialProvider;

public class OTPUserImpl {

	OTPUserCredentialProvider provider;
	public OTPUserImpl(boolean forGoogleAuth, boolean forNewGoogleAuth) throws OTPGenericException
	{
		if(forGoogleAuth)
			provider = OTPUserCredentialProvider.createAuthenticatorUserObject(getSecretKey(), getUserID(), getCompany(), getAllowedSteps());
		else if(forNewGoogleAuth)
			provider = OTPUserCredentialProvider.createNewAuthenticatorUserObject( getUserID(), getAllowedSteps(), getCompany() );
		else
			provider = OTPUserCredentialProvider.createBasicUserObject(getUserID(), getAllowedSteps());
		
	}

	public String getSecretKey() {

		return "CKW5OXOSEB2KLRVWXGBRJIQR5TNKQ54L";
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
