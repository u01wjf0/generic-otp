# 🔐 Generic OTP for Java

**A lightweight, secure, and flexible Java library for generating and validating TOTP-based One-Time Passwords (OTP).**  
Perfect for adding two-factor authentication (2FA) to your Java applications — whether you’re using SMS/email or apps like Google Authenticator.

---

## 🚀 Quick Start

Install dependencies:

This project uses: 
- Apache Commons Codec
- ZXing for QR code generation

### Generate and Validate OTP

```java
// Create a user object (valid for 2 time steps)
OTPUserCredentialProvider user = OTPUserCredentialProvider.createBasicUserObject("user123", 2);

// Create an OTP instance
OTPImplementation otp = OTPImplementation.createInstance(user);

// Get the 6-digit OTP
String code = otp.getOTP();

// Later, validate input from user
boolean isValid = otp.validate(userInputCode);
