package com.tesla.easyso1;

public class VerificationResult {
    public boolean isValid;
    public String errorMessage;
    public String encryptedValue;

    public VerificationResult(boolean isValid, String errorMessage, String encryptedValue) {
        this.isValid = isValid;
        this.errorMessage = errorMessage;
        this.encryptedValue = encryptedValue;
    }
}
