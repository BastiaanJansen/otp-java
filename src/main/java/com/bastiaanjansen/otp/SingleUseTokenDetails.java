package com.bastiaanjansen.otp;

public record SingleUseTokenDetails(byte[] secret, String otp) {
}
