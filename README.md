# OTP-Java

![](https://github./BastiaanJansen/OTP-Java/workflows/Build/badge.svg)
![](https://github.com/BastiaanJansen/OTP-Java/workflows/Test/badge.svg)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/df7c6f4a7e5a4692af2f78cf16266fdd)](https://app.codacy.com/gh/BastiaanJansen/OTP-Java?utm_source=github.com&utm_medium=referral&utm_content=BastiaanJansen/OTP-Java&utm_campaign=Badge_Grade_Settings)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/6eeb888f65db4c168435e739cb7c84e3)](https://www.codacy.com/gh/BastiaanJansen/Toast-Swift/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=BastiaanJansen/Toast-Swift&amp;utm_campaign=Badge_Grade)
![](https://img.shields.io/github/license/BastiaanJansen/OTP-Java)
![](https://img.shields.io/github/issues/BastiaanJansen/OTP-Java)

A small and easy-to-use one-time password generator for Java according to [RFC 4226](https://tools.ietf.org/html/rfc4226) (HOTP) and [RFC 6238](https://tools.ietf.org/html/rfc6238) (TOTP).

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
    * [HOTP (Counter-based one-time passwords)](#hotp-counter-based-one-time-passwords)
    * [TOTP (Time-based one-time passwords)](#totp-time-based-one-time-passwords)

## Features
The following features are supported:
1. Generation of secrets
2. Time-based one-time password (TOTP, RFC 6238) generation based on current time, specific time, OTPAuth URI and more for different HMAC algorithms.
3. HMAC-based one-time password (HOTP, RFC 4226) generation based on counter and OTPAuth URI.
4. Verification of one-time passwords
5. Generation of OTP Auth URI's

## Installation
### Maven
```xml
<dependency>
    <groupId>com.github.bastiaanjansen</groupId>
    <artifactId>otp-java</artifactId>
    <version>1.2.0</version>
</dependency>
```

### Gradle
```gradle
implementation 'com.github.bastiaanjansen:otp-java:1.2.0'
```

### Scala SBT
```scala
libraryDependencies += "com.github.bastiaanjansen" % "otp-java" % "1.2.0"
```

### Apache Ivy
```xml
<dependency org="com.github.bastiaanjansen" name="otp-java" rev="1.2.0" />
```

Or you can download the source from the [GitHub releases page](https://github.com/BastiaanJansen/OTP-Java/releases).

## Usage
### HOTP (Counter-based one-time passwords)
#### Initialization HOTP instance
To create a `HOTPGenerator` use the `HOTPGenerator.Builder` class as follows:

```java
byte[] secret = "VV3KOX7UQJ4KYAKOHMZPPH3US4CJIMH6F3ZKNB5C2OOBQ6V2KIYHM27Q".getBytes();
HOTPGenerator.Builder builder = new HOTPGenerator.Builder(secret);
HOTPGenerator hotp = builder.build();
```
The above builder creates a HOTPGenerator instance with default values for passwordLength = 6 and algorithm = SHA1. Use the builder to change these defaults:
```java
HOTPGenerator.Builder builder = new HOTPGenerator.Builder(secret);
builder
  .withPasswordLength(8)
  .withAlgorithm(HMACAlgorithm.SHA256);

HOTPGenerator hotp = builder.build();
```

When you don't already have a secret, you can let the library generate it:
```java
// To generate a secret with 160 bits
byte[] secret = SecretGenerator.generate();

// To generate a secret with a custom amount of bits
byte[] secret = SecretGenerator.generate(512);
```

It is also possible to create a HOTPGenerator instance based on an OTPAuth URI. When algorithm or digits are not specified, the default values will be used.
```java
URI uri = new URI("otpauth://hotp/issuer?secret=ABCDEFGHIJKLMNOP&algorithm=SHA1&digits=6&counter=8237");
HOTPGenerator hotp = HOTPGenerator.Builder.fromOTPAuthURI(uri);
```

Get information about the generator:

```java
byte[] secret = hotp.getSecret();
int passwordLength = hotp.getPasswordLength(); // 6
HMACAlgorithm algorithm = hotp.getAlgorithm(); // HMACAlgorithm.SHA1
```

#### Generation of HOTP code
After creating an instance of the HOTPGenerator class, a code can be generated by using the `generate()` method:
```java
try {
    int counter = 5;
    String code = hotp.generate(counter);
    
    // To verify a token:
    boolean isValid = hotp.verify(code, counter);
    
    // Or verify with a delay window
    boolean isValid = hotp.verify(code, counter, 2);
} catch (IllegalStateException e) {
    // Handle error
}
```

### TOTP (Time-based one-time passwords)
#### Initialization TOTP instance
TOTPGenerator can accept more paramaters: `passwordLength`, `period`, `algorithm` and `secret`. The default values are: passwordLength = 6, period = 30 and algorithm = SHA1.

```java
// Generate a secret (or use your own secret)
byte[] secret = SecretGenerator.generate();

TOTPGenerator.Builder builder = new TOTPGenerator.Builder(secret);

builder
    .withPasswordLength(6)
    .withAlgorithm(HMACAlgorithm.SHA1) // SHA256 and SHA512 are also supported
    .withPeriod(Duration.ofSeconds(30));
    
TOTPGenerator totp = builder.build();
```
Or create a `TOTPGenerator` instance from an OTPAuth URI:
```java
URI uri = new URI("otpauth://totp/issuer?secret=ABCDEFGHIJKLMNOP&algorithm=SHA1&digits=6&period=30");
TOTPGenerator totp = TOTPGenerator.Builder.fromOTPAuthURI(uri);
```

Get information about the generator:
```java
byte[] secret = totp.getSecret();
int passwordLength = totp.getPasswordLength(); // 6
HMACAlgorithm algorithm = totp.getAlgorithm(); // HMACAlgorithm.SHA1
Duration period = totp.getPeriod(); // Duration.ofSeconds(30)
```

#### Generation of TOTP code
After creating an instance of the TOTPGenerator class, a code can be generated by using the `generate()` method, similarly with the HOTPGenerator class:
```java
try {
    String code = totp.generate();
     
    // To verify a token:
    boolean isValid = totp.verify(code);
} catch (IllegalStateException e) {
    // Handle error
}
```
The above code will generate a time-based one-time password based on the current time. The API supports, besides the current time, the creation of codes based on `timeSince1970` in milliseconds, `Date`, and `Instant`:

```java
try {
    // Based on current time
    totp.generate();
    
    // Based on specific date
    totp.generate(new Date());
    
    // Based on milliseconds past 1970
    totp.generate(9238346823);
    
    // Based on an instant
    totp.generate(Instant.now());
} catch (IllegalStateException e) {
    // Handle error
}
```

### Generation of OTPAuth URI's
To easily generate a OTPAuth URI for easy on-boarding, use the `getURI()` method for both `HOTPGenerator` and `TOTPGenerator`. Example for `TOTPGenerator`:
```java
TOTPGenerator totp = new TOTPGenerator.Builder(secret).build();

URI uri = totp.getURI("issuer", "account"); // otpauth://totp/issuer:account?period=30&digits=6&secret=SECRET&algorithm=SHA1

```

## Licence
OTP-Java is available under the MIT licence. See the LICENCE for more info.

[![Stargazers repo roster for @BastiaanJansen/OTP-Java](https://reporoster.com/stars/BastiaanJansen/OTP-Java)](https://github.com/BastiaanJansen/OTP-Java/stargazers)
