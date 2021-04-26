package com.buptmcs.privstg.generator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RSAEncryption {

    private static final int KEYSIZE = 1024;

    public static KeyPair genKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(KEYSIZE, new SecureRandom());

        KeyPair keyPair = keyPairGen.generateKeyPair();
        return keyPair;
    }

    public static BigInteger encrypt(BigInteger m, BigInteger e, BigInteger n) {
        BigInteger cipher = m.modPow(e, n);
        return cipher;
    }

    public static BigInteger decrypt(BigInteger c, BigInteger d, BigInteger n) {
        BigInteger message = c.modPow(d, n);
        return message;
    }

    public static BigInteger multi(BigInteger c1, BigInteger c2, BigInteger n) {
        BigInteger c = c1.multiply(c2).mod(n);
        return c;
    }
}
