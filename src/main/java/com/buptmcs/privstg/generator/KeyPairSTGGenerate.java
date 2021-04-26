package com.buptmcs.privstg.generator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.buptmcs.privstg.parameters.KeyPairSTG;
import com.buptmcs.privstg.parameters.MasterSecretKey;
import com.buptmcs.privstg.parameters.PublicKey;
import com.buptmcs.privstg.parameters.ServerASecretKey;
import com.buptmcs.privstg.parameters.ServerBSecretKey;
import com.buptmcs.util.GeneratorUtils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public class KeyPairSTGGenerate {
    public static final int dp = GeneratorUtils.dp;

    public static KeyPairSTG setup(int maxSearchLength, int maxBinaryTimeLength) throws Exception {
        // TODO Auto-generated method stub
        TypeACurveGenerator typeACurveGenerator = new TypeACurveGenerator(80, 256);
        PairingParameters pairingParameters = typeACurveGenerator.generate();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);

        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element alpha_1 = pairing.getZr().newRandomElement().getImmutable();
        Element alpha_2 = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element beta_1 = pairing.getZr().newRandomElement().getImmutable();
        Element gama = pairing.getZr().newRandomElement().getImmutable();
        Element delta = pairing.getZr().newRandomElement().getImmutable();
        Element fai = pairing.getZr().newRandomElement().getImmutable();

        Element eghAlpha = pairing.pairing(g, h).powZn(alpha).getImmutable();
        Element gBeta = g.powZn(beta).getImmutable();

        Element g1 = g.powZn(alpha_1).getImmutable();
        Element w1 = g.powZn(beta_1).getImmutable();
        Element g2 = g.powZn(alpha_2.mul(gama)).getImmutable();
        Element h1 = h.powZn(alpha_1.mul(gama)).getImmutable();
        Element h2 = h.powZn(alpha_2).getImmutable();
        Element g3 = g.powZn(delta).getImmutable();
        Element g4 = g.powZn(fai).getImmutable();

        KeyPair keyPair1 = null;
        KeyPair keyPair2 = null;
        RSAPublicKey publicKey1 = null;
        RSAPublicKey publicKey2 = null;
        BigInteger N1 = BigInteger.ZERO;
        BigInteger N2 = BigInteger.ZERO;
        while (true) {
            keyPair1 = RSAEncryption.genKeyPair();
            keyPair2 = RSAEncryption.genKeyPair();

            publicKey1 = (RSAPublicKey) keyPair1.getPublic();
            publicKey2 = (RSAPublicKey) keyPair2.getPublic();

            N1 = publicKey1.getModulus();
            N2 = publicKey2.getModulus();

            if (publicKey1.getModulus().compareTo(publicKey2.getModulus()) == 1) {
                break;
            }
        }

        RSAPrivateKey privateKey1 = (RSAPrivateKey) keyPair1.getPrivate();
        RSAPrivateKey privateKey2 = (RSAPrivateKey) keyPair2.getPrivate();
        return new KeyPairSTG(new PublicKey(pairingParameters, g, h, eghAlpha, gBeta, g1, w1, g2, h1, h2, g3, g4,
                N1, N2, publicKey1, publicKey2, maxBinaryTimeLength),
                new MasterSecretKey(pairingParameters, alpha, beta, gama, delta, fai),
                new ServerASecretKey(pairingParameters, alpha_1, beta_1, privateKey1),
                new ServerBSecretKey(pairingParameters, alpha_2, privateKey2));
    }

}
