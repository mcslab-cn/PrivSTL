package com.buptmcs.privstg.generator;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.security.interfaces.RSAPublicKey;

import com.buptmcs.privstg.parameters.Ciphertext;
import com.buptmcs.privstg.parameters.PublicKey;
import com.buptmcs.util.GeneratorUtils;
import com.buptmcs.util.PolicyUtil;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class CiphertextGenerator {
    public static final int dp = GeneratorUtils.dp;

    public static Ciphertext encryption(PublicKey publicKey, String accessPolicyExample, String[] ciphertextKeywords, String[] ciphertextTime, double[] ciphertextLocation, double cityLatitude) throws Exception {
        // TODO Auto-generated method stub
        int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyExample);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicyExample);
        AccessTreeEngine accessTreeEngine = new AccessTreeEngine();
        Pairing pairing = PairingFactory.getPairing(publicKey.getPairingParameters());
        AccessControlParameter accessControlParameter = accessTreeEngine.generateAccessControl(accessPolicy, rhos);

        Element EK = pairing.getGT().newRandomElement().getImmutable();
        System.out.println("EK=" + EK);
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element C0 = EK.mul(publicKey.getEghAlpha().powZn(s)).getImmutable();
        Element C1 = publicKey.getgBeta().powZn(s).getImmutable();
        Element C2 = publicKey.getG2().powZn(s).getImmutable();
        Map<String, Element> lambdas = accessTreeEngine.secretSharing(pairing, s, accessControlParameter);
        Map<String, Element> C1s = new HashMap<>();
        Map<String, Element> C2s = new HashMap<>();
        for (String rho : lambdas.keySet()) {
            C1s.put(rho, publicKey.getH().powZn(lambdas.get(rho)));
            byte[] hashrho = GeneratorUtils.hash(rho.getBytes());
            Element hrho = pairing.getG1().newElementFromHash(hashrho, 0, hashrho.length).getImmutable();
            C2s.put(rho, hrho.powZn(lambdas.get(rho)));
        }
        Map<String, Element> E1s = new HashMap<>();
        Map<String, Element> E2s = new HashMap<>();
        Element g4s = publicKey.getG4().powZn(s).getImmutable();
        for (String keyword : ciphertextKeywords) {
            Element pi = pairing.getZr().newRandomElement().getImmutable();
            byte[] hashKeyword = GeneratorUtils.hash(keyword.getBytes());
            Element hKeyword = pairing.getZr().newElementFromHash(hashKeyword, 0, hashKeyword.length).getImmutable();
            E1s.put(keyword, g4s.mul(publicKey.getG().powZn(hKeyword.mul(pi))).getImmutable());
            E2s.put(keyword, publicKey.getH2().powZn(pi).getImmutable());
        }

        Element g3s = publicKey.getG3().powZn(s).getImmutable();
        int[] ciphertextTimeInt = GeneratorUtils.timeToInt(ciphertextTime);
        int tu = ciphertextTimeInt[0];
        String tuBinary = PolicyUtil.decimal2Binary(tu, publicKey.getMaxBinaryTimeLength());
        Set<String> tu0_encodingSet = PolicyUtil.get0_encoding(tuBinary);
        Map<String, Element> T0_1s = new HashMap<>();
        Map<String, Element> T0_2s = new HashMap<>();
        for (String eti : tu0_encodingSet) {
            Element Phii = pairing.getZr().newRandomElement().getImmutable();
            byte[] hashEti = GeneratorUtils.hash(eti.getBytes());
            Element hEti = pairing.getZr().newElementFromHash(hashEti, 0, hashEti.length).getImmutable();
            T0_1s.put(eti, g3s.mul(publicKey.getG().powZn(hEti.mul(Phii))).getImmutable());
            T0_2s.put(eti, publicKey.getH2().powZn(Phii).getImmutable());
        }
        int tv = ciphertextTimeInt[1];
        String tvBinary = PolicyUtil.decimal2Binary(tv, publicKey.getMaxBinaryTimeLength());
        Set<String> tv1_encodingSet = PolicyUtil.get1_encoding(tvBinary);
        Map<String, Element> T1_1s = new HashMap<>();
        Map<String, Element> T1_2s = new HashMap<>();
        for (String etj : tv1_encodingSet) {
            Element muj = pairing.getZr().newRandomElement().getImmutable();
            byte[] hashEtj = GeneratorUtils.hash(etj.getBytes());
            Element hEtj = pairing.getZr().newElementFromHash(hashEtj, 0, hashEtj.length).getImmutable();
            T1_1s.put(etj, g3s.mul(publicKey.getG().powZn(hEtj.mul(muj))).getImmutable());
            T1_2s.put(etj, publicKey.getH2().powZn(muj).getImmutable());
        }

        double[] coord = GeneratorUtils.latLngToCoord(ciphertextLocation, cityLatitude);
        Random rand = new Random(Integer.MAX_VALUE);
        BigInteger ranNum1 = BigInteger.valueOf(rand.nextInt(Integer.MAX_VALUE));

        BigInteger lu = BigInteger.valueOf((int) coord[0]);
        BigInteger lv = BigInteger.valueOf((int) coord[1]);

        BigInteger e0 = lu.pow(2).add(lv.pow(2));
        BigInteger e1 = lu.add(lu);
        BigInteger e2 = lv.add(lv);
        BigInteger e3 = BigInteger.valueOf(1);

        RSAPublicKey publicKey1 = publicKey.getRSAPublicKey1();
        RSAPublicKey publicKey2 = publicKey.getRSAPublicKey2();

        BigInteger G0 = RSAEncryption.encrypt(e0.multiply(ranNum1), publicKey2.getPublicExponent(), publicKey2.getModulus());
        BigInteger G1 = RSAEncryption.encrypt(e1.multiply(ranNum1), publicKey2.getPublicExponent(), publicKey2.getModulus());
        BigInteger G2 = RSAEncryption.encrypt(e2.multiply(ranNum1), publicKey2.getPublicExponent(), publicKey2.getModulus());
        BigInteger G3 = RSAEncryption.encrypt(e3.multiply(ranNum1), publicKey2.getPublicExponent(), publicKey2.getModulus());

        BigInteger E0 = RSAEncryption.encrypt(G0, publicKey1.getPublicExponent(), publicKey1.getModulus());
        BigInteger E1 = RSAEncryption.encrypt(G1, publicKey1.getPublicExponent(), publicKey1.getModulus());
        BigInteger E2 = RSAEncryption.encrypt(G2, publicKey1.getPublicExponent(), publicKey1.getModulus());
        BigInteger E3 = RSAEncryption.encrypt(G3, publicKey1.getPublicExponent(), publicKey1.getModulus());
        return new Ciphertext(publicKey.getPairingParameters(), C0, C1, C2, C1s, C2s, E1s, E2s, T0_1s, T0_2s, T1_1s, T1_2s,
                E0, E1, E2, E3, accessPolicy, rhos);
    }

}
