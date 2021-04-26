package com.buptmcs.privstg.generator;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.security.interfaces.RSAPublicKey;

import com.buptmcs.privstg.parameters.PublicKey;
import com.buptmcs.privstg.parameters.Token;
import com.buptmcs.privstg.parameters.TransformationKey;
import com.buptmcs.privstg.parameters.RetrieveKey;
import com.buptmcs.util.GeneratorUtils;
import com.buptmcs.util.PolicyUtil;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class TokenGenerator {
    public static final int dp = GeneratorUtils.dp;

    public static Token tokenGeneration(PublicKey publicKey, TransformationKey transformationKey, String searchKeywordsConditionExample, String[] searchTimeCondition, double[] searchLocationCondition,
                                        int searchRange, double cityLatitude, RetrieveKey delegationKey) throws IOException, ClassNotFoundException, PolicySyntaxException {
        // TODO Auto-generated method stub
        int[][] searchKeywordsCondition = ParserUtils.GenerateAccessPolicy(searchKeywordsConditionExample);
        String[] keywords = ParserUtils.GenerateRhos(searchKeywordsConditionExample);
        AccessTreeEngine searchTreeEngine = new AccessTreeEngine();
        Pairing pairing = PairingFactory.getPairing(publicKey.getPairingParameters());
        Element tau = delegationKey.getTau().getImmutable();

        Element rho0 = pairing.getZr().newRandomElement().getImmutable();
        Element rho1 = pairing.getZr().newRandomElement().getImmutable();
        Element B0 = publicKey.getG1().powZn(rho0).getImmutable();
        Element B1 = publicKey.getW1().powZn(rho1).getImmutable();

        Element grho01 = publicKey.getG().powZn(rho0.add(rho1)).getImmutable();
        AccessControlParameter searchTreeParameter = searchTreeEngine.generateAccessControl(searchKeywordsCondition, keywords);
        Map<String, Element> lambdas = searchTreeEngine.secretSharing(pairing, tau, searchTreeParameter);
        Map<String, Element> B1s = new HashMap<>();
        Map<String, Element> B2s = new HashMap<>();
        for (String keyword : lambdas.keySet()) {
            B1s.put(keyword, publicKey.getH2().powZn(lambdas.get(keyword)).getImmutable());
            byte[] hashKeyword = GeneratorUtils.hash(keyword.getBytes());
            Element hKeyword = pairing.getZr().newElementFromHash(hashKeyword, 0, hashKeyword.length).getImmutable();
            B2s.put(keyword, publicKey.getG().powZn(hKeyword.mul(lambdas.get(keyword))).mul(grho01).getImmutable());
        }

        int[] searchTimeInt = GeneratorUtils.timeToInt(searchTimeCondition);
        Element rho = pairing.getZr().newRandomElement().getImmutable();
        int tb = searchTimeInt[1];
        String tbBinary = PolicyUtil.decimal2Binary(tb, publicKey.getMaxBinaryTimeLength());
        Set<String> tb0_encodingSet = PolicyUtil.get0_encoding(tbBinary);
        Map<String, Element> W0_1s = new HashMap<>();
        Map<String, Element> W0_2s = new HashMap<>();
        for (String eti : tb0_encodingSet) {
            W0_1s.put(eti, publicKey.getH2().powZn(tau.sub(rho)).getImmutable());
            byte[] hashEti = GeneratorUtils.hash(eti.getBytes());
            Element hEti = pairing.getZr().newElementFromHash(hashEti, 0, hashEti.length).getImmutable();
            W0_2s.put(eti, publicKey.getG().powZn(hEti.mul(tau.sub(rho))).mul(grho01).getImmutable());
        }
        int ta = searchTimeInt[0];
        String taBinary = PolicyUtil.decimal2Binary(ta, publicKey.getMaxBinaryTimeLength());
        Set<String> ta1_encodingSet = PolicyUtil.get1_encoding(taBinary);
        Map<String, Element> W1_1s = new HashMap<>();
        Map<String, Element> W1_2s = new HashMap<>();
        for (String etj : ta1_encodingSet) {
            W1_1s.put(etj, publicKey.getH2().powZn(rho).getImmutable());
            byte[] hashEtj = GeneratorUtils.hash(etj.getBytes());
            Element hEtj = pairing.getZr().newElementFromHash(hashEtj, 0, hashEtj.length).getImmutable();
            W1_2s.put(etj, publicKey.getG().powZn(hEtj.mul(rho)).mul(grho01).getImmutable());
        }

        double[] coord = GeneratorUtils.latLngToCoord(searchLocationCondition, cityLatitude);
        Random rand = new Random(Integer.MAX_VALUE);
        BigInteger ranNum2 = BigInteger.valueOf(rand.nextInt(Integer.MAX_VALUE));

        BigInteger la = BigInteger.valueOf((int) coord[0]);
        BigInteger lb = BigInteger.valueOf((int) coord[1]);
        BigInteger ld = BigInteger.valueOf(searchRange);

        BigInteger v0 = BigInteger.valueOf(1);
        BigInteger v1 = la;
        BigInteger v2 = lb;
        BigInteger v3 = la.pow(2).add(lb.pow(2)).subtract(ld.pow(2));

        RSAPublicKey publicKey1 = publicKey.getRSAPublicKey1();
        RSAPublicKey publicKey2 = publicKey.getRSAPublicKey2();

        BigInteger U0 = RSAEncryption.encrypt(v0.multiply(ranNum2), publicKey2.getPublicExponent(), publicKey2.getModulus());
        BigInteger U1 = RSAEncryption.encrypt(v1.multiply(ranNum2), publicKey2.getPublicExponent(), publicKey2.getModulus());
        BigInteger U2 = RSAEncryption.encrypt(v2.multiply(ranNum2), publicKey2.getPublicExponent(), publicKey2.getModulus());
        BigInteger U3 = RSAEncryption.encrypt(v3.multiply(ranNum2), publicKey2.getPublicExponent(), publicKey2.getModulus());

        BigInteger V0 = RSAEncryption.encrypt(U0, publicKey1.getPublicExponent(), publicKey1.getModulus());
        BigInteger V1 = RSAEncryption.encrypt(U1, publicKey1.getPublicExponent(), publicKey1.getModulus());
        BigInteger V2 = RSAEncryption.encrypt(U2, publicKey1.getPublicExponent(), publicKey1.getModulus());
        BigInteger V3 = RSAEncryption.encrypt(U3, publicKey1.getPublicExponent(), publicKey1.getModulus());

        Element id = transformationKey.getId();
        return new Token(publicKey.getPairingParameters(), id, B1s, B2s, W0_1s, W0_2s, W1_1s, W1_2s, B0, B1,
                V0, V1, V2, V3, searchKeywordsCondition, keywords);
    }

}
