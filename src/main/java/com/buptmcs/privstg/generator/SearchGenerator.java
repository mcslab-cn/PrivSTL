package com.buptmcs.privstg.generator;

import java.math.BigInteger;
import java.util.Map;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


import com.buptmcs.privstg.parameters.Ciphertext;
import com.buptmcs.privstg.parameters.CiphertextCandDecryptA;
import com.buptmcs.privstg.parameters.PublicKey;
import com.buptmcs.privstg.parameters.ServerASecretKey;
import com.buptmcs.privstg.parameters.ServerBSecretKey;
import com.buptmcs.privstg.parameters.Token;
import com.buptmcs.privstg.parameters.TransformationKey;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SearchGenerator {
    public static CiphertextCandDecryptA search(PublicKey publicKey, Ciphertext ciphertext, Token token, TransformationKey transformationKey,
                                                ServerASecretKey serverAKey, ServerBSecretKey serverBKey) throws UnsatisfiedAccessControlException, PolicySyntaxException {
        // TODO Auto-generated method stub
        Pairing pairing = PairingFactory.getPairing(publicKey.getPairingParameters());

        RSAPrivateKey privateKey1 = serverAKey.getRSAPrivateKey1();
        RSAPrivateKey privateKey2 = serverBKey.getRSAPrivateKey2();
        RSAPublicKey publicKey2 = publicKey.getRSAPublicKey2();

        BigInteger X0 = RSAEncryption.decrypt(ciphertext.getE0(), privateKey1.getPrivateExponent(), privateKey1.getModulus());
        BigInteger Y0 = RSAEncryption.decrypt(token.getV0(), privateKey1.getPrivateExponent(), privateKey1.getModulus());
        BigInteger X1 = RSAEncryption.decrypt(ciphertext.getE1(), privateKey1.getPrivateExponent(), privateKey1.getModulus());
        BigInteger X2 = RSAEncryption.decrypt(ciphertext.getE2(), privateKey1.getPrivateExponent(), privateKey1.getModulus());
        BigInteger Y1 = RSAEncryption.decrypt(token.getV1(), privateKey1.getPrivateExponent(), privateKey1.getModulus());
        BigInteger Y2 = RSAEncryption.decrypt(token.getV2(), privateKey1.getPrivateExponent(), privateKey1.getModulus());
        BigInteger X3 = RSAEncryption.decrypt(ciphertext.getE3(), privateKey1.getPrivateExponent(), privateKey1.getModulus());
        BigInteger Y3 = RSAEncryption.decrypt(token.getV3(), privateKey1.getPrivateExponent(), privateKey1.getModulus());

        BigInteger L0 = RSAEncryption.multi(X0, Y0, publicKey2.getModulus());
        BigInteger L1 = RSAEncryption.multi(X1, Y1, publicKey2.getModulus());
        BigInteger L2 = RSAEncryption.multi(X2, Y2, publicKey2.getModulus());
        BigInteger L3 = RSAEncryption.multi(X3, Y3, publicKey2.getModulus());

        BigInteger M0 = RSAEncryption.decrypt(L0, privateKey2.getPrivateExponent(), privateKey2.getModulus());
        BigInteger M1 = RSAEncryption.decrypt(L1, privateKey2.getPrivateExponent(), privateKey2.getModulus());
        BigInteger M2 = RSAEncryption.decrypt(L2, privateKey2.getPrivateExponent(), privateKey2.getModulus());
        BigInteger M3 = RSAEncryption.decrypt(L3, privateKey2.getPrivateExponent(), privateKey2.getModulus());

        BigInteger fl = M0.add(M3).subtract(M2).subtract(M1);

        int dFL = fl.signum();

        if (dFL > 0) {
            return null;
        }

        Element b01 = (token.getB0().powZn(serverAKey.getAlphai().invert())).mul(token.getB1().powZn(serverAKey.getBetai().invert())).getImmutable();

        Map<String, Element> T0_1s = ciphertext.getT0_1s();
        Map<String, Element> T0_2s = ciphertext.getT0_2s();
        Map<String, Element> W1_1s = token.getW1_1s();
        Map<String, Element> W1_2s = token.getW1_2s();
        Element FT0 = pairing.getGT().newOneElement().getImmutable();
        for (String encoding : T0_1s.keySet()) {
            if (W1_1s.containsKey(encoding)) {
                FT0 = pairing.pairing(W1_1s.get(encoding), T0_1s.get(encoding)).div(pairing.pairing(W1_2s.get(encoding).div(b01), T0_2s.get(encoding))).getImmutable();
                break;
            }
        }
        Map<String, Element> T1_1s = ciphertext.getT1_1s();
        Map<String, Element> T1_2s = ciphertext.getT1_2s();
        Map<String, Element> W0_1s = token.getW0_1s();
        Map<String, Element> W0_2s = token.getW0_2s();
        Element FT1 = pairing.getGT().newOneElement().getImmutable();
        for (String encoding : T1_1s.keySet()) {
            if (W0_1s.containsKey(encoding)) {
                FT1 = pairing.pairing(W0_1s.get(encoding), T1_1s.get(encoding)).div(pairing.pairing(W0_2s.get(encoding).div(b01), T1_2s.get(encoding))).getImmutable();
                break;
            }
        }
        Element FT = FT1.mul(FT0).getImmutable();

        int[][] searchKeywordsCondition = token.getSearchKeywordsCondition();
        String[] keywords = token.getKeywords();
        AccessTreeEngine searchTreeEngine = new AccessTreeEngine();
        AccessControlParameter searchTreeParameters = searchTreeEngine.generateAccessControl(searchKeywordsCondition, keywords);
        Map<String, Element> searchOmegaElementsMap = searchTreeEngine.reconstructOmegas(pairing, ciphertext.getCiphertextKeywords(), searchTreeParameters);
        Element FS = pairing.getGT().newOneElement().getImmutable();
        for (String keyword : searchOmegaElementsMap.keySet()) {
            Element E1x = ciphertext.getE1s().get(keyword).getImmutable();
            Element E2x = ciphertext.getE2s().get(keyword).getImmutable();
            Element B1x = token.getB1s().get(keyword).getImmutable();
            Element B2x = token.getB2s().get(keyword).getImmutable();
            Element searchLambda = searchOmegaElementsMap.get(keyword).getImmutable();
            FS = FS.mul(pairing.pairing(E1x, B1x).div(pairing.pairing(E2x, B2x.div(b01))).powZn(searchLambda)).getImmutable();
        }

        int[][] accessPolicy = ciphertext.getAccessPolicy();
        String[] rhos = ciphertext.getRhos();
        AccessTreeEngine accessTreeEngine = new AccessTreeEngine();
        AccessControlParameter accessControlParameter = accessTreeEngine.generateAccessControl(accessPolicy, rhos);
        Map<String, Element> decryptOmegaElementsMap = accessTreeEngine.reconstructOmegas(pairing, transformationKey.getAttributes(), accessControlParameter);
        Element FR = pairing.getGT().newOneElement().getImmutable();
        for (String attribute : decryptOmegaElementsMap.keySet()) {
            Element D1xp = transformationKey.getD1sp().get(attribute).getImmutable();
            Element D2xp = transformationKey.getD2sp().get(attribute).getImmutable();
            Element C1x = ciphertext.getC1s().get(attribute).getImmutable();
            Element C2x = ciphertext.getC2s().get(attribute).getImmutable();
            Element decryptLambda = decryptOmegaElementsMap.get(attribute).getImmutable();
            FR = FR.mul(pairing.pairing(D1xp, C1x).div(pairing.pairing(D2xp, C2x)).powZn(decryptLambda)).getImmutable();
        }
        boolean a = pairing.pairing(ciphertext.getC2(), transformationKey.getD0p()).mul(FR.powZn(serverBKey.getAlphai())).equals(FS.mul(FT));

        if (a) {
            Element A = pairing.pairing(ciphertext.getC1(), transformationKey.getDp()).div(FR).getImmutable();
            return new CiphertextCandDecryptA(publicKey.getPairingParameters(), ciphertext.getC0(), A);
        } else {
            return null;
        }

    }


}
