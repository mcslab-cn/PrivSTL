package com.buptmcs.privstg.generator;

import java.util.HashMap;
import java.util.Map;

import com.buptmcs.privstg.parameters.RetrieveKey;
import com.buptmcs.privstg.parameters.SecretKey;
import com.buptmcs.privstg.parameters.TransformationKey;
import com.buptmcs.privstg.parameters.TransformationkeyAndDelegationKey;
import com.buptmcs.util.GeneratorUtils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class TransformGenerator {
    public static TransformationkeyAndDelegationKey transform(SecretKey secretKey, String[] userAttributes) {
        PairingParameters pairingParameters = secretKey.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element tau = pairing.getZr().newRandomElement().getImmutable();
        StringBuilder sb = new StringBuilder();
        for (String attribute : userAttributes) {
            sb.append(attribute);
        }
        sb.append(tau.toString());
        byte[] hashSb = GeneratorUtils.hash(sb.toString().getBytes());
        Element id = pairing.getZr().newElementFromHash(hashSb, 0, hashSb.length).getImmutable();
        Element Dp = secretKey.getD().powZn(tau).getImmutable();
        Element D0p = secretKey.getD0().powZn(tau).getImmutable();
        Map<String, Element> D1sp = new HashMap<>();
        Map<String, Element> D2sp = new HashMap<>();
        for (String attribute : secretKey.getD1s().keySet()) {
            D1sp.put(attribute, secretKey.getD1s().get(attribute).powZn(tau));
            D2sp.put(attribute, secretKey.getD2s().get(attribute).powZn(tau));
        }
        return new TransformationkeyAndDelegationKey(new TransformationKey(pairingParameters, id, Dp, D0p, D1sp, D2sp), new RetrieveKey(pairingParameters, tau));
    }

}
