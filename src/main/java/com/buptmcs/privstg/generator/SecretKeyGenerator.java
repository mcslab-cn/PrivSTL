package com.buptmcs.privstg.generator;

import java.util.HashMap;
import java.util.Map;

import com.buptmcs.privstg.parameters.MasterSecretKey;
import com.buptmcs.privstg.parameters.PublicKey;
import com.buptmcs.privstg.parameters.SecretKey;
import com.buptmcs.util.GeneratorUtils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SecretKeyGenerator {
    public static SecretKey keyGeneration(PublicKey publicKey, MasterSecretKey masterSecretKey, String[] userAttributes) {
        // TODO Auto-generated method stub
        PairingParameters pairingParameters = publicKey.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element sigma = pairing.getZr().newRandomElement().getImmutable();
        Element D = publicKey.getH().powZn((masterSecretKey.getAlpha().add(sigma)).div(masterSecretKey.getBeta())).getImmutable();
        Element D0 = publicKey.getH().powZn((masterSecretKey.getDelta().add(masterSecretKey.getFai()).sub(sigma)).div(masterSecretKey.getGama())).getImmutable();
        Element gSigma = publicKey.getG().powZn(sigma).getImmutable();
        Map<String, Element> D1s = new HashMap<>();
        Map<String, Element> D2s = new HashMap<>();
        for (String attribute : userAttributes) {
            byte[] hashAttri = GeneratorUtils.hash(attribute.getBytes());
            Element hAttri = pairing.getG1().newElementFromHash(hashAttri, 0, hashAttri.length).getImmutable();
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            D1s.put(attribute, gSigma.mul(hAttri.powZn(ri)));
            D2s.put(attribute, publicKey.getH().powZn(ri));
        }
        return new SecretKey(pairingParameters, D, D0, D1s, D2s);
    }
}
