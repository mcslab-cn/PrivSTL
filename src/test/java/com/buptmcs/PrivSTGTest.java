package com.buptmcs;


import com.buptmcs.example.DataOwnerNeedToKnow;
import com.buptmcs.example.DataUserNeedToKnow;
import com.buptmcs.example.TrustedAuthorityNeedToKnow;
import com.buptmcs.privstg.generator.*;
import com.buptmcs.privstg.geotree.GeoTree;
import com.buptmcs.privstg.geotree.Node;
import com.buptmcs.privstg.parameters.*;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public class PrivSTGTest {

    @Test
    public void test() throws Exception {
        //Service Initialization
        int maxSearchLength = TrustedAuthorityNeedToKnow.maxSearchLength;
        int maxBinaryTimeLength = TrustedAuthorityNeedToKnow.maxBinaryTimeLength;
        KeyPairSTG keyPair = KeyPairSTGGenerate.setup(maxSearchLength, maxBinaryTimeLength);
        PublicKey publicKey = keyPair.getPublicKey();
        MasterSecretKey masterSecretKey = keyPair.getMasterSecretKey();
        ServerASecretKey serverAKey = keyPair.getServerASecretKey();
        ServerBSecretKey serverBKey = keyPair.getServerBSecretKey();
        String[] childrenGeoHash = new String[]{"wx4d", "wx4e", "wx4f", "wx4g", "wx4s", "wx4u"};
        GeoTree geoTree = new GeoTree(childrenGeoHash, publicKey, masterSecretKey);

        //Key Generation
        String[] userAttributes = TrustedAuthorityNeedToKnow.userAttributes;
        SecretKey secretKey = SecretKeyGenerator.keyGeneration(publicKey, masterSecretKey, userAttributes);

        TransformationkeyAndDelegationKey transformationkeyAndDelegationKey = TransformGenerator.transform(secretKey, userAttributes);
        TransformationKey transformationKey = transformationkeyAndDelegationKey.getTransformationKey();
        RetrieveKey delegationKey = transformationkeyAndDelegationKey.getDelegationKey();

        //Data Outsourcing
        String accessPolicyExample = DataOwnerNeedToKnow.accessPolicyExample;
        String[] ciphertextKeywords = DataOwnerNeedToKnow.ciphertextKeywords;
        String[] ciphertextTime = DataOwnerNeedToKnow.ciphertextTime;
        double cityLatitude = DataOwnerNeedToKnow.cityLatitude;
        double[] ciphertextLocation = DataOwnerNeedToKnow.ciphertextLocation;
        Ciphertext ciphertext = CiphertextGenerator.encryption(publicKey, accessPolicyExample, ciphertextKeywords, ciphertextTime, ciphertextLocation, cityLatitude);
        GT ciphertextGT = GTGenerator.generateGT(publicKey, ciphertextLocation);
        CiphertextAndGT ciphertextAndGT = new CiphertextAndGT(ciphertext, ciphertextGT);

        GeoTree geoTreeWithCiphertexts = GridComGenerator.addCiphertext2GeoTree(geoTree, ciphertextAndGT);


        //Trapdoor Generation
        String searchKeywordsConditionExample = DataUserNeedToKnow.searchKeywordsConditionExample;
        String[] searchTimeCondition = DataUserNeedToKnow.searchTimeCondition;
        double[] searchLocationCondition = DataUserNeedToKnow.searchLocationCondition;
        int searchRange = DataUserNeedToKnow.searchRange;
        Token token = TokenGenerator.tokenGeneration(publicKey, transformationKey, searchKeywordsConditionExample,
                searchTimeCondition, searchLocationCondition, searchRange, cityLatitude, delegationKey);
        GT tokenGT = GTGenerator.generateGT(publicKey, searchLocationCondition);
        TokenAndGT tokenAndGT = new TokenAndGT(token, tokenGT);


        //Search and Decryption Delegation
        Node node = GridComGenerator.judgeSearchNode(geoTreeWithCiphertexts, tokenAndGT.getGt());
        Set<String> adjacentNodeId = node.getAdjacentNodeId();
        Set<CiphertextCandDecryptA> resultSet = new HashSet<>();
        for (String id : adjacentNodeId) {
            Node adjacentNode = geoTreeWithCiphertexts.getL6NodeMap().get(id);
            Set<Ciphertext> ciphertextSet = adjacentNode.getCiphertexts();
            for (Ciphertext childCiphertext : ciphertextSet) {
                CiphertextCandDecryptA ciphertextCandDecryptA = SearchGenerator.search(publicKey, childCiphertext, token, transformationKey, serverAKey, serverBKey);
                resultSet.add(ciphertextCandDecryptA);
            }
        }


        //Final Decryption
        if (resultSet.size() == 0) {
            System.out.println("fail to meet the condition!");
        } else {
            for (CiphertextCandDecryptA result : resultSet) {
                Element DK = DecryptionGenerator.decrypt(result, delegationKey);
                System.out.println("DK=" + DK);
            }
        }
    }

}
