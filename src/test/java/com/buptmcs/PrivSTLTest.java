package com.buptmcs;


import com.buptmcs.example.DataOwnerNeedToKnow;
import com.buptmcs.example.DataUserNeedToKnow;
import com.buptmcs.example.TrustedAuthorityNeedToKnow;
import com.buptmcs.privstg.generator.*;
import com.buptmcs.privstg.parameters.*;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.Test;

public class PrivSTLTest {

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


        //Trapdoor Generation
        String searchKeywordsConditionExample = DataUserNeedToKnow.searchKeywordsConditionExample;
        String[] searchTimeCondition = DataUserNeedToKnow.searchTimeCondition;
        double[] searchLocationCondition = DataUserNeedToKnow.searchLocationCondition;
        int searchRange = DataUserNeedToKnow.searchRange;
        Token token = TokenGenerator.tokenGeneration(publicKey, transformationKey, searchKeywordsConditionExample, searchTimeCondition, searchLocationCondition, searchRange, cityLatitude, delegationKey);

        //Search and Decryption Delegation
        CiphertextCandDecryptA ciphertextCandDecryptA = SearchGenerator.search(publicKey, ciphertext, token, transformationKey, serverAKey, serverBKey);


        //Final Decryption
        if (ciphertextCandDecryptA == null) {
            System.out.println("fail to meet the condition!");
        } else {
            Element DK = DecryptionGenerator.decrypt(ciphertextCandDecryptA, delegationKey);
            System.out.println("DK=" + DK);
        }
    }


}
