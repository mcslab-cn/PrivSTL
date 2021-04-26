package com.buptmcs.privstg.parameters;

public class TransformationkeyAndDelegationKey extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private TransformationKey transformationKey;
    private RetrieveKey delegationKey;

    public TransformationkeyAndDelegationKey(TransformationKey transformationKey, RetrieveKey delegationKey) {
        this.transformationKey = transformationKey;
        this.delegationKey = delegationKey;
    }

    public TransformationKey getTransformationKey() {
        return transformationKey;
    }

    public RetrieveKey getDelegationKey() {
        return delegationKey;
    }

}
