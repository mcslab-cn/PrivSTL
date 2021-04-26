package com.buptmcs.privstg.parameters;

public class KeyPairSTG {
	private PublicKey publicKey;
	private MasterSecretKey masterSecretKey;
	private ServerASecretKey ServerASKey;
	private ServerBSecretKey ServerBSKey;
	
	public KeyPairSTG(PublicKey publicKey, MasterSecretKey masterSecretKey, ServerASecretKey ServerASKey, ServerBSecretKey ServerBSKey) {
		this.publicKey = publicKey;
		this.masterSecretKey = masterSecretKey;
		this.ServerASKey=ServerASKey;
		this.ServerBSKey=ServerBSKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public MasterSecretKey getMasterSecretKey() {
		return masterSecretKey;
	}
	
	public ServerASecretKey getServerASecretKey() {
		return ServerASKey;
	}
	
	public ServerBSecretKey getServerBSecretKey() {
		return ServerBSKey;
	}
}
