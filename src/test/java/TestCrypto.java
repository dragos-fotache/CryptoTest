import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import com.google.common.collect.ObjectArrays;

public class TestCrypto {

	private static final String SEQUENCE = "00000001";
	private static final String ENCRYPTED_MESSAGE_HEX = "46e9fbeb564e5eba68c094da08172bac8299bd268749763224dea8a59313d548963dafbc3dcc7ea206646edeb4469e5d6eed38";
	private static final String PUB_KEY_A = "0474542541492424edc34f33ba94e61bf718f33ca393d1bf0816f156e4a266873f59564aad1a95c9fd8971b527171784e390d9137d037fe2ae30490b1ed1d73aa3";
	private static final String PUB_KEY_B = "04ad2d126c3f8f85bf5796f6ab849b57a35133fed491eced0254ed6a1169d9281f98018f1aa71d222874d72f47b0b28d84dacb8801b96e815c06f1151210cc7090";
	private static final String PRIV_KEY_A = "53994c02ca9f6d1afbda1742f43d3c17dedfaf3367727208fe9ccc50a33824a0";
	private static final String PRIV_KEY_B = "6c300cac339b4c7084e34175e2e6f5e1d1b135d158bd578c2b1af870facaef17";
	private static final String SHARED_SECRET = "a6c3021dc18ad03959768250e872818585264fbdd1b6de6ed32a7eb16f19f858";
	private static final String KEYING_MATERIAL = "58a5f8b53ff010a62eb2e98303f7d2d088b35fa8b758797777dbafa81df3bc9f";
	private static final String AES_KEY =         "58a5f8b53ff010a62eb2e98303f7d2d0";
	private static final String INIT_VECTOR =                                     "88b35fa8b758797777dbafa81df3bc9f";
	
	private static final String MESSAGE = "{ \"id\": \"Hello\", \"value\": \"World\" }";
	

	@Test
	public void test1() {
		ECKeyPairGenerator gen = new ECKeyPairGenerator();
		SecureRandom secureRandom = new SecureRandom();
		X9ECParameters secnamecurves = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters ecParams = new ECDomainParameters(secnamecurves.getCurve(), secnamecurves.getG(),
				secnamecurves.getN(), secnamecurves.getH());
		ECKeyGenerationParameters keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
		gen.init(keyGenParam);

		AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

		ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();

		BigInteger d = privateKeyParams.getD();

		String privateKeyHexStr = d.toString(16);

		System.out.println();
	}
	
	@Test
	public void testGenerateSecret() throws InvalidKeyException, IllegalStateException, Exception {
		
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
		ECPoint g = params.getG();
		
		BigInteger privKeyA = new BigInteger(PRIV_KEY_A, 16);
		
		ECPoint pubKeyA = g.multiply(privKeyA).normalize();
		
		String pubKeyXA = pubKeyA.getXCoord().toBigInteger().toString(16);
		String pubKeyYA = pubKeyA.getYCoord().toBigInteger().toString(16);
		
		String pubKeyStrA = "04" + pubKeyXA + pubKeyYA;
		
		assertEquals(PUB_KEY_A, pubKeyStrA);
		
		BigInteger privKeyB = new BigInteger(PRIV_KEY_B, 16);
		
		ECPoint pubKeyB = g.multiply(privKeyB).normalize();
		
		String pubKeyXB = pubKeyB.getXCoord().toBigInteger().toString(16);
		String pubKeyYB = pubKeyB.getYCoord().toBigInteger().toString(16);
		
		String pubKeyStrB = "04" + pubKeyXB + pubKeyYB;
		
		assertEquals(PUB_KEY_B, pubKeyStrB);
		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		byte[] secretHexStringA = getSharedSecret(Hex.decode(PRIV_KEY_A), pubKeyB);
		byte[] secretHexStringB = getSharedSecret(Hex.decode(PRIV_KEY_B), pubKeyA);
		
		assertEquals(SHARED_SECRET, Hex.toHexString(secretHexStringB));
		assertEquals(SHARED_SECRET, Hex.toHexString(secretHexStringA));
		
	}

	private byte[] getSharedSecret(byte[] privateKey , ECPoint pubKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		
		KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
		
		ka.init(loadPrivateKey(privateKey));
		ka.doPhase(loadPublicKey(pubKey), true);
		return ka.generateSecret();
	}
	
	@Test
	public void testKeyDerivationFunction() throws NoSuchAlgorithmException {
		
		String sharedInfo = PUB_KEY_A + PUB_KEY_B;
		String extraInfo = SEQUENCE + sharedInfo;
		String str = SHARED_SECRET + extraInfo;
		
		byte[] digest = deriveKey(Hex.decode(str));
	    
	    String hexString = Hex.toHexString(digest);
		assertEquals(KEYING_MATERIAL, hexString);
	}

	private byte[] deriveKey(byte[] strBytes) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");

	    md.update(strBytes);
	    byte[] digest = md.digest();
		return digest;
	}
	
	@Test
	public void testAESEncryption() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		byte[] messBytes = MESSAGE.getBytes();
		
		byte[] pubKeyBytesA = Hex.decode(PUB_KEY_A);
		byte[] pubKeyBytesB = Hex.decode(PUB_KEY_B);
		byte[] privKeyBytesA = Hex.decode(PRIV_KEY_A);
		byte[] sequenceBytes = Hex.decode(SEQUENCE);
		
		byte[] encryptedContent = doECIESEncryption(messBytes, pubKeyBytesA, pubKeyBytesB, privKeyBytesA, sequenceBytes);
		
		String encryptedHexStr = Hex.toHexString(encryptedContent);
		
		assertEquals(ENCRYPTED_MESSAGE_HEX, encryptedHexStr);
		
	}

	@Test
	public void testAESDecryption() throws InvalidKeyException, Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		byte[] messageBytes = Hex.decode(ENCRYPTED_MESSAGE_HEX);
		byte[] pubKeyBytesA = Hex.decode(PUB_KEY_A);
		byte[] pubKeyBytesB = Hex.decode(PUB_KEY_B);
		byte[] privKeyBytesB = Hex.decode(PRIV_KEY_B);
		byte[] sequenceBytes = Hex.decode(SEQUENCE);
		
		byte[] decryptedContent = doECIESDecryption(messageBytes, pubKeyBytesA, pubKeyBytesB, privKeyBytesB, sequenceBytes);
		
		String message = new String(decryptedContent);
		
		assertEquals(MESSAGE, message);
	}
	
	private byte[] doECIESEncryption(byte[] messageBytes, byte[] pubKeyBytesA, byte[] pubKeyBytesB, byte[] privKeyBytesA, byte[] sequenceBytes)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException,
			       NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		SecP256R1Curve curve = new SecP256R1Curve();
		
		ECPoint pubKeyB = curve.decodePoint(pubKeyBytesB);
		
		byte[] sharedSecret = getSharedSecret(privKeyBytesA, pubKeyB);
		
		byte[] strBytes = new byte[sharedSecret.length + sequenceBytes.length + pubKeyBytesA.length + pubKeyBytesB.length];
		
		System.arraycopy(sharedSecret, 0, strBytes, 0, sharedSecret.length);
		System.arraycopy(sequenceBytes, 0, strBytes, sharedSecret.length, sequenceBytes.length);
		System.arraycopy(pubKeyBytesA, 0, strBytes, sharedSecret.length + sequenceBytes.length, pubKeyBytesA.length);
		System.arraycopy(pubKeyBytesB, 0, strBytes, sharedSecret.length + sequenceBytes.length + pubKeyBytesA.length, pubKeyBytesB.length);
		
		byte[] keyingMaterial = deriveKey(strBytes);
		
		byte[] aesKey = Arrays.copyOfRange(keyingMaterial, 0, 16);
		byte[] initVector = Arrays.copyOfRange(keyingMaterial, 16, 32);
		
		SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
		
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		
		GCMParameterSpec parameterSpec = new GCMParameterSpec(128, initVector);
		
		cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, parameterSpec);
		
		byte[] encryptedContent = cipher.doFinal(messageBytes);
		return encryptedContent;
	}

	private byte[] doECIESDecryption(byte[] messageBytes, byte[] pubKeyBytesA, byte[] pubKeyBytesB, byte[] privKeyBytesB, byte[] sequenceBytes) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, 
				   IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException {
		
		SecP256R1Curve curve = new SecP256R1Curve();
		
		ECPoint pubKeyA = curve.decodePoint(pubKeyBytesA);
		
		byte[] sharedSecret = getSharedSecret(privKeyBytesB, pubKeyA);
		
		byte[] strBytes = new byte[sharedSecret.length + sequenceBytes.length + pubKeyBytesA.length + pubKeyBytesB.length];
		
		System.arraycopy(sharedSecret, 0, strBytes, 0, sharedSecret.length);
		System.arraycopy(sequenceBytes, 0, strBytes, sharedSecret.length, sequenceBytes.length);
		System.arraycopy(pubKeyBytesA, 0, strBytes, sharedSecret.length + sequenceBytes.length, pubKeyBytesA.length);
		System.arraycopy(pubKeyBytesB, 0, strBytes, sharedSecret.length + sequenceBytes.length + pubKeyBytesA.length, pubKeyBytesB.length);
		
		byte[] keyingMaterial = deriveKey(strBytes);
		
		byte[] aesKey = Arrays.copyOfRange(keyingMaterial, 0, 16);
		byte[] initVector = Arrays.copyOfRange(keyingMaterial, 16, 32);
		
		SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
		
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		
		GCMParameterSpec parameterSpec = new GCMParameterSpec(128, initVector);
		
		cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, parameterSpec);
		
		byte[] decryptedContent = cipher.doFinal(messageBytes);
		return decryptedContent;
	}
	
	private PublicKey loadPublicKey(ECPoint publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
		ECPublicKeySpec pubKey = new ECPublicKeySpec(publicKey, params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(pubKey);
	}
	
	private PrivateKey loadPrivateKey (byte [] data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
		ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePrivate(prvkey);
	}

}
