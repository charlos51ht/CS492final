import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
public class client 
{
	public static int SECRET_KEY = 0;
	public static void main(String[] args) throws Exception
	{
		String location = "41.6931 N, 72.7639 W"; //CCSU coordinates
		try {
			Socket s = new Socket("localhost",6666);
			DataOutputStream dos= new DataOutputStream(s.getOutputStream());
	        BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
	        DataInputStream dis = new DataInputStream(s.getInputStream());
	        
	        //Security Key exchange
	        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    		keyPairGen.initialize(2048);
    		KeyPair client_pair = keyPairGen.generateKeyPair();
    		dos.writeUTF(client_pair.getPublic().getEncoded().toString());//send public key for encryption
    		String server_key = dis.readUTF();
			
			//Client Side
	        SecureRandom rand = new SecureRandom();
			BigInteger clientG = BigInteger.probablePrime(128,rand);//random integer?
			BigInteger clientP = BigInteger.probablePrime(128,rand);
			BigInteger a = new BigInteger(rand.nextInt(1000)+"");
			
			/*dos.writeUTF(key_pair.getPublic().toString());
			dos.writeUTF(key_pair.getPrivate().toString());*/
			dos.writeUTF(encrypt(clientG+"",server_key)); //send 1
			dos.writeUTF(encrypt(clientP+"",server_key)); //send 2
			
			BigInteger gamodp = clientG.modPow(a, clientP);
			
			dos.writeUTF(encrypt(gamodp+"",server_key)); //send 3
			
			BigInteger gbmodp = new BigInteger(decrypt(dis.readUTF(),client_pair.getPrivate())); //gets g^b mod p from server
			BigInteger gabmodp = gbmodp.modPow(a, clientP); //creates the key to encrypt location using server's 
	
			//String ss_client = Integer.toString(gabmodp);
			byte[] key = gabmodp.toByteArray();
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			String encryptedLocation = encryptLoc(location, secretKeySpec);
			dos.writeUTF(encryptedLocation+"");//send 4
			
			dis.close();
			dos.close();
			br.close();
			s.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static String encryptLoc(String loc, SecretKeySpec key) throws Exception //encryption method for shared symmetric key
	{
		byte[] locationBytes = loc.getBytes();
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encrypted = cipher.doFinal(locationBytes);
		return Base64.getEncoder().encodeToString(encrypted);
	}
	public static String encrypt(String message, String key) throws Exception //encryption method
	{
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		byte[] encoded = Base64.getDecoder().decode(key);
        PublicKey publicKey = (PublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
		byte[] messageBytes = message.getBytes();
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encrypted = cipher.doFinal(messageBytes);
		return Base64.getEncoder().encodeToString(encrypted);
	}
	public static String decrypt(String ciphertext, PrivateKey key) throws Exception //encryption method
	{
		byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decrypted = cipher.doFinal(encryptedBytes);
		return Base64.getEncoder().encodeToString(decrypted);
	}
}
