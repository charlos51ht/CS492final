
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
public class server 
{
	public static void main(String[] args) throws Exception
	{
		try {
			SecureRandom rand = new SecureRandom();
			BigInteger b = new BigInteger(rand.nextInt(1000)+"");
			ServerSocket ss = new ServerSocket(6666);
			Socket s = ss.accept();
			System.out.println("Connection established");
			DataInputStream dis = new DataInputStream(s.getInputStream());
			OutputStream outToClient = s.getOutputStream();
            DataOutputStream dos = new DataOutputStream(outToClient);
            
            String client_key = dis.readUTF();
            System.out.println(client_key);
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    		keyPairGen.initialize(2048);
    		KeyPair server_pair = keyPairGen.generateKeyPair();
    		dos.writeUTF(server_pair.getPublic().getEncoded().toString());
			
			BigInteger clientG = new BigInteger(decrypt(dis.readUTF(),server_pair.getPrivate())); //public /read 1
			BigInteger clientP = new BigInteger(decrypt(dis.readUTF(),server_pair.getPrivate())); //public /read 2
			BigInteger gamodp = new BigInteger(decrypt(dis.readUTF(),server_pair.getPrivate())); //public number /read 3
			
			BigInteger gbmodp = clientG.modPow(b,clientP);
			dos.writeUTF(encrypt(gbmodp+"",client_key));
			
			BigInteger gabmodp = gamodp.modPow(b,clientP);
			byte[] key = gabmodp.toByteArray();
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			String ss_client = decrypt(dis.readUTF(),server_pair.getPrivate());//read 4
			
			System.out.println("aes key: " + ss_client);
			String decrypted = decryptLoc(ss_client, secretKeySpec); 
			System.out.println("Coordinates: " + decrypted);
			
			dis.close();
			dos.close();
			System.out.println("Connection terminated");
			s.close();
			ss.close();
			System.exit(0);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static String decryptLoc(String encryptedMessage, SecretKeySpec key) throws Exception
	{
		byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
		return new String(decryptedMessage, "UTF8");
	}
	public static String encrypt(String message, String key) throws Exception //encryption method
	{
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = (PublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(key)));
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