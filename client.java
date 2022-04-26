import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
		String location = "41.6931° N, 72.7639° W"; //CCSU coordinates
		try {
			Socket s = new Socket("localhost",6666);
			DataOutputStream dos= new DataOutputStream(s.getOutputStream());
	        BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
	        DataInputStream dis = new DataInputStream(s.getInputStream());
			
			//Client Side
			int clientG = 9;//random integer?
			int clientP = 23;//random integer?
			int a = 4;
			
			/*dos.writeUTF(key_pair.getPublic().toString());
			dos.writeUTF(key_pair.getPrivate().toString());*/
			dos.writeUTF(clientG+""); //send 1
			dos.writeUTF(clientP+""); //send 2
			
			int gamodp = ((int)Math.pow(clientG, a))%clientP;
			
			dos.writeUTF(gamodp+""); //send 3
			
			int gbmodp = Integer.parseInt(dis.readUTF()); //gets g^b mod p from server
			int gabmodp = ((int) Math.pow(gbmodp, a))%clientP; //creates the key to encrypt location using server's 
			
			//String ss_client = Integer.toString(gabmodp);
			byte[] key = (Integer.toString(gabmodp)).getBytes("UTF-8");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			String encryptedLocation = encrypt(location, secretKeySpec);
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
	
	public static String encrypt(String loc, SecretKeySpec key) throws Exception //encryption method
	{
		byte[] locationBytes = loc.getBytes();
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encrypted = cipher.doFinal(locationBytes);
		return Base64.getEncoder().encodeToString(encrypted);
	}
}