
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
public class client 
{
	public static void main(String[] args)
	{
		try {
			Socket s = new Socket("localhost",6666);
			 DataOutputStream dos= new DataOutputStream(s.getOutputStream());
	        BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
	        DataInputStream dis = new DataInputStream(s.getInputStream());
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
			keyPairGen.initialize(2048);
			KeyPair key_pair = keyPairGen.generateKeyPair();
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			//Client Side
			int clientG = 9;//random integer?
			int clientP = 23;//random integer?
			int a = 4;
			
			/*dos.writeUTF(key_pair.getPublic().toString());
			dos.writeUTF(key_pair.getPrivate().toString());*/
			dos.writeUTF(clientG+"");
			dos.writeUTF(clientP+"");
			
			int x = ((int)Math.pow(clientG, a))%clientP;
			dos.writeUTF(x+"");
			
			int y = Integer.parseInt(dis.readUTF());
			
			int ss_client = ((int) Math.pow(y, a))%clientP;
			dos.writeUTF(ss_client+"");
			
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
}
