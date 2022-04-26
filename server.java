
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
public class server 
{
	public static void main(String[] args) throws Exception
	{
		try {
			int b = 3;
			ServerSocket ss = new ServerSocket(6666);
			Socket s = ss.accept();
			System.out.println("Connection established");
			DataInputStream dis = new DataInputStream(s.getInputStream());
			OutputStream outToClient = s.getOutputStream();
            DataOutputStream dos = new DataOutputStream(outToClient);
			
			int clientG = Integer.parseInt(dis.readUTF()); //public /read 1
			int clientP = Integer.parseInt(dis.readUTF()); //public /read 2
			int gamodp = Integer.parseInt(dis.readUTF()); //public number /read 3
			
			int gbmodp = ((int)Math.pow(clientG, b))%clientP;
			dos.writeUTF(gbmodp+"");
			
			int gabmodp = ((int)Math.pow(gamodp, b))%clientP;
			byte[] key = (Integer.toString(gabmodp)).getBytes("UTF-8");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			String ss_client = dis.readUTF();//read 4
			int ss_client_int = Integer.parseInt(ss_client);
			if(gabmodp==ss_client_int)
				System.out.println("SUCCESS: SHARED SYMMETRIC KEY: "+ss_client);
			System.out.println("Encrypted message" + ss_client);
			String decrypted = decrypt(ss_client, secretKeySpec); 
			System.out.println("Coordinates: " + decrypted);
			
			//KeyPai
			
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
	
	public static String decrypt(String encryptedMessage, SecretKeySpec key) throws Exception
	{
		byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
		return new String(decryptedMessage, "UTF8");
	}
}