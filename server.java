
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.PublicKey;
public class server 
{
	public static void main(String[] args)
	{
		try {
			int b = 3;
			ServerSocket ss = new ServerSocket(6666);
			Socket s = ss.accept();
			System.out.println("Connection established");
			DataInputStream dis = new DataInputStream(s.getInputStream());
			OutputStream outToClient = s.getOutputStream();
            DataOutputStream dos = new DataOutputStream(outToClient);
			
			int clientG = Integer.parseInt(dis.readUTF());
			int clientP = Integer.parseInt(dis.readUTF());
			int x = Integer.parseInt(dis.readUTF());
			
			int y = ((int)Math.pow(clientG, b))%clientP;
			dos.writeUTF(y+"");
			
			int ss_server = ((int)Math.pow(x, b))%clientP;
			int ss_client = Integer.parseInt(dis.readUTF());
			if(ss_server==ss_client)
				System.out.println("SUCCESS: SHARED SYMMETRIC KEY: "+ss_client);
			
			//KeyPai
			
			dis.close();
			dos.close();
			System.out.println("Connction terminated");
			s.close();
			ss.close();
			System.exit(0);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
