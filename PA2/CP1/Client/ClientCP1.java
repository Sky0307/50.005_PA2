import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.crypto.Cipher;

public class ClientCP1{
	static X509Certificate serverCert = null;
	static PublicKey pubkey = null;

	// handshake with server
	public static void handshake(DataOutputStream toServer,DataInputStream fromServer, X509Certificate CAcert) throws Exception{

		String msg_verify = null;
		String msg_verified = null;
		//message to be sent to server
		String msg_init = null;
		byte [] msg_verify_bytes =null;
		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		int numBytes = 0;
		
		// initialise the handshake

		//Generate NONCE
		String timeString = Long.toString(new Date().getTime());
        byte[] nonceByte = timeString.getBytes();
		String nonce =  new String(nonceByte);
		toServer.writeInt(2);
		toServer.writeInt(nonce.getBytes().length);
		toServer.write(nonce.getBytes());

		// waiting for SecStore response
		while(msg_verify == null){
			int packetType = fromServer.readInt();
			if (packetType == 2){
				System.out.println("receiving msg_verify...");
				numBytes = fromServer.readInt();
				msg_verify_bytes = new byte[numBytes];
				fromServer.readFully(msg_verify_bytes, 0, numBytes);
				msg_verify = new String(msg_verify_bytes);
				System.out.println("Received Encrypted block from Server");
			}
		}

		// ask for CA cert to get server's public key
		msg_init = "Give me your certificate signed by CA";
		System.out.println("Sending msg_init :" + msg_init);
		// 2 => establishing connection
		toServer.writeInt(2);
		toServer.writeInt(msg_init.getBytes().length);
		toServer.write(msg_init.getBytes());

		// wait for SecStore to provide CA
		boolean condition = true;
		while(condition){
			int packetType = fromServer.readInt();
			if(packetType==0){
				numBytes = fromServer.readInt();
				byte [] filename = new byte[numBytes];
				fromServer.readFully(filename, 0, numBytes);
				fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
				bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

			}else if (packetType == 1) {
				numBytes = fromServer.readInt();
				byte [] block = new byte[numBytes];
				// CHECKOFF : Get server.crt from server
				fromServer.readFully(block, 0, numBytes);
					if (numBytes > 0){
						bufferedFileOutputStream.write(block, 0, numBytes);
					}
					if (numBytes < 117) {
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						condition = false;
					}

			}
		}

		// get public key from certificate
		InputStream fileInputStream = new FileInputStream("recv_certificate_1004365.crt");
		CertificateFactory certf = CertificateFactory.getInstance("X.509");
		serverCert =(X509Certificate)(certf.generateCertificate(fileInputStream));

		//CHECKOFF : Verify (and decrypt) the server.crt using CA cert
		serverCert.verify(CAcert.getPublicKey());

		//CHECKOFF: Extract server's public key from the certificate
		pubkey = serverCert.getPublicKey();

		Cipher rsaCipher = Cipher.getInstance("RSA");
		rsaCipher.init(Cipher.DECRYPT_MODE, pubkey);
		byte[] decryptedBlock = rsaCipher.doFinal(msg_verify_bytes);
		msg_verified = new String(decryptedBlock);
		System.out.println("This is decrypted message: " + msg_verified);
		if(nonce.compareTo(msg_verified) == 0){
			System.out.println("decrypted message is the exact same as the nonce. Check succeeded.");
		}else{System.out.println("decrypted message is not the same as the nonce. Check failed.");}

	}
	public static void main(String[] args) {
		int count = args.length;
		String serverAddress = "localhost";
		int port = 4321;
		int numBytes = 0;
		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {
			System.out.println("Establishing connection to server...");

			//Create X509Certificate object
			InputStream fis = new FileInputStream("cacse.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);

			// Extract public key from X509Certificate object
			// PublicKey key = CAcert.getPublicKey();

			// Verify signed certificate
			// CAcert.verify(key);

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			//Handshake Protocol
			handshake(toServer, fromServer, CAcert);

			// 1111 => for sending number of arguments
			toServer.writeInt(1111); 
			toServer.writeInt(count); //count = number of files
			// Connect to server
			System.out.println("Sending file...");

			// Encrypt file with SecServer's public key
			Cipher rsaCipher = Cipher.getInstance("RSA");
			rsaCipher.init(Cipher.ENCRYPT_MODE, pubkey);
			String filename = null;
			byte[] encryptedBlock = null;
			byte [] fromFileBuffer = new byte[117];

			for (int i = 0; i < args.length; i++) {

				filename = args[i];
			
				//CHECKOFF: Encrypt file chunks with server???s public key
				encryptedBlock = rsaCipher.doFinal(filename.getBytes());
				System.out.println(encryptedBlock);
				System.out.println(encryptedBlock.length);
				
				// 0 => sending filename to SecServer
				toServer.writeInt(0);
				toServer.writeInt(encryptedBlock.length);
				toServer.write(encryptedBlock);
				//toServer.flush();

				// Open the file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

				// Send the file
				for (boolean fileEnded = false; !fileEnded;) {
					//encrypt the file in blocks of 117 bytes
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					encryptedBlock = rsaCipher.doFinal(fromFileBuffer);
					fileEnded = numBytes < 117;
					// 1 => transferring file content
					toServer.writeInt(1); 
					toServer.writeInt(numBytes);
					toServer.write(encryptedBlock);
					//toServer.flush();
				}
			}

			System.out.println("Done transferring all files");
			bufferedFileInputStream.close();
			fileInputStream.close();
			
			try{
				while (true){
					int packetType = fromServer.readInt();
					if (packetType == 4){ // 4 => Close connection
						System.out.println("Closing connection...");
						//clientSocket.close();
						break;
					}
				}
			}catch(EOFException e){
				System.out.println("Closing connection...");
			}
		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}







