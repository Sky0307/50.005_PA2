package CP1;

import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Date;
import CP1.CertificateReader;
import CP1.*;

public class ClientWithCP1{
    public static void main(String[] args) throws Exception {

        // get CA cert
        X509Certificate CAcert = CertificateReader.get("CP1/key_cert/cacse.crt");

        // get CA public key
        PublicKey CAPublicKey = CAcert.getPublicKey();
        System.out.println("CAPublicKey: " + CAPublicKey);
        System.out.println();

        String serverAddress = "localhost";
        int port = 4321;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        int numBytes = 0;
        long timeStarted = System.nanoTime();

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            //authentication
            toServer.writeInt(69); // 69 => ask to prove identity
            String clientMessage = "Hello";
            toServer.writeUTF(clientMessage);
            String encryptedMessage = fromServer.readUTF();
            toServer.writeInt(70); // 70 => ask for cert signed by CA

            // receive cert from server
            System.out.println("Receiving server's certificate");
            String serverCertString = fromServer.readUTF();
            X509Certificate serverCert = CertificateReader.get_from_string(serverCertString);

            // get server public key
            PublicKey serverPublicKey = serverCert.getPublicKey();
            System.out.println("serverPublicKey: " + serverPublicKey);

            // verify server's certificate
            try {
                serverCert.checkValidity();
                serverCert.verify(CAPublicKey);
            } catch (Exception e) {
                e.printStackTrace();
                toServer.writeInt(71); // 71 => invalid cert, close connection
                System.out.println("Closing connection...");
                clientSocket.close();
            }

            // verify server owns the private key associated with the public key in the cert
            // by decrypting encryptedMessage with server's public key

//            String decryptedMessage = Base64.getEncoder().encodeToString(RSA.decrypt(Base64.getDecoder().decode(encryptedMessage), serverPublicKey));
//
//            if (decryptedMessage.contentEquals(clientMessage)) {
//                toServer.writeInt(71); // 71 => invalid cert, close connection
//                System.out.println("Closing connection...");
//                clientSocket.close();
//            }

            System.out.println("Server's certificate is verified");
            System.out.println();

            // begin sending files from input arguments
            for (int i = 0; i < args.length; i++) {

                String filename = args[i];

                // begin handshake for file upload
                System.out.println("Sending " + filename + "...");
                // Send the filename
                toServer.writeInt(0); // 0 => file name
                toServer.writeInt(filename.getBytes().length);
                toServer.write(filename.getBytes());
                toServer.flush();

                // Open the file
                fileInputStream = new FileInputStream(filename);
                bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                byte[] fromFileBuffer = new byte[117];

                int packetCount = 0;

                // Send the file
                for (boolean fileEnded = false; !fileEnded;) {
                    // send 3 packets
                    // numBytes = number of bytes before encryption, to be written
                    // numBytesEncrypted = number of bytes after encryption, to be read from the buffer

                    numBytes = bufferedFileInputStream.read(fromFileBuffer);
                    fileEnded = numBytes < 117;

                    toServer.writeInt(1); // 1 => file chunk
                    toServer.writeInt(numBytes);
                    // System.out.println(numBytes);

                    // System.out.println("original bytes: " + fromFileBuffer);
                    // System.out.println("before encryption length: " + fromFileBuffer.length);

                    // encrypt the data
                    byte[] fromFileBufferEncrypted = RSA.encrypt(fromFileBuffer, serverPublicKey);

                    int numBytesEncryted = fromFileBufferEncrypted.length;
                    toServer.writeInt(numBytesEncryted);
                    // System.out.println(numBytesEncryted);

                    // send the data
                    toServer.write(fromFileBufferEncrypted);
                    toServer.flush();

                    // count and print the packet in string
                    packetCount++;
                    // System.out.println("packetCount:" + packetCount);
                    // System.out.println(Base64.getEncoder().encodeToString(fromFileBuffer));
                    // System.out.println(new String(fromFileBuffer));
                    // System.out.println(new String(fromFileBufferEncrypted));
                    // System.out.println();

                }

                System.out.println("Sent " + filename);
                System.out.println("Total packets sent: " + packetCount);
                System.out.println("");

                if (i == args.length - 1) {
                    // send EOF packet
                    toServer.writeInt(4); // 4 => End of transfer
                    bufferedFileInputStream.close();
                    fileInputStream.close();
                }
            }

            System.out.println("Closing connection...");

        } catch (Exception e) {
            e.printStackTrace();
        }

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }
}
