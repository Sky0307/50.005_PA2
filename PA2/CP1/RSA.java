package CP1;

import java.security.*;
import javax.crypto.Cipher;

public class RSA {

    // RSA encrypt
    public static byte[] encrypt(byte[] byteArray, Key key) throws Exception {
        // instantiate cipher
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, key);

        // System.out.println("BytesArray: " + byteArray + "\nLength of BytesArray: " + byteArray.length);

        // encrypt message
        byte[] encryptedBytesArray = rsaCipher.doFinal(byteArray);
        // System.out.println("encryptedBytesArray: " + encryptedBytesArray + "\nLength of encryptedBytesArray: "
        // + encryptedBytesArray.length);

        return encryptedBytesArray;
    }

    // RSA decrypt
    public static byte[] decrypt(byte[] byteArray, Key key) throws Exception {
        // instantiate cypher
        Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        desCipher.init(Cipher.DECRYPT_MODE, key);

        // System.out.println("BytesArray: " + byteArray + "\nLength of BytesArray: " + byteArray.length);

        // decrypt message
        byte[] decryptedBytesArray = desCipher.doFinal(byteArray);
        // System.out.println("decryptedBytesArray: " + decryptedBytesArray + "\nLength of decryptedBytesArray: "
        // + decryptedBytesArray.length);

        return decryptedBytesArray;
    }

}