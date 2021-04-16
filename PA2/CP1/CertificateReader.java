package CP1;
import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.nio.file.Files;
import java.nio.file.Paths;

class CertificateReader {

    public static X509Certificate get(String filename) throws Exception {
        InputStream inputStream = new FileInputStream(filename);
        return get(inputStream);
    }

    public static X509Certificate get_from_string(String certString) throws Exception {
        byte[] certBytes = Base64.getDecoder().decode(certString);
        InputStream inputStream = new ByteArrayInputStream(certBytes);
        return get(inputStream);
    }

    public static X509Certificate get(InputStream inputStream) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(inputStream);
    }

}