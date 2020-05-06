import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SecureMessaging {
    private static final String PUBLIC_KEY_FILENAME = "app.pub";
    private static final String PRIVATE_KEY_FILENAME = "app.key";

    public static void main(String[] args) {
        if (args.length == 1 && args[0].equalsIgnoreCase("generate")) {
            try {
                generate();
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Error while generating keypairs");
            } catch (IOException e) {
                System.out.println("Error while writing key to file");
            } finally {
                System.exit(0);
            }
        }

        if (args.length == 2) {
            if (!args[0].equalsIgnoreCase("encrypt") && !args[0].equalsIgnoreCase("decrypt")) {
                System.out.println("Invalid args[0]");
                System.exit(0);
            }
            try {
                if (args[0].equalsIgnoreCase("encrypt")) {
                    encrypt(args[1]);
                } else {
                    decrypt(args[1]);
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                System.exit(0);
            }
        }

        System.out.println("Invalid operation.");
    }

    /**
     * Generating a RSA key pairs and store
     * public key as app.pub;
     * private key as app.key;
     */
    private static void generate() throws NoSuchAlgorithmException, IOException {
        System.out.println("Generating keypair...");
        KeyPair keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Base64.Encoder encoder = Base64.getEncoder();

        // Writing public key to app.pub
        FileWriter out = new FileWriter(PUBLIC_KEY_FILENAME);
        out.write("-----BEGIN RSA PUBLIC KEY-----\n");
        out.write(encoder.encodeToString(keys.getPublic().getEncoded()));
        out.write("\n-----END RSA PUBLIC KEY-----\n");
        out.close();

        // Writing private key to app.key
        out = new FileWriter(PRIVATE_KEY_FILENAME);
        out.write("-----BEGIN RSA PRIVATE KEY-----\n");
        out.write(encoder.encodeToString(keys.getPrivate().getEncoded()));
        out.write("\n-----END RSA PRIVATE KEY-----\n");
        out.close();
    }

    /**
     * Encrypt a file (example.txt) with public key,
     * generate another file with the original content encrypted (example_encrypted.txt) (assumed first line)
     */
    private static void encrypt(String filename)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        System.out.println("Start encrypting...");
        
        // Read public key file and convert into public key
        System.out.println("Generating key from file...");
        BufferedReader br = new BufferedReader(new FileReader(PUBLIC_KEY_FILENAME));
        br.readLine();
        byte[] pKeyBytes = Base64.getDecoder().decode(br.readLine());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pKeyBytes);
        PublicKey pKey = kf.generatePublic(publicKeySpec);
        br.close();   

        // Read plain text from input file
        System.out.println("Reading plantext...");
        br = new BufferedReader(new FileReader(filename));
        String plainText = br.readLine();
        br.close();
        
        // Encrypt plain text
        System.out.println("Encrypting...");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pKey);
        byte[] encryptText = cipher.doFinal(plainText.getBytes());

        // Write output into file
        System.out.println("Writing to output file...");
        String outFileName = filename.substring(0, filename.lastIndexOf('.')) + "_encrypted.txt";
        FileOutputStream fos = new FileOutputStream(outFileName);
        fos.write(encryptText);
        fos.close();

        System.out.println("Encrypted message generated: " + outFileName);
    }


    private static void decrypt(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("Start decrypting...");
        
        // Read private key file and convert into private key
        System.out.println("Generating key from file...");
        BufferedReader br = new BufferedReader(new FileReader(PRIVATE_KEY_FILENAME));
        br.readLine();
        byte[] pKeyBytes = Base64.getDecoder().decode(br.readLine());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pKeyBytes);
        PrivateKey pKey = kf.generatePrivate(privateKeySpec);
        br.close();

        // Read encrypted text from input file
        System.out.println("Reading encryptedtext...");
        Path path = Paths.get(filename);
        byte[] result = Files.readAllBytes(path);
        
        // Decrypt encrypted text
        System.out.println("Decrypting...");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, pKey);
        byte[] plainText = cipher.doFinal(result);

        // Write output into file
        System.out.println("Writing to output file...");
        String outFileName = filename.replace("_encrypted", "_decrypted");
        FileOutputStream fos = new FileOutputStream(outFileName);
        fos.write(plainText);
        fos.close();

        System.out.println("Decrypted message generated: " + outFileName);
    }

}