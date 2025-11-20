import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class CryptoUtils {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int SALT_LENGTH = 16;
    private static final int ITERATION_COUNT = 65536;

    /**
     * Encrypts a file using password-based encryption
     */
    public static void encryptFile(String password, File inputFile, File outputFile) 
            throws CryptoException {
        try {
            // Generate random salt and IV
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(salt);
            secureRandom.nextBytes(iv);

            // Derive key from password
            SecretKey secretKey = deriveKey(password, salt);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            // Read input file
            byte[] fileContent = Files.readAllBytes(inputFile.toPath());
            
            // Encrypt the content
            byte[] encryptedContent = cipher.doFinal(fileContent);

            // Combine salt + iv + encrypted content
            ByteBuffer byteBuffer = ByteBuffer.allocate(
                salt.length + iv.length + encryptedContent.length
            );
            byteBuffer.put(salt);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedContent);

            // Write to output file
            Files.write(outputFile.toPath(), byteBuffer.array());
            
            System.out.println("File encrypted successfully: " + outputFile.getPath());

        } catch (Exception e) {
            throw new CryptoException("Error encrypting file", e);
        }
    }

    /**
     * Decrypts a file using password-based decryption
     */
    public static void decryptFile(String password, File inputFile, File outputFile) 
            throws CryptoException {
        try {
            // Read the encrypted file
            byte[] fileContent = Files.readAllBytes(inputFile.toPath());
            
            if (fileContent.length < SALT_LENGTH + GCM_IV_LENGTH) {
                throw new CryptoException("File is too short to be valid");
            }

            // Extract salt, IV, and encrypted content
            ByteBuffer byteBuffer = ByteBuffer.wrap(fileContent);
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(salt);
            byteBuffer.get(iv);
            byte[] encryptedContent = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedContent);

            // Derive key from password
            SecretKey secretKey = deriveKey(password, salt);

            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            // Decrypt the content
            byte[] decryptedContent = cipher.doFinal(encryptedContent);

            // Write to output file
            Files.write(outputFile.toPath(), decryptedContent);
            
            System.out.println("File decrypted successfully: " + outputFile.getPath());

        } catch (Exception e) {
            throw new CryptoException("Error decrypting file - wrong password?", e);
        }
    }

    /**
     * Encrypts text and returns Base64 encoded string
     */
    public static String encryptText(String password, String text) throws CryptoException {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(salt);
            secureRandom.nextBytes(iv);

            SecretKey secretKey = deriveKey(password, salt);
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] encryptedContent = cipher.doFinal(text.getBytes());

            ByteBuffer byteBuffer = ByteBuffer.allocate(
                salt.length + iv.length + encryptedContent.length
            );
            byteBuffer.put(salt);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedContent);

            return Base64.getEncoder().encodeToString(byteBuffer.array());

        } catch (Exception e) {
            throw new CryptoException("Error encrypting text", e);
        }
    }

    /**
     * Decrypts Base64 encoded encrypted text
     */
    public static String decryptText(String password, String encryptedText) throws CryptoException {
        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedText);
            
            ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(salt);
            byteBuffer.get(iv);
            byte[] encryptedContent = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedContent);

            SecretKey secretKey = deriveKey(password, salt);
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            byte[] decryptedContent = cipher.doFinal(encryptedContent);
            return new String(decryptedContent);

        } catch (Exception e) {
            throw new CryptoException("Error decrypting text - wrong password?", e);
        }
    }

    /**
     * Derives a secret key from password using PBKDF2
     */
    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(
            password.toCharArray(), 
            salt, 
            ITERATION_COUNT, 
            AES_KEY_SIZE
        );
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
    }

    /**
     * Generates a random secure password
     */
    public static String generatePassword(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }
}