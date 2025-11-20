import java.io.File;
import java.util.Scanner;

public class CryptoApp {
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("=== Java Encryption/Decryption Tool ===");
        System.out.println("Secure AES-256 GCM Encryption");

        while (true) {
            showMenu();
            int choice = getIntInput("Choose an option: ");

            try {
                switch (choice) {
                    case 1:
                        encryptFile();
                        break;
                    case 2:
                        decryptFile();
                        break;
                    case 3:
                        encryptText();
                        break;
                    case 4:
                        decryptText();
                        break;
                    case 5:
                        generatePassword();
                        break;
                    case 6:
                        System.out.println("Goodbye!");
                        return;
                    default:
                        System.out.println("Invalid option. Please try again.");
                }
            } catch (CryptoException e) {
                System.out.println("Error: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("Unexpected error: " + e.getMessage());
            }
            
            System.out.println();
        }
    }

    private static void showMenu() {
        System.out.println("1. Encrypt File");
        System.out.println("2. Decrypt File");
        System.out.println("3. Encrypt Text");
        System.out.println("4. Decrypt Text");
        System.out.println("5. Generate Secure Password");
        System.out.println("6. Exit");
    }

    private static void encryptFile() throws CryptoException {
        System.out.println("\n--- File Encryption ---");
        
        String inputPath = getStringInput("Enter input file path: ");
        String outputPath = getStringInput("Enter output file path: ");
        String password = getPasswordInput();
        
        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);

        if (!inputFile.exists()) {
            System.out.println("Input file does not exist!");
            return;
        }

        CryptoUtils.encryptFile(password, inputFile, outputFile);
    }

    private static void decryptFile() throws CryptoException {
        System.out.println("\n--- File Decryption ---");
        
        String inputPath = getStringInput("Enter encrypted file path: ");
        String outputPath = getStringInput("Enter output file path: ");
        String password = getPasswordInput();
        
        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);

        if (!inputFile.exists()) {
            System.out.println("Input file does not exist!");
            return;
        }

        CryptoUtils.decryptFile(password, inputFile, outputFile);
    }

    private static void encryptText() throws CryptoException {
        System.out.println("\n--- Text Encryption ---");
        
        String text = getStringInput("Enter text to encrypt: ");
        String password = getPasswordInput();
        
        String encryptedText = CryptoUtils.encryptText(password, text);
        System.out.println("Encrypted text: " + encryptedText);
    }

    private static void decryptText() throws CryptoException {
        System.out.println("\n--- Text Decryption ---");
        
        String encryptedText = getStringInput("Enter encrypted text: ");
        String password = getPasswordInput();
        
        String decryptedText = CryptoUtils.decryptText(password, encryptedText);
        System.out.println("Decrypted text: " + decryptedText);
    }

    private static void generatePassword() {
        System.out.println("\n--- Password Generator ---");
        int length = getIntInput("Enter password length (8-64): ");
        
        if (length < 8 || length > 64) {
            System.out.println("Length must be between 8 and 64");
            return;
        }
        
        String password = CryptoUtils.generatePassword(length);
        System.out.println("Generated password: " + password);
    }

    private static String getStringInput(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine();
    }

    private static int getIntInput(String prompt) {
        while (true) {
            try {
                System.out.print(prompt);
                return Integer.parseInt(scanner.nextLine());
            } catch (NumberFormatException e) {
                System.out.println("Please enter a valid number.");
            }
        }
    }

    private static String getPasswordInput() {
        System.out.print("Enter password: ");
        return scanner.nextLine();
    }
}