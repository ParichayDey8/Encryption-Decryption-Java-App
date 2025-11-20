import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class CryptoGUI extends JFrame {
    private JTextField inputField, outputField, passwordField;
    private JTextArea textArea;
    
    public CryptoGUI() {
        setTitle("Java Encryption Tool");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 500);
        setLocationRelativeTo(null);
        
        initComponents();
    }
    
    private void initComponents() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Text area for input/output
        textArea = new JTextArea(10, 50);
        textArea.setBorder(BorderFactory.createTitledBorder("Text Input/Output"));
        JScrollPane scrollPane = new JScrollPane(textArea);
        
        // Control panel
        JPanel controlPanel = new JPanel(new GridLayout(5, 2, 5, 5));
        
        inputField = new JTextField();
        outputField = new JTextField();
        passwordField = new JTextField();
        
        controlPanel.add(new JLabel("Input File:"));
        controlPanel.add(inputField);
        controlPanel.add(new JLabel("Output File:"));
        controlPanel.add(outputField);
        controlPanel.add(new JLabel("Password:"));
        controlPanel.add(passwordField);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        
        JButton encryptFileBtn = new JButton("Encrypt File");
        JButton decryptFileBtn = new JButton("Decrypt File");
        JButton encryptTextBtn = new JButton("Encrypt Text");
        JButton decryptTextBtn = new JButton("Decrypt Text");
        
        encryptFileBtn.addActionListener(new EncryptFileListener());
        decryptFileBtn.addActionListener(new DecryptFileListener());
        encryptTextBtn.addActionListener(new EncryptTextListener());
        decryptTextBtn.addActionListener(new DecryptTextListener());
        
        buttonPanel.add(encryptFileBtn);
        buttonPanel.add(decryptFileBtn);
        buttonPanel.add(encryptTextBtn);
        buttonPanel.add(decryptTextBtn);
        
        mainPanel.add(controlPanel, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        add(mainPanel);
    }
    
    private class EncryptFileListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                CryptoUtils.encryptFile(
                    passwordField.getText(),
                    new File(inputField.getText()),
                    new File(outputField.getText())
                );
                JOptionPane.showMessageDialog(CryptoGUI.this, "File encrypted successfully!");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(CryptoGUI.this, "Error: " + ex.getMessage());
            }
        }
    }
    
    private class DecryptFileListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                CryptoUtils.decryptFile(
                    passwordField.getText(),
                    new File(inputField.getText()),
                    new File(outputField.getText())
                );
                JOptionPane.showMessageDialog(CryptoGUI.this, "File decrypted successfully!");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(CryptoGUI.this, "Error: " + ex.getMessage());
            }
        }
    }
    
    private class EncryptTextListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String encrypted = CryptoUtils.encryptText(
                    passwordField.getText(), 
                    textArea.getText()
                );
                textArea.setText(encrypted);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(CryptoGUI.this, "Error: " + ex.getMessage());
            }
        }
    }
    
    private class DecryptTextListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String decrypted = CryptoUtils.decryptText(
                    passwordField.getText(), 
                    textArea.getText()
                );
                textArea.setText(decrypted);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(CryptoGUI.this, "Error: " + ex.getMessage());
            }
        }
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new CryptoGUI().setVisible(true);
        });
    }
}