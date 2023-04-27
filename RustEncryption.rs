use qt_widgets::{
    QApplication, QFormLayout, QGridLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QWidget,
};
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

fn main() {
    QApplication::init(|_| {
        // Create the main window
        let mut window = QWidget::new_0a();
        window.set_window_title(&QString::from_std_str("AES Encryption Tool"));

        // Create the text input fields
        let mut input_label = QLabel::from_q_string(&QString::from_std_str("Input text:"));
        let mut input_text = QLineEdit::new();
        let mut password_label = QLabel::from_q_string(&QString::from_std_str("Password:"));
        let mut password_text = QLineEdit::new();
        password_text.set_echo_mode(qt_widgets::line_edit::EchoMode::Password);

        // Create the encryption and decryption buttons
        let mut encrypt_button = QPushButton::from_q_string(&QString::from_std_str("Encrypt"));
        let mut decrypt_button = QPushButton::from_q_string(&QString::from_std_str("Decrypt"));

        // Create the layout and add the widgets
        let mut layout = QFormLayout::new_0a();
        layout.add_widget_2a(&mut input_label, 0, 0);
        layout.add_widget_2a(&mut input_text, 0, 1);
        layout.add_widget_2a(&mut password_label, 1, 0);
        layout.add_widget_2a(&mut password_text, 1, 1);

        let mut button_layout = QGridLayout::new_0a();
        button_layout.add_widget_2a(&mut encrypt_button, 0, 0);
        button_layout.add_widget_2a(&mut decrypt_button, 0, 1);

        let mut main_layout = QVBoxLayout::new_0a();
        main_layout.add_layout_1a(&mut layout);
        main_layout.add_layout_1a(&mut button_layout);

        // Connect the buttons to their respective functions
        let cipher = Cbc::<Aes128, Pkcs7>::new_var(b"mysecretkey12345", b"initializationvect").unwrap();
        let mut output_text = QLineEdit::new();
        output_text.set_read_only(true);

        let output_layout = QVBoxLayout::new_0a();
        output_layout.add_widget(&mut QLabel::from_q_string(&QString::from_std_str("Output:")));
        output_layout.add_widget(&mut output_text);

        main_layout.add_layout_1a(&mut output_layout);

        encrypt_button.clicked().connect(&window, slot!(encrypt(&mut input_text, &mut password_text, &cipher, &mut output_text)));
        decrypt_button.clicked().connect(&window, slot!(decrypt(&mut input_text, &mut password_text, &cipher, &mut output_text)));

        // Set the layout on the window and show it
        window.set_layout(&mut main_layout);
        window.show();

        // Run the application event loop
        QApplication::exec()
    });
}

fn encrypt(input_text: &mut QLineEdit, password_text: &mut QLineEdit, cipher: &Cbc<Aes128, Pkcs7>, output_text: &mut QLineEdit) {
    let input = input_text.text().to_std_string();
    let password = password_text.text().to_std_string();
    let ciphertext = cipher.encrypt_vec(input.as_bytes());
    let ciphertext_str = hex::encode(ciphertext);
    output_text.set_text(&QString::from_std_str(&ciphertext_str));
