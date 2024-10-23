<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'C:\Users\DELL\Desktop\projects\xuremi web\src\PHPMailer.php';
require 'C:\Users\DELL\Desktop\projects\xuremi web\src\SMTP.php';
require 'C:\Users\DELL\Desktop\projects\xuremi web\src\Exception.php';

// Database connection details
$host = 'localhost';
$dbname = 'xuremi_db';
$username = 'root';
$password = 'Cerufixime250.';
 
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    header('Content-Type: application/json');
    echo json_encode(["error" => "Database connection failed: " . $e->getMessage()]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    $email = trim($_POST['email']);

    // Check if the email exists in the database
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // Generate a reset token
        $token = bin2hex(random_bytes(50));

        // Store the token in the password_resets table
        $stmt = $pdo->prepare("INSERT INTO password_resets (email, token) VALUES (?, ?)");
        $stmt->execute([$email, $token]);

        // Create the reset link
        $resetLink = "http://localhost/xuremi%20web/reset-password.php?token=" . $token;

        // Use PHPMailer to send the email
        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = 'in-v3.mailjet.com';
            $mail->SMTPAuth = true;
            $mail->Username = '20d863fb6ee10ae695978d5ea5e554a4';
            $mail->Password = '4eadba00bcbb492bc32c16fe5c46c5a5';
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;

            $mail->setFrom('004techartist@gmail.com', 'Password Reset');
            $mail->addAddress($email);

            $mail->isHTML(true);
            $mail->Subject = 'Password Reset Request';
            $mail->Body = 'Click the link below to reset your password: <a href="' . $resetLink . '">' . $resetLink . '</a>';

            $mail->send();

            header('Content-Type: application/json');
            echo json_encode(["success" => true, "message" => "Password reset link has been sent to your email."]);
        } catch (Exception $e) {
            header('Content-Type: application/json');
            echo json_encode(["error" => "Message could not be sent. Mailer Error: {$mail->ErrorInfo}"]);
        }
    } else {
        header('Content-Type: application/json');
        echo json_encode(["error" => "Email address not found."]);
    }
}
