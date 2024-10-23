<?php
session_start();
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user_id = $_POST['user_id'];
    $note = $_POST['note'];

    // Insert the sticky note into the database
    $stmt = $pdo->prepare("INSERT INTO sticky_notes (user_id, note) VALUES (?, ?)");
    $stmt->execute([$user_id, $note]);

    // Redirect back to admin page
    header('Location: admin.php');
}
?>
