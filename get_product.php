<?php
// Database connection details
$host = 'localhost';
$dbname = 'xuremi_db';
$username = 'root';
$password = 'Cerufixime250.';

// Connect to the database
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die(json_encode(["error" => "Database connection failed: " . $e->getMessage()]));
}

// Fetch products from the apps table
$stmt = $pdo->query("SELECT name, description, image_filename, file_filename FROM apps");
$apps = [];

while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $apps[] = [
        'name' => $row['name'],
        'description' => $row['description'],
        'image_url' => 'uploads/' . $row['image_filename'],
        'file_url' => 'uploads/' . $row['file_filename']
    ];
}

// Return the result as JSON
header('Content-Type: application/json');
echo json_encode($apps);
?>
