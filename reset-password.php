<?php
// Database connection details here

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'reset_password') {
    $token = $_POST['token'];
    $newPassword = password_hash($_POST['password'], PASSWORD_BCRYPT);

    // Check if the token is valid
    $stmt = $pdo->prepare("SELECT email FROM password_resets WHERE token = ?");
    $stmt->execute([$token]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {
        $email = $row['email'];

        // Update the user's password
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE email = ?");
        $stmt->execute([$newPassword, $email]);

        // Delete the token after password reset
        $stmt = $pdo->prepare("DELETE FROM password_resets WHERE token = ?");
        $stmt->execute([$token]);

        echo json_encode(["success" => true, "message" => "Password has been updated."]);
        exit;
    } else {
        echo json_encode(["error" => "Invalid or expired token."]);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Reset Password</title>
</head>
<body>
    <form method="POST" action="reset-password.php">
        <input type="hidden" name="token" value="<?php echo htmlspecialchars($_GET['token']); ?>" />
        <input type="password" name="password" placeholder="New Password" required>
        <button type="submit" name="action" value="reset_password">Reset Password</button>
    </form>
</body>
</html>
