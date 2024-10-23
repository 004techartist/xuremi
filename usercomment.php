<?php
// Database connection
$host = 'localhost'; // Database host
$db = 'xuremi_db'; // Database name
$user = 'root'; // Database user
$pass = 'Cerufixime250.'; // Database password

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
}

// Get the product ID from the URL
$product_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

// Fetch product details
$stmt = $pdo->prepare("SELECT * FROM apps WHERE id = ?");
$stmt->execute([$product_id]);
$product = $stmt->fetch();

// Handle rating submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['rating'])) {
    $rating = (int)$_POST['rating'];
    $stmt = $pdo->prepare("INSERT INTO ratings (product_id, rating) VALUES (?, ?)");
    $stmt->execute([$product_id, $rating]);
}

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    $comment = $_POST['comment'];
    $stmt = $pdo->prepare("INSERT INTO comments (product_id, comment) VALUES (?, ?)");
    $stmt->execute([$product_id, $comment]);
}

// Fetch ratings and comments
$ratings_stmt = $pdo->prepare("SELECT AVG(rating) as average_rating FROM ratings WHERE product_id = ?");
$ratings_stmt->execute([$product_id]);
$average_rating = $ratings_stmt->fetchColumn();

$comments_stmt = $pdo->prepare("SELECT * FROM comments WHERE product_id = ? ORDER BY created_at DESC");
$comments_stmt->execute([$product_id]);
$comments = $comments_stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($product['name']); ?> - Product Page</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="product-container">
        <h1><?php echo htmlspecialchars($product['name']); ?></h1>
        <img src="<?php echo htmlspecialchars($product['image_url']); ?>" alt="<?php echo htmlspecialchars($product['name']); ?>">
        <p><?php echo htmlspecialchars($product['description']); ?></p>

        <h2>Average Rating: <?php echo $average_rating ? number_format($average_rating, 1) : 'Not rated yet'; ?></h2>

        <h3>Rate this Product</h3>
        <form method="POST">
            <input type="radio" name="rating" value="1"> 1
            <input type="radio" name="rating" value="2"> 2
            <input type="radio" name="rating" value="3"> 3
            <input type="radio" name="rating" value="4"> 4
            <input type="radio" name="rating" value="5"> 5
            <input type="submit" value="Rate">
        </form>

        <h3>Comments</h3>
        <form method="POST">
            <textarea name="comment" rows="4" placeholder="Leave a comment..." required></textarea><br>
            <input type="submit" value="Submit Comment">
        </form>

        <h3>User Comments:</h3>
        <ul>
            <?php foreach ($comments as $comment): ?>
                <li><?php echo htmlspecialchars($comment['comment']); ?> - <em><?php echo htmlspecialchars($comment['created_at']); ?></em></li>
            <?php endforeach; ?>
        </ul>
    </div>
</body>
</html>
