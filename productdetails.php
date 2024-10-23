<?php
// Connect to your database
// Database connection
$host = 'localhost';
$dbname = 'xuremi_db';
$username = 'root';
$password = 'Cerufixime250.';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}


// Get the product ID from the URL
$product_id = $_GET['id'];

// Fetch product data from the database
$query = "SELECT * FROM products WHERE id = ?";
$stmt = $pdo->prepare($query);
$stmt->execute([$product_id]);
$product = $stmt->fetch(PDO::FETCH_ASSOC);

// Fetch related apps (based on category or tags)
$query_related = "SELECT * FROM products WHERE category = ? AND id != ? LIMIT 4";
$stmt_related = $pdo->prepare($query_related);
$stmt_related->execute([$product['category'], $product_id]);
$related_products = $stmt_related->fetchAll(PDO::FETCH_ASSOC);

// Fetch reviews and ratings
$query_reviews = "SELECT * FROM reviews WHERE product_id = ?";
$stmt_reviews = $pdo->prepare($query_reviews);
$stmt_reviews->execute([$product_id]);
$reviews = $stmt_reviews->fetchAll(PDO::FETCH_ASSOC);

// Calculate the average rating
$query_avg_rating = "SELECT AVG(rating) as avg_rating, COUNT(rating) as total_ratings FROM reviews WHERE product_id = ?";
$stmt_avg_rating = $pdo->prepare($query_avg_rating);
$stmt_avg_rating->execute([$product_id]);
$rating_info = $stmt_avg_rating->fetch(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="stylesheet" href="style.css">
    <title><?php echo htmlspecialchars($product['name']); ?> - Product Details</title>
</head>
<body>

<div class="product-details">
    <div class="left-column">
        <!-- Product Icon -->
        <img src="<?php echo htmlspecialchars($product['image_url']); ?>" alt="<?php echo htmlspecialchars($product['name']); ?>" class="product-icon">
        <!-- Download Button -->
        <a href="<?php echo htmlspecialchars($product['file_url']); ?>" class="download-btn" download>Download</a>
    </div>
    
    <div class="right-column">
        <!-- Product Name -->
        <h1><?php echo htmlspecialchars($product['name']); ?></h1>

        <!-- Star Rating -->
        <div class="rating">
            <span>Average Rating: <?php echo round($rating_info['avg_rating'], 1); ?> stars (<?php echo $rating_info['total_ratings']; ?> ratings)</span>
            <!-- You can add star icons here dynamically based on the rating -->
            <!-- Users can submit their own rating -->
            <form action="rate_product.php" method="post">
                <input type="hidden" name="product_id" value="<?php echo $product_id; ?>">
                <label for="rating">Rate this product:</label>
                <select name="rating" id="rating">
                    <option value="1">1 Star</option>
                    <option value="2">2 Stars</option>
                    <option value="3">3 Stars</option>
                    <option value="4">4 Stars</option>
                    <option value="5">5 Stars</option>
                </select>
                <button type="submit">Submit Rating</button>
            </form>
        </div>

        <!-- Description -->
        <p><?php echo nl2br(htmlspecialchars($product['description'])); ?></p>

        <!-- Screenshots and Videos -->
        <div class="media-section">
            <h3>App Screenshots & Videos</h3>
            <div class="media-row">
                <?php
                // Assuming screenshots and videos are stored in the database or a specific directory
                // Example for displaying media (you can extend this to videos as well)
                $screenshots = explode(',', $product['screenshots']);
                foreach ($screenshots as $screenshot) {
                    echo '<img src="' . htmlspecialchars($screenshot) . '" alt="Screenshot" class="screenshot">';
                }
                ?>
            </div>
        </div>

        <!-- Downloads and Reviews -->
        <div class="product-info">
            <p>Total Downloads: <?php echo htmlspecialchars($product['downloads']); ?></p>

            <h3>User Reviews</h3>
            <div class="reviews-section">
                <?php foreach ($reviews as $review): ?>
                    <div class="review">
                        <p><strong><?php echo htmlspecialchars($review['user_id']); ?>:</strong></p>
                        <p><?php echo htmlspecialchars($review['review_text']); ?></p>
                        <p>Rating: <?php echo htmlspecialchars($review['rating']); ?> stars</p>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Add a review -->
            <form action="submit_review.php" method="post">
                <input type="hidden" name="product_id" value="<?php echo $product_id; ?>">
                <textarea name="review_text" placeholder="Write your review here..." required></textarea>
                <button type="submit">Submit Review</button>
            </form>
        </div>

        <!-- Related Products -->
        <div class="related-products">
            <h3>Related Products</h3>
            <div class="related-product-grid">
                <?php foreach ($related_products as $related): ?>
                    <div class="related-product-card">
                        <a href="product-description.php?id=<?php echo $related['id']; ?>">
                            <img src="<?php echo htmlspecialchars($related['image_url']); ?>" alt="<?php echo htmlspecialchars($related['name']); ?>">
                            <p><?php echo htmlspecialchars($related['name']); ?></p>
                        </a>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

    </div>
</div>

</body>
</html>
