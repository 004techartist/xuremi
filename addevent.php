<?php
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

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $title = $_POST['title'];
    $description = $_POST['description'];
    $event_date = $_POST['event_date'];

    // Insert event into the database
    $stmt = $pdo->prepare("INSERT INTO events (title, description, event_date) VALUES (:title, :description, :event_date)");
    $stmt->bindParam(':title', $title);
    $stmt->bindParam(':description', $description);
    $stmt->bindParam(':event_date', $event_date);

    if ($stmt->execute()) {
        echo "<p class='success-message'>Event added successfully!</p>";
    } else {
        echo "<p class='error-message'>Failed to add event.</p>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Event</title>
    <link rel="stylesheet" href="adm.css">
    <style>
        body {
            font-family: 'Merriweather', serif;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
        }
        .navbar {
            width: 100%;
            height: 75px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            background-color: #5e72e4;
            position: fixed; /* Make the navbar fixed */
            top: 0; /* Align it to the top */
            z-index: 1000; /* Ensure it stays above other content */
        }
        .navbar ul {
            list-style-type: none;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
        }
        .navbar li {
            margin: 0 15px;
        }
        .navbar a {
            color: white;
            text-decoration: none;
            font-size: 18px;
        }
        .navbar a:hover {
            text-decoration: underline;
        }

        .form-container {
            background-color: #fff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 100%;
            margin: 100px auto; /* Center the form and create space for the fixed navbar */
        }

        h1 {
            font-family: 'Montserrat', sans-serif;
            color: #007BFF;
            text-align: center;
            margin-bottom: 30px;
        }
 
        label {
            display: block;
            font-weight: bold;
            margin-bottom: 5px;
            color: #333;
        }

        input[type="text"],
        input[type="date"],
        textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 1rem;
            box-sizing: border-box;
        }

        button {
            background-color: #007BFF;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            font-size: 1.2rem;
            transition: background-color 0.3s;
        }

        button:hover {
            background-color: #0056b3;
        }

        .success-message {
            color: green;
            text-align: center;
            margin-top: 20px;
        }

        .error-message {
            color: red;
            text-align: center;
            margin-top: 20px;
        }

        /* Responsive Design */
        @media (max-width: 600px) {
            .form-container {
                padding: 20px;
            }

            h1 {
                font-size: 1.8rem;
            }

            button {
                font-size: 1rem;
            }
        }
    </style>
</head>
<body>

<div class="navbar">
    <div class="icon">
        <h2 class="logo">Xuremi</h2>
    </div>
    <div class="menu" id="menu">
        <ul>
            <li><a href="index.php">HOME</a></li>
            <li><a href="Products.html">PRODUCTS</a></li>
            <li><a href="About.html">ABOUT</a></li>
            <li><a href="#">CONTACTS</a></li>
            <li><a href="news.php">NEWS</a></li>
            <li><a href="#">REVIEWS</a></li>
            <li><a href="admindash.html">DASHBOARD</a></li>
            <li class="search-menu-item">
                <div class="search">
                    <input type="text" class="search__input" placeholder="Search...">
                    <div class="search__icon">
                        <ion-icon name="search"></ion-icon>
                    </div>
                </div>
            </li>
        </ul>
    </div>
</div>

<div class="form-container">
    <h1>Add New Event</h1>
    <form method="POST" action="addevent.php">
        <label for="title">Event Title:</label>
        <input type="text" id="title" name="title" required>

        <label for="description">Event Description:</label>
        <textarea id="description" name="description" rows="5" required></textarea>

        <label for="event_date">Event Date:</label>
        <input type="date" id="event_date" name="event_date" required>

        <button type="submit">Add Event</button>
    </form>
</div>

</body>
</html>
