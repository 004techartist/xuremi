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

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = $_POST['title'];
    $content = $_POST['content'];
    $summary = $_POST['summary'];

   
    $errorMessage = "";

    // Handle the file upload
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $title = $_POST['title'];
        $content = $_POST['content'];
        $summary = isset($_POST['summary']) ? $_POST['summary'] : ''; // Check for summary
        
        $errorMessage = "";
    
        // Handle the file upload
        if (isset($_FILES['thumbnail']) && $_FILES['thumbnail']['error'] === 0) {
            $targetDir = "uploads/";
            $fileName = basename($_FILES['thumbnail']['name']);
            $targetFilePath = $targetDir . $fileName;
            $fileType = pathinfo($targetFilePath, PATHINFO_EXTENSION);
    
            $allowedTypes = ['jpg', 'jpeg', 'png', 'gif'];
            if (in_array(strtolower($fileType), $allowedTypes)) {
                if (move_uploaded_file($_FILES['thumbnail']['tmp_name'], $targetFilePath)) {
                    // Insert blog into the database
                    $stmt = $pdo->prepare("INSERT INTO blogs (title, content, image, summary) VALUES (:title, :content, :image, :summary)");
                    $stmt->bindParam(':title', $title);
                    $stmt->bindParam(':content', $content);
                    $stmt->bindParam(':image', $fileName);
                    $stmt->bindParam(':summary', $summary);
    
                    if ($stmt->execute()) {
                        $successMessage = "Blog uploaded successfully!";
                    } else {
                        $errorMessage = "Failed to save blog to the database.";
                    }
                } else {
                    $errorMessage = "Failed to upload image.";
                }
            } else {
                $errorMessage = "Invalid file format. Only JPG, JPEG, PNG, and GIF are allowed.";
            }
        } else {
            $errorMessage = "Please upload an image.";
        }
    }}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Blog</title>
    <link rel="stylesheet" href="adm.css">

    <!-- Import custom fonts from Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Lora:wght@400;700&display=swap" rel="stylesheet">
    <link href="https://cdn.quilljs.com/1.0.0/quill.snow.css" rel="stylesheet">
    <link href="https://fonts.cdnfonts.com/css/inconsolata-2" rel="stylesheet">

    <style>
        #toolbar-container {
            margin-bottom: 10px;
            background-color: #f8f8f8;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        
        #editor-container {
            height: 400px;
            border: 1px solid #ccc;
            border-radius: 4px;
            padding: 10px;
        }

        /* Custom fonts */
        .ql-font-roboto { font-family: 'Roboto', sans-serif; }
        .ql-font-lora { font-family: 'Lora', serif; }
        .ql-font-inconsolata { font-family: 'Inconsolata', monospace; }
        .ql-font-arial { font-family: 'Arial', sans-serif; }
    </style>
</head>
<body>
<div class="main"></div>
    <div class="navbar">
        <div class="icon">
            <h2 class="logo">Xuremi</h2>
        </div>
        <div class="menu" id="menu">
            <ul>
                <li><a href="index.php">HOME</a></li>
                <li><a href="customercompany.php">PRODUCTS</a></li>
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
        <div class="hamburger" id="hamburger">
            <ion-icon name="menu-outline"></ion-icon>
        </div>
    </div>
    <h1>Upload a Blog</h1>

    <form action="" method="post" enctype="multipart/form-data">
        <div>
            <label for="title">Blog Title:</label>
            <input type="text" name="title" id="title" required>
        </div>
        <div>
            <label for="content">Content:</label>

            <!-- Toolbar for font selection and editing -->
            <div id="toolbar-container">
                <span class="ql-formats">
                    <select class="ql-font">
                        <option selected>Sans Serif</option>
                        <option value="inconsolata">Inconsolata</option>
                        <option value="roboto">Roboto</option>
                        <option value="lora">Lora</option>
                        <option value="arial">Arial</option>
                    </select>
                    <select class="ql-size"></select>
                </span>
                <span class="ql-formats">
                    <button class="ql-bold"></button>
                    <button class="ql-italic"></button>
                    <button class="ql-underline"></button>
                    <button class="ql-strike"></button>
                </span>
                <span class="ql-formats">
                    <select class="ql-color"></select>
                    <select class="ql-background"></select>
                </span>
                <span class="ql-formats">
                    <button class="ql-blockquote"></button>
                    <button class="ql-code-block"></button>
                    <button class="ql-link"></button>
                </span>
                <span class="ql-formats">
                    <button class="ql-header" value="1"></button>
                    <button class="ql-header" value="2"></button>
                </span>
                <span class="ql-formats">
                    <button class="ql-list" value="ordered"></button>
                    <button class="ql-list" value="bullet"></button>
                </span>
            </div>

            <div id="editor-container"></div>
            <input type="hidden" name="content" id="content" required>
        </div>
        <div>
            <label for="thumbnail">Blog Thumbnail (JPG, PNG, GIF):</label>
            <input type="file" name="thumbnail" id="thumbnail" accept="image/*" required>
        </div>
        <div>
    <label for="summary">Summary:</label>
    <input type="text" name="summary" id="summary" required>
</div>

        <div>
            <button type="submit" onclick="submitForm()">Upload Blog</button>
        </div>
    </form>

    <script src="https://cdn.quilljs.com/1.0.0/quill.js"></script>
    <script>
        let Font = Quill.import('formats/font');
        Font.whitelist = ['inconsolata', 'roboto', 'lora', 'arial'];
        Quill.register(Font, true);

        let quill = new Quill('#editor-container', {
            modules: {
                toolbar: '#toolbar-container'
            },
            placeholder: 'Write your blog content here...',
            theme: 'snow'
        });

        function submitForm() {
            var content = quill.root.innerHTML;
            document.getElementById('content').value = content;
        }
    </script>
</body>
</html>



