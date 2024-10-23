DROP DATABASE IF EXISTS xuremi_db;
CREATE DATABASE xuremi_db;
USE xuremi_db;

-- Create users table with roles for admin management
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('USER', 'ADMIN', 'SUPER_ADMIN') DEFAULT 'USER' NOT NULL,
    can_add_admin BOOLEAN DEFAULT FALSE
);

-- Create products table for uploaded apps

CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    file_url VARCHAR(255) NOT NULL,
    credit_score INT NOT NULL
);


-- Display the users table
SHOW TABLES;
SELECT * FROM products;
SELECT * FROM users;
