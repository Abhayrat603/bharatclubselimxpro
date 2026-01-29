<?php
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'tiny-term-90263711');
define('DB_PASSWORD', 'tiny-term-90263711');
define('DB_NAME', 'tiny-term-90263711');

function getDBConnection() {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    return $conn;
}
?>
