<?php
/*
This file contains database config.phpuration assuming you are running mysql using user "root" and password ""
*/

define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'tiny-term-90263711');
define('DB_PASSWORD', 'tiny-term-90263711');
define('DB_NAME', 'tiny-term-90263711');

// Try connecting to the Database
$conn = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

//Check the connection
if($conn == false){
    dir('Error: Cannot connect');
    Echo"Fail";
}

?>