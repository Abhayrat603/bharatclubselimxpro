<?php
	$conn = mysqli_connect('localhost', 'tiny-term-90263711', 'tiny-term-90263711', 'tiny-term-90263711');
	
	if (!$conn) {
		echo "Error: " . mysqli_connect_error();
		exit();
	}
	
	date_default_timezone_set("Asia/Kolkata"); 
?>