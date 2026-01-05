<?php

$user_data = $_POST['data'];

// Safe
$json = json_decode($user_data);

// Vulnerable (High Confidence)
$obj = unserialize($user_data);

// Hardcoded / Safe (Low Confidence - Ignored/Blue)
$test = unserialize('s:4:"test";');
$test2 = unserialize("a:1:{s:3:'foo';s:3:'bar';}");
