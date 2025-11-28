<?php
// api.php - simple standalone API to drop into your htdocs/api/ folder
// Usage:
// POST /api.php?action=login       JSON body: {"email":"...","password":"..."}
// GET  /api.php?action=health
// POST /api.php?action=analyze-sms JSON body: {"message":"...","sender":"...","user_hash":"..."}

// -----------------
// Configuration
// -----------------
// Edit these values or set environment variables in your Apache/htdocs environment
$DB_HOST = getenv('MYSQL_HOST') ?: '127.0.0.1';
$DB_USER = getenv('MYSQL_USER') ?: 'root';
$DB_PASS = getenv('MYSQL_PASSWORD') ?: '';
$DB_NAME = getenv('MYSQL_DATABASE') ?: 'cyber_sorcier';
$SECRET_KEY = getenv('SECRET_KEY') ?: 'dev-secret-key-change-me';

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

// -----------------
// Helpers
// -----------------
function send_json($data, $code = 200) {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function get_json_body() {
    $body = file_get_contents('php://input');
    if (!$body) return null;
    $data = json_decode($body, true);
    return $data;
}

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) $data .= str_repeat('=', 4 - $remainder);
    return base64_decode(strtr($data, '-_', '+/'));
}

function jwt_encode($payload, $secret) {
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $segments = [];
    $segments[] = base64url_encode(json_encode($header));
    $segments[] = base64url_encode(json_encode($payload));
    $signing_input = implode('.', $segments);
    $signature = hash_hmac('sha256', $signing_input, $secret, true);
    $segments[] = base64url_encode($signature);
    return implode('.', $segments);
}

function jwt_decode($token, $secret) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    list($h, $p, $s) = $parts;
    $sig = base64url_decode($s);
    $check = hash_hmac('sha256', "$h.$p", $secret, true);
    if (!hash_equals($check, $sig)) return null;
    $payload = json_decode(base64url_decode($p), true);
    if (isset($payload['exp']) && time() > $payload['exp']) return null;
    return $payload;
}

// -----------------
// Auth helpers (Bearer JWT)
// -----------------
function get_bearer_token_payload($secret) {
    $hdr = null;
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $hdr = trim($_SERVER['HTTP_AUTHORIZATION']);
    } elseif (function_exists('apache_request_headers')) {
        $headers = apache_request_headers();
        if (!empty($headers['Authorization'])) $hdr = trim($headers['Authorization']);
    }
    if (!$hdr) return null;
    if (stripos($hdr, 'Bearer ') !== 0) return null;
    $token = substr($hdr, 7);
    return jwt_decode($token, $secret);
}

function require_auth_or_die($secret) {
    $payload = get_bearer_token_payload($secret);
    if (!$payload) {
        http_response_code(401);
        echo json_encode(['message' => 'Token manquant ou invalide']);
        exit;
    }
    return $payload;
}

// -----------------
// DB connection
// -----------------
$mysqli = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if ($mysqli->connect_errno) {
    // Return 500 so frontend knows DB not available
    send_json(['message' => 'Impossible de se connecter à la base de données', 'error' => $mysqli->connect_error], 500);
}
$mysqli->set_charset('utf8mb4');

// -----------------
// Routing by ?action=...
// -----------------
$action = isset($_GET['action']) ? $_GET['action'] : '';
switch ($action) {
    case 'health':
        send_json(['status' => 'healthy', 'service' => 'Cyber-Sorcier PHP API']);
        break;

    case 'login':
        $data = get_json_body();
        if (!$data || !isset($data['email']) || !isset($data['password'])) {
            send_json(['message' => 'Email et mot de passe requis'], 400);
        }
        $email = $mysqli->real_escape_string($data['email']);
        $password = $data['password'];

        // try users table first (password_hash)
        $res = $mysqli->query("SELECT id, email, password_hash AS password, role FROM users WHERE email = '$email' LIMIT 1");
        $user = $res ? $res->fetch_assoc() : null;
        if (!$user) {
            $res = $mysqli->query("SELECT id, username, email, password, role FROM admins WHERE email = '$email' LIMIT 1");
            $user = $res ? $res->fetch_assoc() : null;
            if ($user) {
                // normalize: admins use 'password' column
                $user['password'] = $user['password'];
            }
        }

        if (!$user) send_json(['message' => 'Identifiants invalides'], 401);

        $stored = $user['password'];
        $pwd_ok = false;
        // try PHP password_verify
        if (function_exists('password_verify')) {
            try { $pwd_ok = password_verify($password, $stored); } catch (Exception $e) { $pwd_ok = false; }
        }
        // fallback plaintext compare
        if (!$pwd_ok) $pwd_ok = ($password === $stored);

        if (!$pwd_ok) send_json(['message' => 'Identifiants invalides'], 401);

        $payload = ['sub' => $user['id'], 'email' => $user['email'], 'role' => $user['role'] ?? null, 'exp' => time() + 86400];
        $token = jwt_encode($payload, $SECRET_KEY);
        send_json(['token' => $token, 'user' => ['id' => $user['id'], 'email' => $user['email'], 'role' => $user['role'] ?? null]]);
        break;

    case 'analyze-sms':
        // Require auth for reporting
        $payload = require_auth_or_die($SECRET_KEY);
        $data = get_json_body();
        if (!$data || !isset($data['message']) || !isset($data['sender'])) {
            send_json(['error' => 'Données manquantes'], 400);
        }
        $message = $mysqli->real_escape_string($data['message']);
        $sender = $mysqli->real_escape_string($data['sender']);
        // prefer provided user_hash, otherwise use subject from token
        $user_hash = isset($data['user_hash']) ? $mysqli->real_escape_string($data['user_hash']) : (isset($payload['sub']) ? $mysqli->real_escape_string($payload['sub']) : 'anonymous');

        // simple analysis
        $risk_score = 0.1; $is_risky = 0; $threats = [];
        if (stripos($message, 'urgent') !== false) { $risk_score = 0.9; $is_risky = 1; $threats[] = 'urgent'; }

        // save report
        $stmt = $mysqli->prepare("INSERT INTO sms_reports (user_hash, phone_number, message_text, risk_score, is_risky, detected_threats) VALUES (?, ?, ?, ?, ?, ?)");
        $detected = implode(', ', $threats);
        $stmt->bind_param('sssdis', $user_hash, $sender, $message, $risk_score, $is_risky, $detected);
        @$stmt->execute();

        send_json(['risk_score' => $risk_score, 'is_risky' => $is_risky, 'threats' => $threats]);
        break;

    case 'me':
        $payload = require_auth_or_die($SECRET_KEY);
        send_json(['user' => ['id' => $payload['sub'], 'email' => $payload['email'], 'role' => $payload['role'] ?? null]]);
        break;

    case 'blacklist':
        // require auth for admin endpoints
        $payload = require_auth_or_die($SECRET_KEY);
        $res = $mysqli->query("SELECT id, phone_number, reason, is_active, created_at FROM blacklist ORDER BY created_at DESC");
        $rows = [];
        if ($res) {
            while ($r = $res->fetch_assoc()) $rows[] = $r;
        }
        send_json(['blacklist' => $rows]);
        break;

    case 'blacklist_add':
        $payload = require_auth_or_die($SECRET_KEY);
        $data = get_json_body();
        if (!$data || !isset($data['phone_number'])) send_json(['message' => 'phone_number required'], 400);
        $phone = $mysqli->real_escape_string($data['phone_number']);
        $reason = isset($data['reason']) ? $mysqli->real_escape_string($data['reason']) : '';
        $is_active = isset($data['is_active']) ? (int)$data['is_active'] : 1;
        $stmt = $mysqli->prepare("INSERT INTO blacklist (phone_number, reason, is_active, created_at) VALUES (?, ?, ?, NOW())");
        $stmt->bind_param('ssi', $phone, $reason, $is_active);
        $ok = $stmt->execute();
        if (!$ok) send_json(['message' => 'Failed to insert'], 500);
        $id = $mysqli->insert_id;
        send_json(['id' => $id, 'phone_number' => $phone, 'reason' => $reason, 'is_active' => $is_active]);
        break;

    case 'blacklist_delete':
        $payload = require_auth_or_die($SECRET_KEY);
        $data = get_json_body();
        if (!$data || !isset($data['id'])) send_json(['message' => 'id required'], 400);
        $id = intval($data['id']);
        $stmt = $mysqli->prepare("DELETE FROM blacklist WHERE id = ?");
        $stmt->bind_param('i', $id);
        $ok = $stmt->execute();
        if (!$ok) send_json(['message' => 'Failed to delete'], 500);
        send_json(['deleted' => $id]);
        break;

    case 'reports':
        $payload = require_auth_or_die($SECRET_KEY);
        $limit = isset($_GET['limit']) ? intval($_GET['limit']) : 50;
        $limit = max(1, min(1000, $limit));
        $stmt = $mysqli->prepare("SELECT id, user_hash, phone_number, message_text, risk_score, is_risky, detected_threats, created_at FROM sms_reports ORDER BY created_at DESC LIMIT ?");
        $stmt->bind_param('i', $limit);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        send_json(['reports' => $rows]);
        break;

    case 'stats':
        $payload = require_auth_or_die($SECRET_KEY);
        $total = 0; $risky = 0; $blacklisted = 0;
        $r = $mysqli->query("SELECT COUNT(*) AS c FROM sms_reports");
        if ($r) { $row = $r->fetch_assoc(); $total = intval($row['c']); }
        $r = $mysqli->query("SELECT COUNT(*) AS c FROM sms_reports WHERE is_risky = 1");
        if ($r) { $row = $r->fetch_assoc(); $risky = intval($row['c']); }
        $r = $mysqli->query("SELECT COUNT(*) AS c FROM blacklist WHERE is_active = 1");
        if ($r) { $row = $r->fetch_assoc(); $blacklisted = intval($row['c']); }
        send_json(['total_reports' => $total, 'risky_reports' => $risky, 'blacklisted_numbers' => $blacklisted]);
        break;

    case 'stats_series':
        // return counts per day for last 7 days
        $payload = require_auth_or_die($SECRET_KEY);
        $rows = [];
        $q = "SELECT DATE(created_at) as day, COUNT(*) as total, SUM(is_risky) as risky FROM sms_reports WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY) GROUP BY DATE(created_at) ORDER BY day ASC";
        $res = $mysqli->query($q);
        if ($res) {
            while ($r = $res->fetch_assoc()) {
                $rows[] = ['day' => $r['day'], 'total' => intval($r['total']), 'risky' => intval($r['risky'])];
            }
        }
        send_json(['series' => $rows]);
        break;

    default:
        send_json(['message' => 'Endpoint not found'], 404);
}

?>
