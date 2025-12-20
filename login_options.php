<?php
// login_options.php (VERSIÓN CORREGIDA PARA IPHONE)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ob_start();

session_start();

require_once 'config/database.php';
require_once 'src/UserRepository.php';

header('Content-Type: application/json');

$debugLog = [];
$debugLog[] = "Inicio de login_options";

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Método no permitido');
    }
    
    $username = $_POST['username'] ?? '';
    
    if (empty($username)) {
        throw new Exception('Username requerido');
    }
    
    $debugLog[] = "Username recibido: " . $username;
    
    $database = new Database();
    $db = $database->getConnection();
    
    if (!$db) {
        throw new Exception('Error de conexión a la base de datos');
    }
    
    $userRepo = new UserRepository($db);
    
    $user = $userRepo->findByUsername($username);
    
    if (!$user) {
        throw new Exception('Usuario no encontrado');
    }
    
    $debugLog[] = "Usuario encontrado, ID: " . $user['id'];
    
    $credentials = $userRepo->getCredentialsByUserId($user['id']);
    
    $debugLog[] = "Credenciales encontradas: " . count($credentials);
    
    $challenge = random_bytes(32);
    
    $_SESSION['login_challenge'] = base64_encode($challenge);
    $_SESSION['login_user_id'] = $user['id'];
    $_SESSION['login_username'] = $username;
    
    $debugLog[] = "Challenge generado y guardado en sesión";
    
    // CONFIGURACIÓN PARA IPHONE
    $optionsArray = [
        'challenge' => base64_encode($challenge),
        'timeout' => 120000,
        'rpId' => 'appmayol.store',  // EXACTO, igual que en el registro
        'userVerification' => 'required'  // ← CRÍTICO: debe ser 'required', no 'preferred'
    ];
    
    if (!empty($credentials)) {
        $allowCredentials = [];
        foreach ($credentials as $cred) {
            $allowCredentials[] = [
                'type' => 'public-key',
                'id' => base64_encode($cred['credential_id']),
                'transports' => ['internal', 'hybrid']  // Agregar 'hybrid' también
            ];
        }
        $optionsArray['allowCredentials'] = $allowCredentials;
        $debugLog[] = "allowCredentials configurado con " . count($allowCredentials) . " credencial(es)";
    }
    
    $debugLog[] = "Opciones preparadas";
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'options' => $optionsArray,
        'debug' => $debugLog
    ]);
    exit;
    
} catch (Exception $e) {
    $debugLog[] = "ERROR: " . $e->getMessage();
    ob_clean();
    echo json_encode([
        'error' => $e->getMessage(),
        'debug' => $debugLog
    ]);
    exit;
}