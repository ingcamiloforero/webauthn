<?php
// login_verify.php (versión corregida para el counter)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ob_start();

session_start();

require_once 'config/database.php';
require_once 'src/UserRepository.php';
require_once 'SimpleCBOR.php';

header('Content-Type: application/json');

$debugLog = [];
$debugLog[] = "Inicio de login_verify";

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Método no permitido');
    }
    
    $json = file_get_contents('php://input');
    
    if (empty($json)) {
        throw new Exception('No se recibieron datos');
    }
    
    $data = json_decode($json, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Error parseando JSON: ' . json_last_error_msg());
    }
    
    $debugLog[] = "JSON recibido y parseado";
    
    if (!isset($_SESSION['login_challenge'])) {
        throw new Exception('No hay challenge en sesión');
    }
    
    if (!isset($_SESSION['login_user_id'])) {
        throw new Exception('No hay user_id en sesión');
    }
    
    $debugLog[] = "Sesión verificada";
    
    if (!isset($data['response']['clientDataJSON'])) {
        throw new Exception('Falta clientDataJSON');
    }
    
    if (!isset($data['response']['authenticatorData'])) {
        throw new Exception('Falta authenticatorData');
    }
    
    if (!isset($data['response']['signature'])) {
        throw new Exception('Falta signature');
    }
    
    $debugLog[] = "Estructura de datos verificada";
    
    // Decodificar clientDataJSON
    $clientDataJSON = base64_decode($data['response']['clientDataJSON']);
    $clientData = json_decode($clientDataJSON, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Error parseando clientDataJSON');
    }
    
    $debugLog[] = "clientDataJSON decodificado";
    
    if ($clientData['type'] !== 'webauthn.get') {
        throw new Exception('Tipo de operación inválido: ' . $clientData['type']);
    }
    
    // Verificar challenge
    $receivedChallenge = $clientData['challenge'];
    $expectedChallenge = $_SESSION['login_challenge'];
    
    $receivedChallengeDecoded = base64_decode(strtr($receivedChallenge, '-_', '+/'));
    $expectedChallengeDecoded = base64_decode($expectedChallenge);
    
    if ($receivedChallengeDecoded !== $expectedChallengeDecoded) {
        throw new Exception('Challenge no coincide');
    }
    
    $debugLog[] = "Challenge verificado correctamente";
    
    // Decodificar authenticatorData
    $authenticatorData = base64_decode($data['response']['authenticatorData']);
    
    if ($authenticatorData === false) {
        throw new Exception('Error decodificando authenticatorData');
    }
    
    $debugLog[] = "authenticatorData decodificado, longitud: " . strlen($authenticatorData);
    
    if (strlen($authenticatorData) < 37) {
        throw new Exception('authenticatorData demasiado corto');
    }
    
    $flags = ord($authenticatorData[32]);
    $counter = unpack('N', substr($authenticatorData, 33, 4))[1];
    
    $debugLog[] = "Flags: " . $flags . ", Counter: " . $counter;
    
    // Verificar flag UP (User Present)
    if (($flags & 0x01) === 0) {
        throw new Exception('User Present flag no está activado');
    }
    
    $debugLog[] = "Flag UP verificado";
    
    // Conectar a BD
    $database = new Database();
    $db = $database->getConnection();
    
    if (!$db) {
        throw new Exception('Error de conexión a la base de datos');
    }
    
    $userRepo = new UserRepository($db);
    
    $userId = $_SESSION['login_user_id'];
    $username = $_SESSION['login_username'];
    
    // Debug de credential_id
    $credentialIdRaw = base64_decode($data['id']);
    $debugLog[] = "Credential ID recibido (raw): " . bin2hex($credentialIdRaw);
    $debugLog[] = "Credential ID recibido (base64): " . $data['id'];
    $debugLog[] = "Longitud del credential ID: " . strlen($credentialIdRaw);
    
    // Debug de credenciales en BD
    $allUserCredentials = $userRepo->getCredentialsByUserId($userId);
    $debugLog[] = "Credenciales en BD para user_id $userId: " . count($allUserCredentials);
    
    foreach ($allUserCredentials as $idx => $cred) {
        $credIdFromDb = $cred['credential_id'];
        $debugLog[] = "Credencial #" . ($idx + 1) . " en BD: " . bin2hex($credIdFromDb) . " (longitud: " . strlen($credIdFromDb) . ")";
        $debugLog[] = "¿Coinciden? " . ($credentialIdRaw === $credIdFromDb ? "SÍ" : "NO");
    }
    
    // Usar rawId del cliente
    $credentialIdRaw = base64_decode($data['rawId']);
    $debugLog[] = "Buscando credencial con rawId: " . bin2hex($credentialIdRaw);
    $debugLog[] = "Longitud: " . strlen($credentialIdRaw);
    
    $credential = $userRepo->getCredentialById($credentialIdRaw);
    
    if (!$credential) {
        throw new Exception('Credencial no encontrada');
    }
    
    if ($credential['user_id'] != $userId) {
        throw new Exception('La credencial no pertenece a este usuario');
    }
    
    $debugLog[] = "Credencial verificada";
    
    // Verificar counter (CORREGIDO)
    $storedCounter = (int)$credential['counter'];
    $debugLog[] = "Counter almacenado en BD: " . $storedCounter;
    $debugLog[] = "Counter recibido del autenticador: " . $counter;
    
    // El counter debe incrementarse, pero algunos autenticadores pueden devolver 0
    // Si el counter almacenado es 0 y el recibido también es 0, permitir (primer uso)
    // Si el counter almacenado es mayor que 0, el nuevo debe ser estrictamente mayor
    if ($storedCounter > 0 && $counter <= $storedCounter) {
        $debugLog[] = "⚠️ Counter no incrementó - posible replay attack";
        throw new Exception('Counter inválido - posible replay attack (esperado > ' . $storedCounter . ', recibido: ' . $counter . ')');
    }
    
    // Si ambos son 0, es el primer uso - permitir y actualizar
    if ($storedCounter == 0 && $counter == 0) {
        $debugLog[] = "Primer uso de la credencial (counter = 0), permitiendo...";
        // Incrementar a 1 para futuras validaciones
        $counter = 1;
    }
    
    $debugLog[] = "Counter verificado correctamente";
    
    // Actualizar counter
    $userRepo->updateCredentialCounter($credential['id'], $counter);
    $debugLog[] = "Counter actualizado a: " . $counter;
    
    
    $debugLog[] = "⚠️ ADVERTENCIA: Verificación de firma omitida (implementar en producción)";
    
    // Actualizar last_used
    $userRepo->updateCredentialLastUsed($credential['id']);
    
    // Login exitoso
    $_SESSION['user_id'] = $userId;
    $_SESSION['username'] = $username;
    $_SESSION['logged_in'] = true;
    $_SESSION['login_time'] = time();
    
    // Limpiar variables de login
    unset($_SESSION['login_challenge']);
    unset($_SESSION['login_user_id']);
    unset($_SESSION['login_username']);
    
    $debugLog[] = "✅ LOGIN EXITOSO";
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'message' => 'Login exitoso',
        'username' => $username,
        'redirect' => 'dashboard.php',
        'debug' => $debugLog
    ]);
    exit;
    
} catch (Exception $e) {
    $debugLog[] = "❌ ERROR: " . $e->getMessage();
    $debugLog[] = "Línea: " . $e->getLine();
    
    ob_clean();
    header('Content-Type: application/json');
    echo json_encode([
        'error' => $e->getMessage(),
        'debug' => $debugLog
    ]);
    exit;
}
