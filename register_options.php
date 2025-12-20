<?php
// register_options.php (VERSIÓN CORREGIDA PARA IPHONE)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ob_start();

session_start();

require_once 'config/database.php';
require_once 'src/UserRepository.php';

header('Content-Type: application/json');

$username = $_POST['username'] ?? '';

if (empty($username)) {
    ob_clean();
    echo json_encode(['error' => 'Username requerido']);
    exit;
}

// Conectar a BD
$database = new Database();
$db = $database->getConnection();
$userRepo = new UserRepository($db);

// Verificar si el usuario ya existe
$existingUser = $userRepo->findByUsername($username);
if ($existingUser) {
    ob_clean();
    echo json_encode(['error' => 'Usuario ya existe']);
    exit;
}

// Generar user handle único
$userHandle = random_bytes(64);

// Configurar opciones (formato simplificado, sin usar las clases de la librería)
$challenge = random_bytes(32);

// Guardar en sesión
$_SESSION['registration_challenge'] = base64_encode($challenge);
$_SESSION['registration_username'] = $username;
$_SESSION['registration_user_handle'] = base64_encode($userHandle);

// CONFIGURACIÓN CRÍTICA PARA IPHONE
$optionsArray = [
    'rp' => [
        'name' => 'AppMayol',
        'id' => 'appmayol.store'  // EXACTO, sin www
    ],
    'user' => [
        'id' => base64_encode($userHandle),
        'name' => $username,
        'displayName' => $username
    ],
    'challenge' => base64_encode($challenge),
    'pubKeyCredParams' => [
        ['type' => 'public-key', 'alg' => -7],   // ES256
        ['type' => 'public-key', 'alg' => -257]  // RS256
    ],
    'timeout' => 120000,
    'authenticatorSelection' => [
        'authenticatorAttachment' => 'platform',  // Solo Face ID/Touch ID
        'residentKey' => 'required',              // ← CRÍTICO para iPhone
        'requireResidentKey' => true,             // ← CRÍTICO para iPhone
        'userVerification' => 'required'          // ← CRÍTICO para Face ID
    ],
    'attestation' => 'none',
    'excludeCredentials' => []  // No excluir ninguna credencial
];

ob_clean();
echo json_encode($optionsArray);
exit;