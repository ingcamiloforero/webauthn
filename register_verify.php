<?php
// register_verify.php (versión corregida)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ob_start();

session_start();

require_once 'config/database.php';
require_once 'src/UserRepository.php';
require_once 'SimpleCBOR.php';

header('Content-Type: application/json');

$debugLog = [];
$debugLog[] = "Inicio de script";

try {
    require_once 'config/database.php';
    require_once 'src/UserRepository.php';
    require_once 'SimpleCBOR.php';
    
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
    
    $debugLog[] = "JSON parseado correctamente";
    
    if (!isset($_SESSION['registration_challenge'])) {
        throw new Exception('No hay challenge en sesión');
    }
    
    if (!isset($_SESSION['registration_username'])) {
        throw new Exception('No hay username en sesión');
    }
    
    if (!isset($_SESSION['registration_user_handle'])) {
        throw new Exception('No hay user_handle en sesión');
    }
    
    $debugLog[] = "Sesión verificada";
    
    if (!isset($data['response']['clientDataJSON'])) {
        throw new Exception('Falta clientDataJSON');
    }
    
    if (!isset($data['response']['attestationObject'])) {
        throw new Exception('Falta attestationObject');
    }
    
    if (!isset($data['rawId'])) {
        throw new Exception('Falta rawId');
    }
    
    $debugLog[] = "Estructura de datos verificada";
    
    // Decodificar clientDataJSON
    $clientDataJSON = base64_decode($data['response']['clientDataJSON']);
    $clientData = json_decode($clientDataJSON, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Error parseando clientDataJSON');
    }
    
    $debugLog[] = "clientDataJSON decodificado";
    
    if ($clientData['type'] !== 'webauthn.create') {
        throw new Exception('Tipo de operación inválido: ' . $clientData['type']);
    }
    
    // Verificar challenge
    $receivedChallenge = $clientData['challenge'];
    $expectedChallenge = $_SESSION['registration_challenge'];
    
    $receivedChallengeDecoded = base64_decode(strtr($receivedChallenge, '-_', '+/'));
    $expectedChallengeDecoded = base64_decode($expectedChallenge);
    
    if ($receivedChallengeDecoded !== $expectedChallengeDecoded) {
        throw new Exception('Challenge no coincide');
    }
    
    $debugLog[] = "Challenge verificado correctamente";
    
    // Decodificar attestation object
    $attestationObjectBase64 = $data['response']['attestationObject'];
    $attestationObject = base64_decode($attestationObjectBase64);
    
    if ($attestationObject === false) {
        throw new Exception('Error decodificando attestationObject de base64');
    }
    
    $debugLog[] = "attestationObject decodificado, tamaño: " . strlen($attestationObject) . " bytes";
    
    try {
        $attestationData = SimpleCBOR::decode($attestationObject);
        $debugLog[] = "CBOR decodificado con SimpleCBOR";
    } catch (Exception $e) {
        throw new Exception('Error decodificando CBOR: ' . $e->getMessage());
    }
    
    if (!isset($attestationData['authData'])) {
        throw new Exception('authData no encontrado');
    }
    
    $authData = $attestationData['authData'];
    $authDataLength = strlen($authData);
    
    $debugLog[] = "authData encontrado, longitud: " . $authDataLength;
    
    if ($authDataLength < 37) {
        throw new Exception('authData demasiado corto: ' . $authDataLength . ' bytes');
    }
    
    // Extraer información básica del authData
    $rpIdHash = substr($authData, 0, 32);
    $flags = ord($authData[32]);
    $counter = unpack('N', substr($authData, 33, 4))[1];
    
    $debugLog[] = "Flags: " . $flags . ", Counter: " . $counter;
    
    if (($flags & 0x40) === 0) {
        throw new Exception('Flag AT no presente');
    }
    
    $debugLog[] = "Flag AT verificado";
    
    // Extraer AAGUID
    if ($authDataLength < 55) {
        throw new Exception('authData demasiado corto para AAGUID');
    }
    
    $aaguid = substr($authData, 37, 16);
    $debugLog[] = "AAGUID extraído";
    
    // IMPORTANTE: Usar rawId del cliente en lugar de extraerlo del authData
    // Esto es más confiable
    $credentialId = base64_decode($data['rawId']);
    $debugLog[] = "Usando rawId del cliente como credential_id";
    $debugLog[] = "Credential ID (hex): " . bin2hex($credentialId);
    $debugLog[] = "Credential ID (longitud): " . strlen($credentialId);
    
    // Extraer clave pública del authData
    $credIdLengthData = substr($authData, 53, 2);
    $credIdLength = unpack('n', $credIdLengthData)[1];
    $publicKeyOffset = 55 + $credIdLength;
    
    if ($authDataLength <= $publicKeyOffset) {
        throw new Exception('No hay datos de clave pública');
    }
    
    $publicKeyCbor = substr($authData, $publicKeyOffset);
    $debugLog[] = "Clave pública extraída, longitud: " . strlen($publicKeyCbor);
    
    // Conectar a base de datos
    $database = new Database();
    $db = $database->getConnection();
    
    if (!$db) {
        throw new Exception('Error conectando a la base de datos');
    }
    
    $debugLog[] = "Conectado a base de datos";
    
    $userRepo = new UserRepository($db);
    
    $username = $_SESSION['registration_username'];
    $userHandle = base64_decode($_SESSION['registration_user_handle']);
    
    $debugLog[] = "Intentando crear usuario: " . $username;
    
    // Verificar si el usuario ya existe
    $existingUser = $userRepo->findByUsername($username);
    if ($existingUser) {
        throw new Exception('El usuario ya existe');
    }
    
    // Crear usuario
    $userCreated = $userRepo->createUser($username, $userHandle);
    
    if (!$userCreated) {
        throw new Exception('Error creando usuario en la base de datos');
    }
    
    $debugLog[] = "Usuario creado exitosamente";
    
    // Buscar el usuario creado
    $user = $userRepo->findByUsername($username);
    
    if (!$user) {
        throw new Exception('Error recuperando usuario recién creado');
    }
    
    $debugLog[] = "Usuario recuperado, ID: " . $user['id'];
    
    // Guardar credencial
    $credentialSaved = $userRepo->saveCredential(
        $user['id'],
        $credentialId,
        $publicKeyCbor,
        $counter,
        $aaguid
    );
    
    if (!$credentialSaved) {
        throw new Exception('Error guardando credencial');
    }
    
    $debugLog[] = "Credencial guardada exitosamente";
    
    // Limpiar sesión
    unset($_SESSION['registration_challenge']);
    unset($_SESSION['registration_username']);
    unset($_SESSION['registration_user_handle']);
    
    $debugLog[] = "Sesión limpiada";
    $debugLog[] = "✅ REGISTRO COMPLETADO EXITOSAMENTE";
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'message' => 'Usuario registrado correctamente',
        'debug' => $debugLog,
        'user_id' => $user['id']
    ]);
    exit;
    
} catch (Exception $e) {
    $debugLog[] = "❌ ERROR: " . $e->getMessage();
    $debugLog[] = "Línea: " . $e->getLine();
    $debugLog[] = "Archivo: " . $e->getFile();
    
    ob_clean();
    header('Content-Type: application/json');
    echo json_encode([
        'error' => $e->getMessage(),
        'debug' => $debugLog
    ]);
    exit;
}