<?php
// src/UserRepository.php
class UserRepository {
    private $conn;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function findByUsername($username) {
        $query = "SELECT * FROM users WHERE username = :username LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":username", $username);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function createUser($username, $userHandle) {
        $query = "INSERT INTO users (username, user_handle) VALUES (:username, :user_handle)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":username", $username);
        $stmt->bindParam(":user_handle", $userHandle);
        return $stmt->execute();
    }

    

    public function saveCredential($userId, $credentialId, $publicKey, $counter, $aaguid) {
        $query = "INSERT INTO webauthn_credentials 
                  (user_id, credential_id, public_key, counter, aaguid) 
                  VALUES (:user_id, :credential_id, :public_key, :counter, :aaguid)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $userId);
        $stmt->bindParam(":credential_id", $credentialId);
        $stmt->bindParam(":public_key", $publicKey);
        $stmt->bindParam(":counter", $counter);
        $stmt->bindParam(":aaguid", $aaguid);
        return $stmt->execute();
    }

    public function getCredentialsByUserId($userId) {
        $query = "SELECT * FROM webauthn_credentials WHERE user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $userId);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getCredentialById($credentialId) {
    try {
        $query = "SELECT * FROM webauthn_credentials WHERE credential_id = :credential_id LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":credential_id", $credentialId);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        error_log("getCredentialById - Found: " . ($result ? 'Yes' : 'No'));
        
        return $result;
    } catch (PDOException $e) {
        error_log("getCredentialById ERROR: " . $e->getMessage());
        throw $e;
    }
}

public function updateCredentialCounter($credentialId, $counter) {
    try {
        $query = "UPDATE webauthn_credentials SET counter = :counter WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":counter", $counter);
        $stmt->bindParam(":id", $credentialId);
        $result = $stmt->execute();
        
        error_log("updateCredentialCounter - ID: $credentialId, Counter: $counter");
        
        return $result;
    } catch (PDOException $e) {
        error_log("updateCredentialCounter ERROR: " . $e->getMessage());
        throw $e;
    }
}

public function updateCredentialLastUsed($credentialId) {
    try {
        $query = "UPDATE webauthn_credentials SET last_used = NOW() WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $credentialId);
        $result = $stmt->execute();
        
        error_log("updateCredentialLastUsed - ID: $credentialId");
        
        return $result;
    } catch (PDOException $e) {
        error_log("updateCredentialLastUsed ERROR: " . $e->getMessage());
        throw $e;
    }
}
}