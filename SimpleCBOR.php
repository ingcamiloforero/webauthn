<?php
// SimpleCBOR.php - Decodificador CBOR simple para WebAuthn

class SimpleCBOR {
    
    /**
     * Decodifica datos CBOR
     */
    public static function decode($data) {
        $decoder = new self();
        $result = $decoder->decodeInternal($data, 0);
        return $result['value'];
    }
    
    private function decodeInternal($data, $offset) {
        if ($offset >= strlen($data)) {
            throw new Exception('Datos CBOR incompletos');
        }
        
        $initialByte = ord($data[$offset]);
        $majorType = $initialByte >> 5;
        $additionalInfo = $initialByte & 0x1f;
        
        $offset++;
        
        switch ($majorType) {
            case 0: // Entero positivo
                return $this->decodeInteger($data, $offset, $additionalInfo, false);
                
            case 1: // Entero negativo
                return $this->decodeInteger($data, $offset, $additionalInfo, true);
                
            case 2: // Byte string
                return $this->decodeByteString($data, $offset, $additionalInfo);
                
            case 3: // Text string
                return $this->decodeTextString($data, $offset, $additionalInfo);
                
            case 4: // Array
                return $this->decodeArray($data, $offset, $additionalInfo);
                
            case 5: // Map
                return $this->decodeMap($data, $offset, $additionalInfo);
                
            case 7: // Floating point, simple values, break
                return $this->decodeSpecial($data, $offset, $additionalInfo);
                
            default:
                throw new Exception('Tipo CBOR no soportado: ' . $majorType);
        }
    }
    
    private function decodeInteger($data, $offset, $additionalInfo, $negative) {
        $length = 0;
        $value = 0;
        
        if ($additionalInfo < 24) {
            $value = $additionalInfo;
        } elseif ($additionalInfo == 24) {
            $value = ord($data[$offset]);
            $length = 1;
        } elseif ($additionalInfo == 25) {
            $value = unpack('n', substr($data, $offset, 2))[1];
            $length = 2;
        } elseif ($additionalInfo == 26) {
            $value = unpack('N', substr($data, $offset, 4))[1];
            $length = 4;
        } elseif ($additionalInfo == 27) {
            $value = unpack('J', substr($data, $offset, 8))[1];
            $length = 8;
        }
        
        if ($negative) {
            $value = -1 - $value;
        }
        
        return [
            'value' => $value,
            'offset' => $offset + $length
        ];
    }
    
    private function decodeByteString($data, $offset, $additionalInfo) {
        $lengthInfo = $this->getLength($data, $offset, $additionalInfo);
        $length = $lengthInfo['value'];
        $offset = $lengthInfo['offset'];
        
        $value = substr($data, $offset, $length);
        
        return [
            'value' => $value,
            'offset' => $offset + $length
        ];
    }
    
    private function decodeTextString($data, $offset, $additionalInfo) {
        $result = $this->decodeByteString($data, $offset, $additionalInfo);
        return $result;
    }
    
    private function decodeArray($data, $offset, $additionalInfo) {
        $lengthInfo = $this->getLength($data, $offset, $additionalInfo);
        $length = $lengthInfo['value'];
        $offset = $lengthInfo['offset'];
        
        $array = [];
        for ($i = 0; $i < $length; $i++) {
            $item = $this->decodeInternal($data, $offset);
            $array[] = $item['value'];
            $offset = $item['offset'];
        }
        
        return [
            'value' => $array,
            'offset' => $offset
        ];
    }
    
    private function decodeMap($data, $offset, $additionalInfo) {
        $lengthInfo = $this->getLength($data, $offset, $additionalInfo);
        $length = $lengthInfo['value'];
        $offset = $lengthInfo['offset'];
        
        $map = [];
        for ($i = 0; $i < $length; $i++) {
            $key = $this->decodeInternal($data, $offset);
            $offset = $key['offset'];
            
            $value = $this->decodeInternal($data, $offset);
            $offset = $value['offset'];
            
            $map[$key['value']] = $value['value'];
        }
        
        return [
            'value' => $map,
            'offset' => $offset
        ];
    }
    
    private function decodeSpecial($data, $offset, $additionalInfo) {
        if ($additionalInfo == 20) {
            return ['value' => false, 'offset' => $offset];
        } elseif ($additionalInfo == 21) {
            return ['value' => true, 'offset' => $offset];
        } elseif ($additionalInfo == 22) {
            return ['value' => null, 'offset' => $offset];
        }
        
        throw new Exception('Valor especial CBOR no soportado: ' . $additionalInfo);
    }
    
    private function getLength($data, $offset, $additionalInfo) {
        if ($additionalInfo < 24) {
            return ['value' => $additionalInfo, 'offset' => $offset];
        } elseif ($additionalInfo == 24) {
            return ['value' => ord($data[$offset]), 'offset' => $offset + 1];
        } elseif ($additionalInfo == 25) {
            return ['value' => unpack('n', substr($data, $offset, 2))[1], 'offset' => $offset + 2];
        } elseif ($additionalInfo == 26) {
            return ['value' => unpack('N', substr($data, $offset, 4))[1], 'offset' => $offset + 4];
        } elseif ($additionalInfo == 27) {
            return ['value' => unpack('J', substr($data, $offset, 8))[1], 'offset' => $offset + 8];
        }
        
        throw new Exception('Longitud CBOR no válida');
    }
}