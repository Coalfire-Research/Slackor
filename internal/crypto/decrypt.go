package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"github.com/Coalfire-Research/Slackor/internal/config"
)

func PKCS5UnPadding(origData []byte) []byte { //Used for Crypto
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func DecryptFile(crypted []byte) (string, error) { // Decrypt a file (currently unused)
	decodeData := []byte(crypted)
	block, err := aes.NewCipher(config.CipherKeyBytes)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, config.CipherIV)
	origData := make([]byte, len(decodeData))
	blockMode.CryptBlocks(origData, decodeData)
	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}

func Decrypt(crypted string) (string, error) { // decrypt a string
	decodeData, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(config.CipherKeyBytes)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, config.CipherIV)
	origData := make([]byte, len(decodeData))
	blockMode.CryptBlocks(origData, decodeData)
	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}
