package cryptography

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// The protection profile the contract pins for key material: a DER PKCS#8
// EncryptedPrivateKeyInfo under PBES2, with PBKDF2-HMAC-SHA256 and
// AES-256-CBC.
const (
	maxEnvelopeLength = 64 * 1024
	minSaltLength     = 16
	minIterations     = 100_000
	maxIterations     = 10_000_000
	aes256KeyLength   = 32

	// What ProtectKeyMaterial writes: the salt the profile requires at
	// least and the iterations the contract recommends.
	protectSaltLength = 16
	protectIterations = 600_000
)

var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// The rules an envelope can break, in the words of the contract's own
// validation.
var (
	errEnvelopeTooLarge   = errors.New("encryptedPrivateKeyInfo must not exceed 65536 bytes")
	errEnvelopeMalformed  = errors.New("encryptedPrivateKeyInfo must contain a DER-encoded PKCS#8 EncryptedPrivateKeyInfo")
	errEnvelopeScheme     = errors.New("material must be protected with PBES2 using PBKDF2-HMAC-SHA256 and AES-256-CBC")
	errEnvelopeParameters = errors.New("material must use a salt of at least 16 bytes, between 100000 and 10000000 iterations, a 32-byte derived key when the key length is present, and a 16-byte initialisation vector")
	errEnvelopeBlocks     = errors.New("material must carry a non-empty ciphertext of whole 16-byte AES blocks")

	// An envelope that is not standard padded base64 is an unreadable body.
	errMaterialNotBase64 = shared.BadRequest("BAD_REQUEST", "material.encryptedPrivateKeyInfo must be base64")
)

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivation pkix.AlgorithmIdentifier
	Encryption    pkix.AlgorithmIdentifier
}

// pbkdf2Params leaves the prf optional so an envelope that relies on the
// SHA-1 default reads as outside the profile rather than as malformed.
type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// privateKeyInfo is RFC 5958's OneAsymmetricKey, whose optional attributes
// and public key are the only fields that may follow the private key.
type privateKeyInfo struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue  `asn1:"optional,tag:0"`
	PublicKey  asn1.BitString `asn1:"optional,tag:1"`
}

// envelope is the protection an envelope within the profile states.
type envelope struct {
	salt       []byte
	iterations int
	iv         []byte
	ciphertext []byte
}

// OpenKeyMaterial decrypts protected key material and returns the DER PKCS#8
// PrivateKeyInfo inside it. Material that is not base64 renders 400
// BAD_REQUEST and material outside the pinned profile 422 VALIDATION_FAILED,
// as the import handler already refuses both. A passphrase that does not open
// the material, or plaintext that is not a PrivateKeyInfo, returns
// ErrKeyDecryptionFailed: the profile carries no integrity protection, so the
// two cannot be told apart.
//
// The passphrase is used as its UTF-8 bytes, exactly as supplied. The
// returned slice holds the key in the clear: clear it once the key is
// stored, and never log it or the passphrase.
func OpenKeyMaterial(material mdl.EncryptedKeyMaterialV2Dto, passphrase string) ([]byte, error) {
	env, err := readEnvelope(material)
	if err != nil {
		return nil, err
	}
	return env.open(passphrase)
}

// ProtectKeyMaterial protects a DER PKCS#8 PrivateKeyInfo under passphrase in
// the pinned profile, for an export response: a fresh 16-byte salt and
// initialisation vector, 600000 iterations, and no key length, as OpenSSL
// writes it. The passphrase is used as its UTF-8 bytes, exactly as supplied,
// so the envelope opens in external tools.
func ProtectKeyMaterial(privateKeyInfoDER []byte, passphrase string) (mdl.EncryptedKeyMaterialV2Dto, error) {
	if passphrase == "" {
		return mdl.EncryptedKeyMaterialV2Dto{}, errors.New("cryptography: passphrase must not be empty")
	}
	if !isPrivateKeyInfo(privateKeyInfoDER) {
		return mdl.EncryptedKeyMaterialV2Dto{}, errors.New("cryptography: key material must be a DER PKCS#8 PrivateKeyInfo")
	}
	salt := make([]byte, protectSaltLength)
	iv := make([]byte, aes.BlockSize)
	rand.Read(salt)
	rand.Read(iv)
	block, err := blockCipher(passphrase, salt, protectIterations)
	if err != nil {
		return mdl.EncryptedKeyMaterialV2Dto{}, err
	}
	padded := pad(privateKeyInfoDER)
	defer clear(padded)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	der, err := marshalEnvelope(salt, iv, ciphertext, protectIterations)
	if err != nil {
		return mdl.EncryptedKeyMaterialV2Dto{}, err
	}
	if len(der) > maxEnvelopeLength {
		return mdl.EncryptedKeyMaterialV2Dto{}, errors.New("cryptography: key material is too large for the protection profile")
	}
	return mdl.EncryptedKeyMaterialV2Dto{EncryptedPrivateKeyInfo: base64.StdEncoding.EncodeToString(der)}, nil
}

// readEnvelope decodes request material and checks it against the profile,
// with the errors a request is refused with.
func readEnvelope(material mdl.EncryptedKeyMaterialV2Dto) (*envelope, error) {
	der, err := base64.StdEncoding.DecodeString(material.EncryptedPrivateKeyInfo)
	if err != nil {
		return nil, errMaterialNotBase64
	}
	env, err := parseEnvelope(der)
	if err != nil {
		return nil, errValidationFailed(err.Error())
	}
	return env, nil
}

// parseEnvelope checks der against the profile. The object identifiers name
// the scheme; once they are the pinned ones, the parameters must be the DER
// of the pinned structures.
func parseEnvelope(der []byte) (*envelope, error) {
	if len(der) > maxEnvelopeLength {
		return nil, errEnvelopeTooLarge
	}
	outer, ok := decodeCanonical[encryptedPrivateKeyInfo](der)
	if !ok {
		return nil, errEnvelopeMalformed
	}
	env, err := parsePBES2(outer.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(outer.EncryptedData) == 0 || len(outer.EncryptedData)%aes.BlockSize != 0 {
		return nil, errEnvelopeBlocks
	}
	env.ciphertext = outer.EncryptedData
	return env, nil
}

func parsePBES2(algorithm pkix.AlgorithmIdentifier) (*envelope, error) {
	if !algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errEnvelopeScheme
	}
	params, ok := decodeCanonical[pbes2Params](algorithm.Parameters.FullBytes)
	if !ok {
		return nil, errEnvelopeMalformed
	}
	if !params.KeyDerivation.Algorithm.Equal(oidPBKDF2) || !params.Encryption.Algorithm.Equal(oidAES256CBC) {
		return nil, errEnvelopeScheme
	}
	kdf, ok := decodeCanonical[pbkdf2Params](params.KeyDerivation.Parameters.FullBytes)
	if !ok {
		return nil, errEnvelopeMalformed
	}
	if !kdf.PRF.Algorithm.Equal(oidHMACWithSHA256) || !bytes.Equal(kdf.PRF.Parameters.FullBytes, asn1.NullBytes) {
		return nil, errEnvelopeScheme
	}
	iv, ok := decodeCanonical[[]byte](params.Encryption.Parameters.FullBytes)
	if !ok {
		return nil, errEnvelopeMalformed
	}
	if !withinProfile(kdf, iv) {
		return nil, errEnvelopeParameters
	}
	return &envelope{salt: kdf.Salt, iterations: kdf.Iterations, iv: iv}, nil
}

func withinProfile(kdf pbkdf2Params, iv []byte) bool {
	return len(kdf.Salt) >= minSaltLength &&
		kdf.Iterations >= minIterations && kdf.Iterations <= maxIterations &&
		(kdf.KeyLength == 0 || kdf.KeyLength == aes256KeyLength) &&
		len(iv) == aes.BlockSize
}

// decodeCanonical decodes exactly one DER value and reports whether encoding
// it again gives back the same bytes, which is what makes an encoding
// canonical.
func decodeCanonical[T any](der []byte) (T, bool) {
	var value T
	rest, err := asn1.Unmarshal(der, &value)
	if err != nil || len(rest) != 0 {
		return value, false
	}
	again, err := asn1.Marshal(value)
	return value, err == nil && bytes.Equal(again, der)
}

func (e *envelope) open(passphrase string) ([]byte, error) {
	block, err := blockCipher(passphrase, e.salt, e.iterations)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(e.ciphertext))
	cipher.NewCBCDecrypter(block, e.iv).CryptBlocks(plaintext, e.ciphertext)
	key, ok := unpad(plaintext)
	if !ok || !isPrivateKeyInfo(key) {
		clear(plaintext)
		return nil, ErrKeyDecryptionFailed
	}
	return key, nil
}

// blockCipher derives the AES-256 key from passphrase and clears it once the
// cipher holds it.
func blockCipher(passphrase string, salt []byte, iterations int) (cipher.Block, error) {
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, aes256KeyLength)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return aes.NewCipher(key)
}

func pad(data []byte) []byte {
	n := aes.BlockSize - len(data)%aes.BlockSize
	padded := make([]byte, len(data)+n)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}

func unpad(data []byte) ([]byte, bool) {
	n := int(data[len(data)-1])
	if n == 0 || n > aes.BlockSize {
		return nil, false
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, false
		}
	}
	return data[:len(data)-n], true
}

// isPrivateKeyInfo reports whether der is exactly one DER PKCS#8
// PrivateKeyInfo (RFC 5958 OneAsymmetricKey, version 0 or 1) with a private
// key value and nothing but its optional fields after it.
func isPrivateKeyInfo(der []byte) bool {
	info, ok := decodeCanonical[privateKeyInfo](der)
	return ok && (info.Version == 0 || info.Version == 1) &&
		len(info.Algorithm.Algorithm) > 0 && len(info.PrivateKey) > 0
}

func marshalEnvelope(salt, iv, ciphertext []byte, iterations int) ([]byte, error) {
	kdf, err := asn1.Marshal(pbkdf2Params{
		Salt:       salt,
		Iterations: iterations,
		PRF:        pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return nil, err
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	scheme, err := asn1.Marshal(pbes2Params{
		KeyDerivation: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		Encryption:    pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: scheme}},
		EncryptedData: ciphertext,
	})
}
