package auth

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateDigest calculate challange hash from WWWAuthenticate header
func GenerateDigest(username string, realm string, password string, uri string, nonce string, cnonce string, nc string, qop string, method string) string {
	a1hash := fmt.Sprintf("%x", md5.Sum([]byte(username+":"+realm+":"+password)))
	a2hash := fmt.Sprintf("%x", md5.Sum([]byte(method+":"+uri)))
	var a3hash string
	if qop == "" {
		// compatibility with RFC 2069
		a3hash = fmt.Sprintf("%x", md5.Sum([]byte(a1hash+":"+nonce+":"+a2hash)))
	} else {
		a3hash = fmt.Sprintf("%x", md5.Sum([]byte(a1hash+":"+nonce+":"+nc+":"+cnonce+":"+qop+":"+a2hash)))
	}
	return a3hash
}

func GenerateNonce() string {
	b := make([]byte, 10)
	_, err := rand.Read(b)
	if err != nil {
		panic("could not read random: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// GetDigestString generate Digest authentication string for adding to response in Authorization header
func GetDigestString(authenticate string, username string, password string, uri string, method string) string {
	authHeader := SipAuth{}
	GetSipAuth(authenticate, &authHeader)
	authHeader.Nc = "00000001"
	authHeader.Cnonce = GenerateNonce()
	authHeader.Uri = uri
	authHeader.Username = username
	authHeader.Response = GenerateDigest(
		username,
		authHeader.Realm,
		password,
		authHeader.Uri,
		authHeader.Nonce,
		authHeader.Cnonce,
		authHeader.Nc,
		authHeader.Qop,
		method)

	return authHeader.String()
}
