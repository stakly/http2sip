package auth

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// SipAuth SIP Authorization header
type SipAuth struct {
	Username  string
	Realm     string
	Nonce     string
	Uri       string
	Response  string
	Cnonce    string
	Qop       string
	Algorithm string
	Nc        string
}

var (
	nonquotted = []string{"qop", "nc", "algorithm"}
)

func capitalize(str string) string {
	runes := []rune(str)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// returns valid string for SIP Authorization header (Digest)
func (sa *SipAuth) String() string {
	var values []string
	v := reflect.Indirect(reflect.ValueOf(&sa)).Elem()

	if v.Kind() == reflect.Struct {
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).String() != "" {
				name := strings.ToLower(v.Type().Field(i).Name)
				value := v.Field(i).String()
				if !slices.Contains(nonquotted, name) {
					value = strconv.Quote(value)
				}
				values = append(values, fmt.Sprintf("%s=%s", name, value))
			}
		}
	}
	return "Digest " + strings.Join(values, ",")
}

// GetSipAuth populate sipAuth struct from SIP WWWAuthenticate header string
func GetSipAuth(authenticate string, sipAuth *SipAuth) {
	authenticate = strings.TrimSpace(authenticate)
	params := strings.Split(authenticate[7:], ",") // skip Digest string
	sipAuthStruct := reflect.Indirect(reflect.ValueOf(&sipAuth)).Elem()
	if sipAuthStruct.Kind() == reflect.Struct {
		for _, param := range params {
			kv := strings.Split(strings.TrimSpace(param), "=")
			key := capitalize(kv[0])
			value := kv[1]
			if kv[1][0] == '"' {
				value, _ = strconv.Unquote(kv[1])
			}
			sipAuthStruct.FieldByName(key).SetString(value)
		}
	}
}
