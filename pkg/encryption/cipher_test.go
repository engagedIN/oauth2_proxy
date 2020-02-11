package encryption

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	const token = "my access token"
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	encoded, err := c.Encrypt(token)
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, token, encoded)
	assert.Equal(t, token, decoded)
}

func TestEncodeAndDecodeAccessTokenB64(t *testing.T) {
	const secretBase64 = "A3Xbr6fu6Al0HkgrP1ztjb-mYiwmxgNPP-XbNsz1WBk="
	const token = "my access token"

	secret, err := base64.URLEncoding.DecodeString(secretBase64)
	assert.Equal(t, nil, err)
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	encoded, err := c.Encrypt(token)
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, token, encoded)
	assert.Equal(t, token, decoded)
}

func TestDecrypt(t *testing.T) {
	const secret = "2dccd1ab3e03990aea77359831c85ca2"
	const token = "ZKyJ0OUddLqCUeYXu5GhFD3EUiad9zvCVAJjsKnBlycMptXTkquInyFfIapzQaq+aiFmxJ1gbF4sBxCtUGN04H2QTnPcwvDpIJK4X2pHXYJzVMqNIXGSfVgyvmb7nLoO5x6Up0TwW4QpsfEOMsji5Yb+AS+WKlDpCgxoGZ0oS3StLEjemdMNaRmwBFnrX3X8tlemFg/e87WIzlsxpBTN77PUE6myi1v9kJODbjosMuetb6SS9zs0o375+afaorTGWoIZ46jzFA2Esd5uzNd26O3K+BzjGh44+2bEedLgVfazqWKgVOaICTUGp/Tqn/tf83tGQ/C/OYnsgvWKPyQfj2Qn+eHsyKf4fdtI43+7m+L44S1F/MFUnZlNuOxsxDkeUGkPZQ1nzSna/F8lwUMEWmb+UZxVC4Ru8b/bjkFCz2hEtibvfQzzf5QwLK6ylse2fjMlih5L9nEP4HYE180O9MXGSCUaAGry4V0wYEZ8Vn3Q5A3nUarP4aMXdQ1K2edt3p87SN5sUg8/y/Nvdkof+RE9flulaRvfXgfXFsLL+aEPfsikm10d97jwl8yu8xJgtmvAsJ9slqRHiuEM/CxXNyxXmznUKBDztXMYIrv1WuA4LOW7GcdFyGUDe5i5uMUUxCImKSj2UP5pI6xGT8Z7eXBrRuyfjhnfAIySP9gucWUjnI7XkEP7C9qLak6XAN4qYg2CoMHMV8JePCwaRFM7neMlOJqpPWNoZQIagK5titlp0v9nJiK2byI6G3myL0S3Tu6Jpnc5kiy3LN2ULJKuQi6wpEHK0QFjuFO/PH7ym2WyHvccgNPJTHldhjubbadftjC5wfivAtHsoKhOfcMfI6hy4x4+ZehPLmaqeJZ11cMTr8lBsGWQuCDZg/5Szs4AEDLZdpcr8fN065DbXwTDHInzR7VIKEpYgVuose/RSnUsf4GX/yrQ2iueqR6zNyrkzCes4QPVMI0F4WGGpX99f7GskWY/OjtmPRb0BQebnH/QS2p94UZN/VbBQ2gCel/855Bz0vZh1docDLGWwATYRwO7IHfiQZ1TIgP+6oDnjlfJPI6lp6zYwd+NwSqYZ2TL+mFUA7Ds4rdeDaD9367u0FK40SLu5Lvpc1Yr7SnaZZTnsUVVFC+837MYYaZreuU3qAQfx3ZXPR+KwejsO/jRXmZZ3WrvLcrTwR5uodJyRrF+OJ7rU2KP61w1NennIdxzelIaSn1v2iUzRj5UAcmyhDoXNpuK8D4X0aiqgLobwAFxyS0vHYfYsrXs0M/IU0Z+w7/xsjIuCU7gNNBJ7AZyNMS8u7iOk+h6o8BMOw=="

	var s64 []byte
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		s64 = b
	} else {
		s64 = []byte(secret)
	}

	c, err := NewCipher([]byte(s64))
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	val, err := c.Decrypt(token)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	fmt.Println(val)
}
func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}
