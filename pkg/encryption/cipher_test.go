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
	const token = "/CG8pcyYZdf7yLnTaCmM9sxZOo0zpDQ7a5W5Gq8AfcQ6aOJg5F3NRLgf+fSFXqg6Fug6IcmiPqO7jKyU61oWFdcC0l3rJ2zSFuBPhcwtLJ+dTTjayOVrqLkjfjEILBska+j+5iz3IuYACmpOFFhIHhfJwmDTsP5emtmmNnch9vFkwdLZSHFauWlAgDsWpziOZ+KslGBK4imYqAIiC2geXjQ8tQ0XeXgGRl3aZrpPDQXmgIRgjUWV0e1G//2ODC25Az03GSyks0BB94S+sAc0uUyUen5kD8THpxAL9/dx74KOo/qBXqrQxQLoBg5kmIbKuXhJLt/fseB0SUuczxN8T/o8jGR1RSu9wowPYmYsp0v341403u8RlDFZsP4tooSMOxWg6Wrz/ShnQZ7eO+PvG8+Bn9rv2a5cfc7cny03Gm4DJPG3sUv5jwmvTfk8VpF62upwi1K8bwnbAgfQ2/RMCyuVV9lufdCcu2x6CRwOku52krCEzgbSahEBJ3o769SK/Lep2sOtQTBmJi2NP40LWX61eVun1rmZVe8buS96tlhj4vco9B/rPtIB/uzI8Y6XCyJJzkt/jZ8uRzPUmbGpzrNg8MwIDFk2VarTW2BCoRJkJCICFjb76lQwJ3XB2URxu8wJr8t+u/jENegAEnSe+XLEzsbGO9ZXE3NTpGG8GoyrnB/bc6Y/fWtMAzMvz2026EBR3KLd4pQLUBobQFouLo04qYuKDaxBruSu5wNT6VzkTSz4iIXpekDyDpEJQ9xbSP7ETzXaJRyll6KD1v1HpHuZWliVgpM+ROaspoSpQrig6HNMUPfjROJBxoaamKJHEXvjTjsWfdaLugZRO50kXbKT8ckkipA+vtzSclE28zfk54qYcjwCffQfwbU+3tt63M+6MFeDPTxCxg1/8532SqBYg1jAOaeNPyYMKX7gNHv31iBezIkHFJxkPGo4l2cTkoJgO32fmzPUryOdY9BqCxjuGdPXlGP/2G7d16wUcrZfv5d3n6m1ZkoJuUa55m3/F2+tHo5JgHk0EVQqz2iq+HFdatNDjsZ947KmAGF0JmyZnlpMT7jWSYVpzS3/V9VFnH76vUn29Nqpbwp0me3O+QydUIq6xQ=="
	c, err := NewCipher([]byte(secret))
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
