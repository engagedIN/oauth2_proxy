package encryption

import (
	"encoding/base64"
	"log"
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
	//const secret = "2dccd1ab3e03990aea77359831c85ca2"
	const secret = "NDUcxPS8US0xnLu67i87yFuycHTP32uG"
	const token = "WN/Jx7m3ZMk56hLxShgeKS0C5PXbrEt//IO+/pXWBCVh8UEa0rh+bBQhIImlAcLYZ7tkEorqZMuHNS6AHD7nZAENtrZMdc5KjNnC3g43eJslOoXYtBNaJEiRxpL56Ts1Z7taP7IlPCKNpICZWkwe6K3zF0lGIvfFHQ2JT9vheH6WSnQY3UOoevmqLIT24IQekcZCz1ppGIOe/IHLOPCL13UJj9dubVD6/wVW7Fn5L1c5reRk8Sk1wd2v4emIq/JSajXNYQ+vS7Hpn6GkPwvefsX6kmxQf8Pnt39Ah1g3XKz+ulYtyjFfp0bEgoAbdOLVBn6MXpdtR0TSM9xLeJauvjLPbPyXKvAohGr8r8ejouL+eD2XbQHlQV5AMf0vvU24I2atVC8aMbk0VBvF3j/p3an/6uq4a9qOKb7cEnLxyVlITgRvH+fcwrIICThYbgkrFOCABi52Vt7d2QnK88cGEc1p3KZeQD3n2jJOJ0hpYfuMsHvZq09q+Fo/2dtujE6sEEOkjOxJnecDgIUMtAsDnNwxgERbiavTDKV1yYD5lkL1/IVTQZmq376Jz9Ij409KkDL7GFmJvNwFWVijSJ4VKHFjc8aJbF4eDgvyipUaJquk6kNS6Rim//jA26tlnv8jmfg0KHG9CFKNqAvUKpCZr62za3auUfiTikPkAv7BCUbx8mVER8RvJaoPGTeTnmeGMVy7hc2/JcAdKZxQAETFWVg22mngY3GdyFwZaZ/MnlORGGaAeyz6cd3AroHZvZ6RueDN1CtnEnn5Wzx6a+XRA4L241BJtLfMZczOc6yoPIkCdi9LtZPZ+Mv5g64ERpMRsX99a8EUaccZdARQUHBAQBY5liUYLb23YNm1afa8Kdepud5RMBA6+GqL/RXfIGlS2fQCX+45sc6ZSP/R+sWan3B0dlW/fRkY80ZoGJ1fCDBzjcQBEK8VnaEaeo6snF+X3RxghaxHPT23sQh7G14DTJ5g9QuTnKA1r0YD2rqLxDByR3e1efpbgFcR/TBzhYQ7PFxJ5Y8aNCq++DqVbfNi+FUhZf/4XA60T469cP0ERG2mz18PnTv4ApNbAHH+9B+WvyOXfRQJtAe6FnCOdLC2MQSQOu8GYe2MCXiUg2HSdlQmf1ftpgxVLWu7biZ+ZzFBux3PG3ZnO6ommC3gHstwG/rrpVGhu04j0YuJrsqTdv1aOJY/q9TgNnxhjS++QBaTzIRbC4wcAeq13GDGl7iN1mftu7waJzFK4supN7PQq8SGoeKP52NSgLFs8ximFg8ueWMkBg6COe5fT+JQ/vrMWsY9KkuXE0vhG/oTzQ=="
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
	log.Println(val)
}
