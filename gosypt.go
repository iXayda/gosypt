package gosypt

import (
	"errors"
	"strings"

	"github.com/ixayda/gosypt/internal/pkg"
	"github.com/ixayda/gosypt/pkg/algorithm"
	"github.com/ixayda/gosypt/pkg/crypt"
)

var New = getResolver()

type resolver struct {
	verbose bool

	prefix    string
	suffix    string
	algorithm crypt.Algorithm

	stringOutputType string

	providerName      string
	providerClassName string

	ivGeneratorClassName   string
	saltGeneratorClassName string
}

func (r *resolver) Prefix(prefix string) {
	r.prefix = prefix
}

func (r *resolver) Suffix(suffix string) {
	r.suffix = suffix
}

func (r *resolver) Algorithm(algorithm crypt.Algorithm) {
	r.algorithm = algorithm
}

func getResolver() *resolver {
	return &resolver{
		verbose:   false,
		prefix:    "ENC~[",
		suffix:    "]",
		algorithm: algorithm.PBEWITHMD5ANDDES,

		stringOutputType:       "base64",
		providerName:           "gosypt",
		providerClassName:      "ixayda/gosypt",
		ivGeneratorClassName:   "RandomIvGenerator",
		saltGeneratorClassName: "RandomSaltGenerator",
	}
}

func (r *resolver) Encrypt(plaintext string, passphrase string) (string, error) {
	ciphertext, err := pkg.JasyptEncrypt(plaintext, passphrase, r.algorithm)

	return r.prefix + ciphertext + r.suffix, err
}

func (r *resolver) Decrypt(ciphertext string, passphrase string) (string, error) {
	if strings.HasPrefix(ciphertext, r.prefix) && strings.HasSuffix(ciphertext, r.suffix) {
		s := len(r.prefix)
		e := len(ciphertext) - len(r.suffix)
		decrypted, err := pkg.JasyptDecrypt(ciphertext[s:e], passphrase, r.algorithm)
		return decrypted, err
	}
	return "", errors.New("无效数据")
}
