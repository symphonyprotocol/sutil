package bip38

// import b58 "../base58"
import b58 "github.com/symphonyprotocol/sutil/base58"
import "crypto/aes"
import "crypto/sha256"

type BIP38Key struct {
	Flag byte
	Hash [4]byte
	Data [32]byte
}
func (bip BIP38Key) String() string {
	return b58.B58encode(bip.Bytes())
}
func (bip BIP38Key) Bytes() []byte {
	dst := make([]byte, 39)

	dst[0] = byte(0x01)
	dst[1] = byte(0x42)
	dst[2] = bip.Flag

	copy(dst[3:], bip.Hash[:])
	copy(dst[7:], bip.Data[:])

	return dst
}
func Encrypt(pk, dh1, dh2 []byte) (dst []byte) {
	c, _ := aes.NewCipher(dh2)

	for i, _ := range dh1 {
		dh1[i] ^= pk[i]
	}

	dst = make([]byte, 48)
	c.Encrypt(dst, dh1[:16])
	c.Encrypt(dst[16:], dh1[16:])
	dst = dst[:32]

	return
}
func Decrypt(src, dh1, dh2 []byte) (dst []byte) {
	c, _ := aes.NewCipher(dh2)

	dst = make([]byte, 48)
	c.Decrypt(dst, src[:16])
	c.Decrypt(dst[16:], src[16:])
	dst = dst[:32]

	for i := range dst {
		dst[i] ^= dh1[i]
	}

	return
}
func DoubleHash256(in []byte) []byte {
	s1 := sha256.New()
	s2 := sha256.New()

	s1.Write(in)
	s2.Write(s1.Sum(nil))

	return s2.Sum(nil)
}