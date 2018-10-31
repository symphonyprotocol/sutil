package elliptic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"bytes"
	// b38 "../bip38"
	b38 "github.com/symphonyprotocol/sutil/bip38"
	"golang.org/x/crypto/scrypt"
	// b58 "../base58"
	b58 "github.com/symphonyprotocol/sutil/base58"
	"fmt"
)
type PrivateKey ecdsa.PrivateKey
const WIF_VERSION = 0x80
const WIF_COMPRESSED_FLAG = 0x01

// 把一个字节数组转化为私钥以及对应公钥
func PrivKeyFromBytes(curve elliptic.Curve, pk []byte) (*PrivateKey, *PublicKey) {
	x, y := curve.ScalarBaseMult(pk)

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(pk),
	}
	return (*PrivateKey)(priv), (*PublicKey)(&priv.PublicKey)
}

func (p *PrivateKey) PrivatekeyToBytes() ([] byte){
	pri_bytes := p.D.Bytes()
	padding_pri_bytes := append(bytes.Repeat([]byte{0x00}, 32-len(pri_bytes)), pri_bytes...)
	return padding_pri_bytes
}

//convert private key to wallet import format string
func (p *PrivateKey) ToWIF() (wif string){
	pri_bytes := p.PrivatekeyToBytes()
	wif = base58CheckEncode(WIF_VERSION, pri_bytes)
	return wif
}

//convert private key to wallet import format string with public key compressed flag
func (p *PrivateKey) ToWIFCompressed() (wif string){
	pri_bytes := p.PrivatekeyToBytes()
	// to tell wallet use compressed public keys
	pri_bytes = append(pri_bytes, []byte{WIF_COMPRESSED_FLAG}...)
	wif = base58CheckEncode(WIF_VERSION, pri_bytes)
	return wif
}

func (p *PrivateKey) ToBip38Encrypt(passphrase string) string{
	bip38 := new(b38.BIP38Key)
	priv_bytes := p.PrivatekeyToBytes()
	pub_key := (*PublicKey)(&p.PublicKey)
	pub_bytes := pub_key.SerializeUncompressed()
	ah := b38.DoubleHash256(pub_bytes)[:4]
	dh, _ := scrypt.Key([]byte(passphrase), ah, 16384, 8, 8, 64)

	bip38.Flag = byte(0xC0)
	copy(bip38.Hash[:], ah)
	copy(bip38.Data[:], b38.Encrypt(priv_bytes, dh[:32], dh[32:]))
	return bip38.String()
}

func  Bip38Decrypt(bipstr string, passphrase string) (string) {
	b, err := b58.B58decode(bipstr)
	if err != nil {
		// return nil, err
	}
	bip38 := new(b38.BIP38Key)
	bip38.Flag = b[2]
	copy(bip38.Hash[:], b[3:7])
	copy(bip38.Data[:], b[7:])

	dh, _ := scrypt.Key([]byte(passphrase), bip38.Hash[:], 16384, 8, 8, 64)
	p := b38.Decrypt(bip38.Data[:], dh[:32], dh[32:])
	priv_key_str := byteToString(p)
	return priv_key_str
}

func byteToString(b []byte) (s string) {
	s = ""
	for i := 0; i < len(b); i++ {
		s += fmt.Sprintf("%02X", b[i])
	}
	return s
}

// ToECDSA returns the private key as a *ecdsa.PrivateKey.
func (p *PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return (*ecdsa.PrivateKey)(p)
}

// Sign generates an ECDSA signature for the provided hash (which should be the result
// of hashing a larger message) using the private key. Produced signature
// is deterministic (same message and same key yield the same signature) and canonical
// in accordance with RFC6979 and BIP0062.
func (p *PrivateKey) Sign(hash []byte) (*Signature, error) {
	return signRFC6979(p, hash)
}


// checks that string wif is a valid Wallet Import Format or Wallet Import Format Compressed string.
// return the private key bytes
func LoadWIF(wif string) (pribytes []byte, err error) {

	ver, priv_bytes, err := b58checkdecode(wif)
	if err != nil {
		return priv_bytes, err
	}

	/* Check that the version byte is 0x80 */
	if ver != WIF_VERSION {
		return priv_bytes, fmt.Errorf("Invalid WIF version 0x%02x, expected 0x80.", ver)
	}

	/* Check that private key bytes length is 32 or 33 */
	if len(priv_bytes) != 32 && len(priv_bytes) != 33 {
		return priv_bytes, fmt.Errorf("Invalid private key bytes length %d, expected 32 or 33.", len(priv_bytes))
	}

	/* If the private key bytes length is 33, check that suffix byte is 0x01 (for compression) */
	if len(priv_bytes) == 33 && priv_bytes[len(priv_bytes)-1] != WIF_COMPRESSED_FLAG {
		return priv_bytes, fmt.Errorf("Invalid private key bytes, unknown suffix byte 0x%02x.", priv_bytes[len(priv_bytes)-1])
	}

	if len(priv_bytes) == 33 {
		if priv_bytes[len(priv_bytes)-1] != WIF_COMPRESSED_FLAG {
			return priv_bytes, fmt.Errorf("Invalid private key, unknown suffix byte 0x%02x.", priv_bytes[len(priv_bytes)-1])
		}
		priv_bytes = priv_bytes[0:32]
	}

	return priv_bytes, nil
}