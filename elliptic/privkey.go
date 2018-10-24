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