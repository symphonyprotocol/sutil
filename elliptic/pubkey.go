package elliptic

import "crypto/ecdsa"
import "math/big"
import "fmt"
import "crypto/sha256"
import "golang.org/x/crypto/ripemd160"
// import b58 "../base58"
import b58 "github.com/symphonyprotocol/sutil/base58"


const LenPubKeyBytesCompressed   = 33
const LenPubKeyBytesUnCompressed = 65
const PubkeyCompressed   byte = 0x2
const PubkeyUncompressed byte = 0x4
const WALLET_ADDRESS_FLAG = 0x00
const CHECKSUM_LEN = 4

type PublicKey ecdsa.PublicKey

// 非压缩公钥成字节
func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, LenPubKeyBytesUnCompressed)
	b = append(b, PubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// 压缩公钥成字节 / 如果是奇数 结尾append 0x03 否则append 0x02
// 也就是说倒数第一位标识奇偶性 倒数第二位标识是否压缩
func (p *PublicKey) SerializeCompressed() []byte {
	b := make([]byte, 0, LenPubKeyBytesCompressed)
	format := PubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)

	return paddedAppend(32, b, p.X.Bytes())
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// 把public key 字节数组转化为 publickey ， 包含曲线，X， Y
func ParsePubKey(pubKeyBytes []byte,  curve *KoblitzCurve ) (key *PublicKey, err error) {
	pubkey := PublicKey{}
	pubkey.Curve = curve

	if len(pubKeyBytes) == 0 {
		return nil, fmt.Errorf("pubkey string is empty")
	}

	format := pubKeyBytes[0]
	
	// 最后一bit变0， 高位取反成1
	// 检查倒数第二位是否为1
	format &= ^byte(0x1)
	// 奇偶性
	ybit := (format & 0x1) == 0x1

	pubkeyLen := len(pubKeyBytes)

	if pubkeyLen == LenPubKeyBytesCompressed{
		// y^2 = x^3 + Curve.B
		if format != PubkeyCompressed{
			return nil, fmt.Errorf("invalid compressed format flag: %d", pubKeyBytes[0])
		}
		pubkey.X = new(big.Int).SetBytes(pubKeyBytes[1:33])
		pubkey.Y, err = decompressPoint(curve, pubkey.X, ybit)
		if err != nil {
			return nil, err
		}

	}else if pubkeyLen == LenPubKeyBytesUnCompressed{
		if format != PubkeyUncompressed{
			return nil, fmt.Errorf("invalid compressed format flag: %d", pubKeyBytes[0])
		}
		pubkey.X = new(big.Int).SetBytes(pubKeyBytes[1:33])
		pubkey.Y = new(big.Int).SetBytes(pubKeyBytes[33:])
	}

	// 保证X， Y 在曲线范围内
	if pubkey.X.Cmp(pubkey.Curve.Params().P) >= 0 {
		return nil, fmt.Errorf("pubkey X parameter is >= to P")
	}
	if pubkey.Y.Cmp(pubkey.Curve.Params().P) >= 0 {
		return nil, fmt.Errorf("pubkey Y parameter is >= to P")
	}
	// 保证点在曲线上
	if !pubkey.Curve.IsOnCurve(pubkey.X, pubkey.Y) {
		return nil, fmt.Errorf("pubkey isn't on secp256k1 curve")
	}

	return &pubkey, nil
}

// 已知椭圆 X 求 Y
func decompressPoint(curve *KoblitzCurve, x *big.Int, ybit bool) (*big.Int, error) {

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)
	x3.Mod(x3, curve.Params().P)

	// Now calculate sqrt mod p of x^3 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, curve.QPlus1Div4(), curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}

	// Check that y is a square root of x^3 + B.
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.Params().P)
	if y2.Cmp(x3) != 0 {
		return nil, fmt.Errorf("invalid square root")
	}

	// Verify that y-coord has expected parity.
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}
	return y, nil
}

func (p *PublicKey) ToAddress() (address string) {

	pub_bytes := p.SerializeUncompressed()

	// Perform SHA-256 hashing on the public key
	s := sha256.New()
	s.Reset()
	s.Write(pub_bytes)
	hash1 := s.Sum(nil)
	
	//  Perform RIPEMD-160 hashing 
	r := ripemd160.New()
	r.Reset()
	r.Write(hash1)
	hash2 := r.Sum(nil)
	address = base58CheckEncode(WALLET_ADDRESS_FLAG, hash2)
	return address
}

func base58CheckEncode(version uint8, bytes []byte) (res string){

	// Add version byte in front
	ver_bytes := append([]byte{version}, bytes...)
	
	// Perform SHA-256 hash
	s := sha256.New()
	s.Reset()
	s.Write(ver_bytes)
	hash1 := s.Sum(nil)

	// Perform SHA-256 hash
	s.Reset()
	s.Write(hash1)
	hash2 := s.Sum(nil)

	// Take the first checksum bytes of the second SHA-256 hash. This is the address checksum
	// Add the checksum bytes  at the end of vercode bytes
	checksum_bytes := append(ver_bytes, hash2[0:CHECKSUM_LEN]...)
	res = b58.B58encode(checksum_bytes)


	for _, v := range checksum_bytes {
		if v != 0 {
			break
		}
		res = "1" + res
	}

	return res
}

func (p *PublicKey) ToAddressCompressed() (address string) {

	pub_bytes := p.SerializeCompressed()

	// Perform SHA-256 hashing on the public key
	s := sha256.New()
	s.Reset()
	s.Write(pub_bytes)
	hash1 := s.Sum(nil)
	
	//  Perform RIPEMD-160 hashing 
	r := ripemd160.New()
	r.Reset()
	r.Write(hash1)
	hash2 := r.Sum(nil)
	address = base58CheckEncode(WALLET_ADDRESS_FLAG, hash2)
	return address
}