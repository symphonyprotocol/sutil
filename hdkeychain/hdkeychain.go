// ----------------------------------------------
// 路径规则
// m/0	主私钥(m)的第一个(0)子私钥
// m/0/0	第一个子私钥的第一个孙私钥(m/0)
// m/0'/0	第一个强化的子私钥(m/0')的第一个正常的孙私钥
// m/1/0	第二个子私钥(m/1)的第一个孙私钥
// M/23/17/0	第24个子公钥的第18个孙公钥的第一个曾孙公钥
// ----------------------------------------------

package hdkeychain

import "fmt"
import "crypto/hmac"
import "crypto/sha512"
import "math/big"
// import "crypto/ecdsa"
// import "crypto/elliptic"
import ec "../elliptic"
import "encoding/binary"

const MinSeedsBytes = 128 / 8  			// 最短种子
const MaxSeedsBytes = 512 / 8  			// 最长种子
const HardenedKeyStart = 0x80000000     // 硬化子密钥 起始
const MaxUint8  = 1<<8 - 1 				// 8位无符号数字最大值

var HDPrivateKeyID = [4]byte{0x04, 0x88, 0xad, 0xe4}  // starts with xprv
var HDPublicKeyID = [4]byte{0x04, 0x88, 0xb2, 0x1e}   // starts with xpub
var MasterKey = []byte("symphony seed")				  // Master key 标识码

var(
	ErrorDeriveBeyondMaxDepth = fmt.Errorf("cannot derive a key with path more than 255")
	ErrorDeriveHardFromPublic = fmt.Errorf("cannot derive a hardened key from a public key")
	ErrorInvalidChild = fmt.Errorf("the extended key at this index is invalid")
	ErrorNotPrivExtKey = fmt.Errorf("can not create private keys from a public extended key")
)

type ExtendedKey struct {
	key       []byte  // 私钥
	pubKey    []byte  // 公钥
	chainCode []byte  // 链码
	depth     uint8   // 深度
	parentFP  []byte  // ?
	childNum  uint32  // 后代Index
	version   []byte  // 版本
	isPrivate bool    // 是否是私钥
}

func NewExtendedKey(version, key, chainCode, parentFP []byte, depth uint8, childNum uint32, isPrivate bool) *ExtendedKey {
	return &ExtendedKey{
		key:       key,			
		chainCode: chainCode,	
		depth:     depth,
		parentFP:  parentFP,
		childNum:  childNum,
		version:   version,
		isPrivate: isPrivate,
	}
}

func NewMaster(seed []byte) (*ExtendedKey, error){
	if len(seed) < MinSeedsBytes || len(seed) > MaxSeedsBytes{
		return nil, fmt.Errorf("invalid seeds length")
	}

	hmac512 := hmac.New(sha512.New, MasterKey)
	hmac512.Write(seed)
	hashedSeed := hmac512.Sum(nil)

	secretKey := hashedSeed[:len(hashedSeed)/2]
	chainCode := hashedSeed[len(hashedSeed)/2:]

	secretKeyNum := new(big.Int).SetBytes(secretKey)
	if secretKeyNum.Sign() == 0{
		return nil, fmt.Errorf("invalid seeds")
	}

	parentFP := []byte{0x00, 0x00, 0x00, 0x00}

	extendedKey := NewExtendedKey(HDPrivateKeyID[:], secretKey, chainCode, parentFP, 0, 0, true)
	return extendedKey, nil
}

// 1) Private extended key -> Hardened child private extended key
// 2) Private extended key -> Non-hardened child private extended key
// 3) Public extended key -> Non-hardened child public extended key
// 4) Public extended key -> Hardened child public extended key (INVALID!)

func (k *ExtendedKey) Child(idx uint32) (*ExtendedKey, error){
	if k.depth > MaxUint8 {
		return nil, ErrorDeriveBeyondMaxDepth
	}

	// 硬化衍生不能从公钥衍生, case #4
	isHardened := idx >= HardenedKeyStart
	if !k.isPrivate && isHardened {
		return nil, ErrorDeriveHardFromPublic
	}

	// For hardened children:
	//   0x00 || ser256(parentKey) || ser32(i)
	//
	// For normal children:
	//   serP(parentPubKey) || ser32(i)

	keyLen := 1 + 32 + 4
	data := make([]byte, keyLen+4)
	if isHardened {
		// case #1, 硬化需要私钥
		copy(data[1:], k.key)

	}else{
		// case #2 or #3, 非硬化使用公钥
		copy(data, k.pubKeyBytes())
	}

	binary.BigEndian.PutUint32(data[keyLen:], idx)
	hmac512 := hmac.New(sha512.New, k.chainCode)
	hmac512.Write(data)
	lr := hmac512.Sum(nil)

	left := lr[:len(lr)/2]
	childChainCode := lr[len(lr)/2:]

	leftNum := new(big.Int).SetBytes(left)
	if leftNum.Cmp(ec.S256().N) >= 0 || leftNum.Sign() == 0 {
		return nil, ErrorInvalidChild
	}

	var isPrivate bool
	var childKey []byte

	if k.isPrivate{
		// case #1 or #2 
		keyNum := new(big.Int).SetBytes(k.key)
		leftNum.Add(leftNum, keyNum)
		// 保证 私钥值不会超过椭圆曲线N值
		leftNum.Mod(leftNum, ec.S256().N)
		childKey = leftNum.Bytes()
		isPrivate = true
	}else{
		// case #3
		curve := ec.S256()
		ilx, ily := curve.ScalarBaseMult(left)
		if ilx.Sign() == 0 || ily.Sign() == 0 {
			return nil, ErrorInvalidChild
		}
		pubKey, err := ec.ParsePubKey(k.key, ec.S256())
		if err != nil {
			return nil, err
		}
		// 把中间公钥加到 父公钥上，推导出子公钥
		childX, childY := ec.S256().Add(ilx, ily, pubKey.X, pubKey.Y)
		pk := ec.PublicKey{Curve: ec.S256(), X: childX, Y: childY}
		childKey = pk.SerializeCompressed()
	}
	// The fingerprint of the parent for the derived child
	parentFP := ec.Hash160(k.pubKeyBytes())[:4]
	extKey := NewExtendedKey(k.version, childKey, childChainCode, parentFP, k.depth + 1, idx, isPrivate)
	return extKey, nil
}

//扩展秘钥导出为压缩公钥字节组
func (k *ExtendedKey) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.isPrivate {
		return k.key
	}

	// This is a private extended key
	// 使用椭圆曲线算法生成公钥
	if len(k.pubKey) == 0 {
		curve := ec.S256()
		pkx, pky := curve.ScalarBaseMult(k.key)
		pubKey := ec.PublicKey{
			Curve: curve,
			X: pkx,
			Y: pky,
		}
		// pubKey := PublicKey{Curve: btcec.S256(), X: pkx, Y: pky}
		k.pubKey = pubKey.SerializeCompressed()
	}


	return k.pubKey
}

//扩展秘钥导出为椭圆曲线私钥
func (k *ExtendedKey) ECPrivKey() (*ec.PrivateKey, error) {
	if !k.isPrivate {
		return nil, ErrorNotPrivExtKey
	}

	privKey, _ := ec.PrivKeyFromBytes(ec.S256(), k.key)
	return privKey, nil
}

// 扩展秘钥导出为椭圆曲线公钥
func (k *ExtendedKey) ECPubKey() (*ec.PublicKey, error) {
	return ec.ParsePubKey(k.pubKeyBytes(), ec.S256())
}

func (k *ExtendedKey) Neuter() (*ExtendedKey, error) {
	// Already an extended public key.
	if !k.isPrivate {
		return k, nil
	}


	// Convert it to an extended public key.  The key for the new extended
	// key will simply be the pubkey of the current extended private key.
	//
	// This is the function N((k,c)) -> (K, c) from [BIP32].
	return NewExtendedKey(HDPublicKeyID[:], k.pubKeyBytes(), k.chainCode, k.parentFP,
		k.depth, k.childNum, false), nil
}