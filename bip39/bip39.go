package bip39
import "math/big"
import "crypto/sha256"
import "fmt"
import "encoding/binary"
import "crypto/rand"
import "strings"
import "golang.org/x/crypto/pbkdf2"
import "crypto/sha512"


var (
	last11BitsMask = big.NewInt(2047)
	rightShift11BitsDivider = big.NewInt(2048)

	wordList []string
	wordMap map[string]int
)

func SetWordList(list []string) {
	wordList = list
	wordMap = map[string]int{}
	for i, v := range wordList {
		wordMap[v] = i
	}
}

func padByteSlice(slice []byte, length int) []byte {
	offset := length - len(slice)
	if offset <= 0 {
		return slice
	}
	newSlice := make([]byte, length)
	copy(newSlice[offset:], slice)
	return newSlice
}

func computeChecksum(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func addChecksum(data []byte) []byte {
	hash := computeChecksum(data)
	firstChecksumByte := hash[0]
	//校验码长度
	checksumBitLength := uint(len(data) / 4)

	dataBigInt := new(big.Int).SetBytes(data)

	for i := uint(0); i < checksumBitLength; i++ {
		//左移一位
		dataBigInt.Mul(dataBigInt, big.NewInt(2))
		//如果校验码此位是1 尾加校验码1
		if uint8(firstChecksumByte&(1<<(7-i))) > 0 {
			dataBigInt.Or(dataBigInt, big.NewInt(1))
		}
	}

	res := dataBigInt.Bytes()
	return res
}

func NewMnemonic(size int) (string, error) {
	entropy, e := newEntropy(size)
	if e != nil{
		return "", e
	}
	//熵长度
	var entropyBitLength = len(entropy) * 8
	//校验位
	var checksumBitLength = entropyBitLength / 32
	//词位数长度
	var sentenceLength = (entropyBitLength + checksumBitLength) / 11

	err := validateEntropyBitSize(entropyBitLength)
	if err != nil {
		return "", err
	}
	entropy = addChecksum(entropy)
	entropyInt := new(big.Int).SetBytes(entropy)
	words := make([]string, sentenceLength)
	word := big.NewInt(0)
	for i := sentenceLength - 1; i >= 0; i-- {
		// 算出单词
		word.And(entropyInt, last11BitsMask)
		// 整体右移12位, 以便算下一个单词
		entropyInt.Div(entropyInt, rightShift11BitsDivider)
		//仅保留2个字节
		wordBytes := padByteSlice(word.Bytes(), 2)
		//查找对应码
		words[i] = wordList[binary.BigEndian.Uint16(wordBytes)]
	}

	return strings.Join(words, " "), nil
}

func validateEntropyBitSize(bitSize int) error {
	if (bitSize%32) != 0 || bitSize < 128 || bitSize > 256 {
		return fmt.Errorf("entropy length must be [128, 256] and a multiple of 32")
	}
	return nil
}

func newEntropy(size int)([]byte, error){
	err := validateEntropyBitSize(size)
	if err != nil {
		return nil, err
	}

	entropy := make([]byte, size/8)
	_, err = rand.Read(entropy)
	return entropy, err
}

func checkMnemonic(mnemonic string) error{
	if !IsMnemonicValid(mnemonic) {
		return fmt.Errorf("invalid menomic string")
	}

	var mnemonicSlice = strings.Split(mnemonic, " ")
	var entropyBitSize  = len(mnemonicSlice) * 11
	var checksumBitSize  = entropyBitSize % 32
	var fullByteSize  = (entropyBitSize-checksumBitSize)/8 + 1
	var checksumByteSize = fullByteSize - (fullByteSize % 4)

	//推导加了校验的熵值.
	checksummedEntropy := big.NewInt(0)
	modulo := big.NewInt(2048)
	for _, v := range mnemonicSlice {
		index := big.NewInt(int64(wordMap[v]))
		// 左移12
		checksummedEntropy.Mul(checksummedEntropy, modulo)
		// 累加和
		checksummedEntropy.Add(checksummedEntropy, index)
	}

	//右移校验位数, 推导原熵
	checksumModulo := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(checksumBitSize)), nil)
	rawEntropy := big.NewInt(0).Div(checksummedEntropy, checksumModulo)

	//原熵
	rawEntropyBytes := padByteSlice(rawEntropy.Bytes(), checksumByteSize)
	checksummedEntropyBytes := padByteSlice(checksummedEntropy.Bytes(), fullByteSize)

	//原熵再算一下checksum
	newChecksummedEntropyBytes := padByteSlice(addChecksum(rawEntropyBytes), fullByteSize)

	if !compareByteSlices(checksummedEntropyBytes, newChecksummedEntropyBytes) {
		return fmt.Errorf("invalid menomic checksum ")
	}

	return nil
}

func compareByteSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func NewSeed(mnemonic string, pwd string) (seed []byte, e error){
	if err := checkMnemonic(mnemonic); err != nil{
		e = err
		return seed, e
	}
	seed = pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+pwd), 2048, 64, sha512.New)
	return seed, nil
}

// 验证助记词是否数量合法且在助记词单词列表中
func IsMnemonicValid(mnemonic string) bool {
	words := strings.Fields(mnemonic)
	wordCount := len(words)
	if wordCount%3 != 0 || wordCount < 12 || wordCount > 24 {
		return false
	}
	for _, word := range words {
		if _, ok := wordMap[word]; !ok {
			return false
		}
	}
	return true
}