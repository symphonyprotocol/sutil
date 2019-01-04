package utils

import "fmt"
import "os"
import "log"
// import ec "../elliptic"
import ec "github.com/symphonyprotocol/sutil/elliptic"
import "bytes"
import "compress/zlib"
import "encoding/base64"
import "encoding/hex"
// import "strconv"

func BytesToString(b []byte) (s string) {
	// s = ""
	// for i := 0; i < len(b); i++ {
	// 	s += fmt.Sprintf("%02X", b[i])
	// }
	// return s
	return hex.EncodeToString(b)
}

func StringToBytes(s string) (b []byte){
	// var res []string
	// // p := make([]string, len(s)/2)
	// idx1 := 0
	// idx2 := idx1 + 1
    // for i := 0; i < len(s) / 2; i++ {
	// 	val := s[idx1: idx2+1]
	// 	b_val, _ := strconv.ParseInt(val, 16, 8)
	// 	res = append(res, val)
	// 	idx1 += 2
	// 	idx2 = idx1 + 1
    // }
	// return b
	res, err := hex.DecodeString(s)
	if err != nil{
		log.Panic(err)
	}
	return res
}


func gensecp256k1() {
	fi, err := os.Create("secp256k1.go")
	if err != nil {
		log.Fatal(err)
	}
	defer fi.Close()

	// Compress the serialized byte points.
	serialized := ec.S256().SerializedBytePoints()
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(serialized); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	w.Close()
	// Encode the compressed byte points with base64.
	encoded := make([]byte, base64.StdEncoding.EncodedLen(compressed.Len()))
	base64.StdEncoding.Encode(encoded, compressed.Bytes())


	fmt.Fprintln(fi, "package elliptic")
	fmt.Fprintln(fi)
	fmt.Fprintln(fi, "// Auto-generated file (see genprecomps.go)")
	fmt.Fprintln(fi, "// DO NOT EDIT")
	fmt.Fprintln(fi)
	fmt.Fprintf(fi, "var secp256k1BytePoints = %q\n", string(encoded))

	a1, b1, a2, b2 := ec.S256().EndomorphismVectors()
	fmt.Println("The following values are the computed linearly " +
		"independent vectors needed to make use of the secp256k1 " +
		"endomorphism:")
	fmt.Printf("a1: %x\n", a1)
	fmt.Printf("b1: %x\n", b1)
	fmt.Printf("a2: %x\n", a2)
	fmt.Printf("b2: %x\n", b2)
}

func Min(x, y int64) int64 {
    if x < y {
        return x
    }
    return y
}

func Max(x, y int64) int64 {
    if x > y {
        return x
    }
    return y
}
