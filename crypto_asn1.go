package main

import (
	"slowpoke2/utils"
	"flag"
	"io/ioutil"
	"crypto/rand"
	"math/big"
	"errors"
	"encoding/asn1"
	"fmt"
	"crypto/aes"
	"strconv"
	"crypto/cipher"
	"io"
	"crypto/sha256"
	"crypto/elliptic"
	"encoding/json"
)

var (
	ACTIONS = []string{
		"ENC",
		"DEC",
		"SGN",
		"CHK",
		"GEN"}

	ALGORITHMS = []string{
		"RSA",
		"ELG",
		"GST",
	}

	ONE          = big.NewInt(1)
	NEG_ONE      = big.NewInt(-1)
	ZERO         = big.NewInt(0)
	MAX_INT_256  = big.NewInt(0)
	MAX_INT_1024 = big.NewInt(0)
)
// ================ RSA STRUCTS =======================
type PublicRSA_ASN1 struct {
	Ident []byte
	Name  string
	N     *big.Int
	E     *big.Int
}

type SecretRSA_ASN1 struct {
	Ident []byte
	Name  string
	N     *big.Int
	D     *big.Int
}

type EncryptedRSAFile_ASN1 struct {
	PublicKey     PublicRSA_ASN1
	EncryptedRSA  EncryptedRSAValue
	EncryptedData EncryptedAESData
}

type EncryptedRSAValue struct {
	Value *big.Int
}

type EncryptedAESData struct {
	Ident    []byte
	Name     string
	FileLen  int
	FileData []byte
}

type SignRSA struct {
	PublicKey PublicRSA_ASN1
	Name      string
	FileName  string
	Sign      EncryptedRSAValue
}

// ================ EL-GAMAL STRUCTS =======================

type PublicELGAMAL_ASN1 struct {
	Ident []byte
	Name  string
	P     *big.Int
	G     *big.Int
	Y     *big.Int
}

type SecretELGAMAL_ASN1 struct {
	Ident []byte
	Name  string
	X     *big.Int
}

type EncryptedELGAMALFile_ASN1 struct {
	PublicKey        PublicELGAMAL_ASN1
	EncryptedElGamal EncryptedElGamalValue
	EncryptedData    EncryptedAESData
}

type EncryptedElGamalValue struct {
	A *big.Int
	B *big.Int
}

type SignElGamal struct {
	PublicKey PublicELGAMAL_ASN1
	Name      string
	FileName  string
	Sign      EncryptedElGamalValue
}

func check_err(err error) {
	if err != nil {
		utils.CheckError(err)
		panic(0)
	}
}

func readFile(filename string) ([]byte, error) {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		utils.CheckError(err)
		panic("error")
		//return []byte{},err
	}

	return dat, err
}

func writeFile(filename string, data []byte) (error) {
	err := ioutil.WriteFile(filename, data, 0750)
	return err
}

func makeSHA256(data []byte) []byte {

	h := sha256.New()

	h.Write(data)
	return h.Sum(nil)
}

func aes_encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	check_err(err)
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
	return ciphertext, nil
}

func aes_decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)

	check_err(err)
	return text, nil
}

func gen_rsa_keys() (e *big.Int, d *big.Int, n *big.Int, err error) {
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	/*fmt.Printf("\t p = %d\n", p)
	fmt.Printf("q = %d\n", q)*/
	n = big.NewInt(0)
	phi := big.NewInt(0)
	n.Mul(p, q)

	p.Add(p, NEG_ONE)
	q.Add(q, NEG_ONE)

	phi.Mul(p, q)

	e = big.NewInt(65537)

	d = big.NewInt(0)

	d.ModInverse(e, phi)

	test := big.NewInt(0)
	test.Mul(e, d)
	test.Mod(test, phi)
	if test.Cmp(ONE) == 0 {

		fmt.Printf("\te = %d\n", e)
		fmt.Printf("\td = %d\n", d)
		fmt.Printf("\tn = %d\n", n)

		//test,err := rand.Int(rand.Reader,MAX_INT)
		test, err := rand.Prime(rand.Reader, 64)
		check_err(err)

		val := rsa_magic(e, n, test)
		res := rsa_magic(d, n, val)

		/*fmt.Printf("Testing keys encrypting t = %d\n",test)
		fmt.Printf("Testing keys ecnrypted t' = %d\n",val)
		fmt.Printf("Testing keys decrypted t' = %d\n",res)*/

		if test.Cmp(res) == 0 {
			utils.LogResult("Successful generation \n")
			return e, d, n, nil
		}
	}

	return ZERO, ZERO, ZERO, errors.New("Error")
}

func gen_elgamal_keys() (p, g, y, x *big.Int) {
	p, _ = rand.Prime(rand.Reader, 1024)
	g, _ = rand.Int(rand.Reader, MAX_INT_1024)
	test := big.NewInt(0)
	p1 := big.NewInt(0)

	p1.Add(p, NEG_ONE)
	test.Exp(g, p1, p)
	if test.Cmp(ONE) != 0 {
		utils.LogError("Error in El-gamal keys generating")
		panic(2)
	}

	x, err := rand.Int(rand.Reader, p)
	check_err(err)

	y = big.NewInt(0)

	y.Exp(g, x, p)

	test, err = rand.Prime(rand.Reader, 256)

	check_err(err)

	a, b := elgamal_enc(g, p, y, test)
	test_1 := elgamal_dec(a, b, p, x)

	/*fmt.Printf("==============================\n")*/
	/*fmt.Printf("\t Testing keys: t = %d\n", test)
	fmt.Printf("\t Testing keys: t' = %d\n", test_1)*/
	if test.Cmp(test_1) != 0 {
		utils.LogError("Error in El-gamal keys generation: encrypting not working")
		panic(2)
	}
	test, err = rand.Prime(rand.Reader, 256)
	r, s := elgamal_sign(test, p, g, x)

	if !elgamal_check(p, g, y, test, r, s) {
		utils.LogError("Error in El-gamal keys generation : signing not working ")
		panic(2)
	}

	fmt.Printf("\t p = %d\n", p)
	fmt.Printf("\t g = %d\n", g)
	fmt.Printf("\t y = %d\n", y)
	fmt.Printf("\t x = %d\n", x)

	return p, g, y, x

}

func rsa_magic(e, n, data *big.Int) (res *big.Int) {
	res = big.NewInt(0)
	res.Exp(data, e, n)

	return res
}

func elgamal_enc(g, p, y, m *big.Int) (a, b *big.Int) {
	/*fmt.Printf("\t p = %d\n", p)
	fmt.Printf("\t g = %d\n", g)
	fmt.Printf("\t y = %d\n", y)
	fmt.Printf("\t m = %d\n", m)*/

	a = big.NewInt(0)
	b = big.NewInt(0)
	p1 := big.NewInt(0)
	p1.Add(p, NEG_ONE)
	k, err := rand.Int(rand.Reader, p1)

	check_err(err)
	a.Exp(g, k, p)

	b.Exp(y, k, p)

	b.Mul(b, m)

	b.Mod(b, p)

	/*fmt.Printf("\t a = %d\n", a)
	fmt.Printf("\t b = %d\n", b)*/

	return a, b
}

func elgamal_dec(a, b, p, x *big.Int) (m *big.Int) {

	/*fmt.Printf("\t a = %d\n", a)
	fmt.Printf("\t b = %d\n", b)
	fmt.Printf("\t p = %d\n", p)
	fmt.Printf("\t x = %d\n", x)*/

	m = big.NewInt(0)

	p1 := big.NewInt(0)
	p1.Add(p, NEG_ONE)

	temp := big.NewInt(0)
	temp.Neg(x)
	temp.Add(p1, temp)
	m.Exp(a, temp, p)
	m.Mul(m, b)
	m.Mod(m, p)

	//fmt.Printf("\t m = %d\n", m)
	return m
}

func elgamal_sign(m, p, g, x *big.Int) (r, s *big.Int) {

	/*fmt.Printf("\t m = %d\n", m)
	fmt.Printf("\t p = %d\n", p)
	fmt.Printf("\t g = %d\n", g)
	fmt.Printf("\t x = %d\n", x)*/
	s = big.NewInt(0)
	r = big.NewInt(0)

	p1 := big.NewInt(0)
	p1.Add(p, NEG_ONE)
	k := big.NewInt(0)
	suc := false
	for !suc {
		k, _ = rand.Prime(rand.Reader, p1.BitLen())
		//check_err(err)
		if k.Cmp(p1) == -1 {
			suc = true
		}

	}
	//fmt.Printf("\t k = %d\n", k)
	r.Exp(g, k, p)

	t := big.NewInt(0)

	t.Mul(x, r)
	t.Neg(t)
	t.Add(t, m)
	t.Mod(t, p1)

	k.ModInverse(k, p1)

	t.Mul(k, t)
	s.Mod(t, p1)
	/*fmt.Printf("\t r = %d\n", r)
	fmt.Printf("\t s = %d\n", s)
	fmt.Printf("==============================\n")*/
	return r, s
}

func elgamal_check(p, g, y, m, r, s *big.Int) bool {

	/*fmt.Printf("\t m = %d\n", m)
	fmt.Printf("\t p = %d\n", p)
	fmt.Printf("\t g = %d\n", g)
	fmt.Printf("\t y = %d\n", y)
	fmt.Printf("\t r = %d\n", r)
	fmt.Printf("\t s = %d\n", s)
	fmt.Printf("==============================\n")*/
	t1 := big.NewInt(0)
	t2 := big.NewInt(0)

	t1.Exp(y, r, p)
	t2.Exp(r, s, p)
	t1.Mul(t1, t2)
	t1.Mod(t1, p)

	t2.Exp(g, m, p)

	if t1.Cmp(t2) == 0 {
		return true
	} else {
		return false
	}

}

type Point struct {
	X *big.Int
	Y *big.Int
}

type ElleptParams struct {
	A         *big.Int
	B         *big.Int
	BasePoint Point
	N         *big.Int
	P         *big.Int
}

type PublicGost_key struct {
	Ident     []byte
	Name      string
	OpenPoint Point
	Params    ElleptParams
}

type SecretGost_key struct {
	Ident  []byte
	Name   string
	D      *big.Int
	Params ElleptParams
}

type GostSign struct {
	PublicKey PublicGost_key
	Name      string
	FileName  string
	Sign      GostSignedValue
}

type GostSignedValue struct {
	Rx *big.Int
	S  *big.Int
}

func gen_gost_keys() (pub PublicGost_key, sec SecretGost_key) {
	mycurve := elliptic.P256()

	fmt.Printf("\tB: %d\n", mycurve.Params().B)
	fmt.Printf("\tGx: %d\n", mycurve.Params().Gx)
	fmt.Printf("\tGy: %d\n", mycurve.Params().Gy)
	fmt.Printf("\tN: %d\n", mycurve.Params().N)
	fmt.Printf("\tP: %d\n", mycurve.Params().P)
	q := mycurve.Params().N
	d, err := rand.Int(rand.Reader, q)
	check_err(err)

	Qx, Qy := mycurve.ScalarBaseMult(d.Bytes())

	fmt.Printf("\td: %d\n", d)
	fmt.Printf("\tQx %d\n", Qx)
	fmt.Printf("\tQy %d\n", Qy)

	basePoint := Point{}
	openPoint := Point{}
	params := ElleptParams{}

	pub = PublicGost_key{}
	sec = SecretGost_key{}

	basePoint.X = mycurve.Params().Gx
	basePoint.Y = mycurve.Params().Gy

	openPoint.X = Qx
	openPoint.Y = Qy
	a := big.NewInt(1)
	params.A = a
	params.B = mycurve.Params().B
	params.N = mycurve.Params().N
	params.P = mycurve.Params().P

	pub.Params = params
	pub.Params.BasePoint = basePoint
	pub.OpenPoint = openPoint

	sec.Params = params
	sec.Params.BasePoint = basePoint
	sec.D = d

	return pub, sec

}

func gost_sign(sec SecretGost_key, m *big.Int) (Rx, s *big.Int) {
	mycurve := elliptic.P256()

	mycurve.Params().B.Set(sec.Params.B)
	mycurve.Params().P.Set(sec.Params.P)
	mycurve.Params().N.Set(sec.Params.N)
	mycurve.Params().Gx.Set(sec.Params.BasePoint.X)
	mycurve.Params().Gy.Set(sec.Params.BasePoint.Y)

	q := mycurve.Params().N

	e := big.NewInt(0)
	e.Mod(m, q)

	if e.Cmp(ZERO) == 0 {
		e.SetInt64(1)
	}

	ok := false
	Rx = big.NewInt(0)
	s = big.NewInt(0)
	R := Point{}
	for !ok {
		k, _ := rand.Int(rand.Reader, q)

		//fmt.Printf("k: %d\n", k)

		R.X, R.Y = mycurve.ScalarBaseMult(k.Bytes())

		/*fmt.Printf("find kP:\n")
		fmt.Printf("R(x) = %d\n", R.X)
		fmt.Printf("R(y) = %d\n", R.Y)*/
		Rx.Mod(R.X, q)
		//fmt.Printf("R(x) mod q = %d\n", Rx)
		if Rx.Cmp(ZERO) != 0 {

			rd := big.NewInt(0)
			ke := big.NewInt(0)
			sum := big.NewInt(0)

			rd.Mul(Rx, sec.D)
			ke.Mul(k, e)

			sum.Add(rd, ke)

			s.Mod(sum, q)
			/*fmt.Printf("r*d = %d\n", rd)
			fmt.Printf("k*e = %d\n", ke)
			fmt.Printf("r*d+k*e = %d\n", sum)
			fmt.Printf("(r*d+k*e) mod q = %d\n", s)*/

			if s.Cmp(ZERO) != 0 {
				ok = true
				break
			}
		}
	}

	return Rx, s
}

func gost_check(pub PublicGost_key, m *big.Int, sign GostSignedValue) bool {
	mycurve := elliptic.P256()

	mycurve.Params().B.Set(pub.Params.B)
	mycurve.Params().P.Set(pub.Params.P)
	mycurve.Params().N.Set(pub.Params.N)
	mycurve.Params().Gx.Set(pub.Params.BasePoint.X)
	mycurve.Params().Gy.Set(pub.Params.BasePoint.Y)

	q := mycurve.Params().N

	e := big.NewInt(0)

	e.Mod(m, q)
	if e.Cmp(ZERO) == 0 {
		e.SetInt64(1)
	}

	v := big.NewInt(0)

	v.ModInverse(e, q)

	z1 := big.NewInt(0)
	z2 := big.NewInt(0)

	sv := big.NewInt(0)
	rv := big.NewInt(0)

	sv.Mul(sign.S, v)
	rv.Mul(sign.Rx, v)

	rv.Mul(rv, NEG_ONE)

	/*fmt.Printf("sv = %d\n", sv)
	fmt.Printf("rv = %d\n", rv)*/

	z1.Mod(sv, q)
	z2.Mod(rv, q)

	px1, py1 := mycurve.ScalarBaseMult(z1.Bytes())
	qx1, qy1 := mycurve.ScalarMult(pub.OpenPoint.X, pub.OpenPoint.Y, z2.Bytes())

	cx, _ := mycurve.Add(px1, py1, qx1, qy1)

	r2 := big.NewInt(0)

	r2.Mod(cx, q)

	if sign.Rx.Cmp(r2) == 0 {
		return true
	} else {
		return false
	}
}

func encrypt(infile string, pubkey string, algo string) {

	data, err := readFile(infile)

	check_err(err)

	aes_key, err := rand.Int(rand.Reader, MAX_INT_256)

	check_err(err)

	encrypted_data, err := aes_encrypt(aes_key.Bytes(), data)
	check_err(err)

	encrypted_aes_struct := EncryptedAESData{}

	encrypted_aes_struct.Name = "AES-256"
	encrypted_aes_struct.Ident = []byte{0x02, 0x00}
	encrypted_aes_struct.FileLen = len(data)
	encrypted_aes_struct.FileData = encrypted_data

	if algo == ALGORITHMS[0] {
		utils.LogInfo("Encrypting file " + infile + "(" + strconv.Itoa(len(data)) + ") with RSA ")
		main_struct := EncryptedRSAFile_ASN1{}

		encrypted_key_struct := EncryptedRSAValue{}

		pubkey_asn1, err := readFile(pubkey)
		if err != nil {
			utils.CheckError(err)

			return
		}

		pub := PublicRSA_ASN1{}

		_, err = asn1.Unmarshal(pubkey_asn1, &pub)
		check_err(err)

		main_struct.PublicKey = pub

		fmt.Printf("\t e = %d\n", main_struct.PublicKey.E)
		fmt.Printf("\t n = %d\n", main_struct.PublicKey.N)

		e := big.NewInt(0)
		n := big.NewInt(0)
		e.Set(pub.E)
		n.Set(pub.N)
		encrypted_key_struct.Value = big.NewInt(0)

		encrypted_key_struct.Value.Set(rsa_magic(e, n, aes_key))

		main_struct.EncryptedData = encrypted_aes_struct
		main_struct.EncryptedRSA = encrypted_key_struct

		fmt.Printf("\t Using AES-256, key[32] = %x\n", aes_key)
		fmt.Printf("\t Encrypted AES key : %d\n", encrypted_key_struct.Value)

		encoded_enc, err := asn1.Marshal(main_struct)
		check_err(err)

		utils.LogResult("Saving encrypted file as " + infile + ".enc")
		err = writeFile(infile+".enc", encoded_enc)

		check_err(err)
	} else if algo == ALGORITHMS[1] {
		utils.LogInfo("Encrypting file " + infile + "(" + strconv.Itoa(len(data)) + ") with EL-GAMAL ")

		main_struct := EncryptedELGAMALFile_ASN1{}

		encrypted_key_struct := EncryptedElGamalValue{}

		pubkey_asn1, err := readFile(pubkey)
		if err != nil {
			utils.CheckError(err)

			return
		}

		pub := PublicELGAMAL_ASN1{}

		_, err = asn1.Unmarshal(pubkey_asn1, &pub)
		check_err(err)

		main_struct.PublicKey = pub

		g := big.NewInt(0)
		y := big.NewInt(0)
		p := big.NewInt(0)

		g.Set(pub.G)
		y.Set(pub.Y)
		p.Set(pub.P)

		fmt.Printf("\t Public key params  g =  %d\n", pub.G)
		fmt.Printf("\t Public key params  y =  %d\n", pub.Y)
		fmt.Printf("\t Public key params  p =  %d\n", pub.P)

		encrypted_key_struct.A = big.NewInt(0)
		encrypted_key_struct.B = big.NewInt(0)

		a, b := elgamal_enc(g, p, y, aes_key)

		encrypted_key_struct.A.Set(a)
		encrypted_key_struct.B.Set(b)

		main_struct.EncryptedData = encrypted_aes_struct
		main_struct.EncryptedElGamal = encrypted_key_struct

		fmt.Printf("\t Using AES-256, key[32] = %x\n", aes_key)
		fmt.Printf("\t Encrypted AES key a =  %d\n", encrypted_key_struct.A)
		fmt.Printf("\t Encrypted AES key b =  %d\n", encrypted_key_struct.B)

		encoded_enc, err := asn1.Marshal(main_struct)
		check_err(err)

		utils.LogResult("Saving encrypted file as " + infile + ".enc")
		err = writeFile(infile+".enc", encoded_enc)

		check_err(err)
	} else {

		check_err(errors.New("Unknown algorithm type "))
	}

}

func decrypt(infile string, outfile string, seckey string, algo string) {

	data, err := readFile(infile)

	check_err(err)
	aes_key := big.NewInt(0)

	var filedata []byte
	var filelen int

	if algo == ALGORITHMS[0] {
		utils.LogInfo("Decrypting file " + infile + " with RSA")

		main_struct := EncryptedRSAFile_ASN1{}
		secretkey_struct := SecretRSA_ASN1{}

		asn1.Unmarshal(data, &main_struct)

		secret_key, err := readFile(seckey)
		check_err(err)

		asn1.Unmarshal(secret_key, &secretkey_struct)

		fmt.Printf("\t Encrypted AES key : %d\n", main_struct.EncryptedRSA.Value)
		aes_key = rsa_magic(secretkey_struct.D, secretkey_struct.N, main_struct.EncryptedRSA.Value)
		filedata = main_struct.EncryptedData.FileData
		filelen = main_struct.EncryptedData.FileLen

	} else if algo == ALGORITHMS[1] {
		utils.LogInfo("Decrypting file " + infile + " with ELGAMAL")

		main_struct := EncryptedELGAMALFile_ASN1{}
		secretkey_struct := SecretELGAMAL_ASN1{}

		asn1.Unmarshal(data, &main_struct)

		secret_key, err := readFile(seckey)
		check_err(err)

		asn1.Unmarshal(secret_key, &secretkey_struct)
		a := main_struct.EncryptedElGamal.A
		b := main_struct.EncryptedElGamal.B
		p := main_struct.PublicKey.P
		x := secretkey_struct.X

		fmt.Printf("\t Params  a =  %d\n", a)
		fmt.Printf("\t Params  b =  %d\n", b)
		fmt.Printf("\t Params  p =  %d\n", p)
		fmt.Printf("\t Params  x =  %d\n", x)

		aes_key = elgamal_dec(a, b, p, x)
		filedata = main_struct.EncryptedData.FileData
		filelen = main_struct.EncryptedData.FileLen
	} else {
		check_err(errors.New("Unknown algorithm"))
	}

	fmt.Printf("\t AES-256 decrypted key[32] = %d\n", aes_key)
	fmt.Printf("\t AES-256 decrypted key[32] = %x\n", aes_key)
	decrypted, err := aes_decrypt(aes_key.Bytes(), filedata)
	check_err(err)
	if len(decrypted) != filelen {
		utils.LogError("Length of encrypted file doesn't match with FileLen field")
		return
	}

	utils.LogResult("Saving decrypted file as " + outfile)
	err = writeFile(outfile, decrypted)
	check_err(err)
}

func generate_keys(outfile string, algo string) {
	if algo == ALGORITHMS[0] {

		utils.LogInfo("Generating RSA keys")

		e, d, n, err := gen_rsa_keys()

		if err != nil {
			utils.CheckError(err)
		}
		/*fmt.Printf("\t e = %d\n", e)
		fmt.Printf("\t d = %d\n", d)
		fmt.Printf("\t n = %d\n", n)*/
		pub := PublicRSA_ASN1{}
		pub.N = big.NewInt(0)
		pub.E = big.NewInt(0)
		sec := SecretRSA_ASN1{}
		sec.D = big.NewInt(0)
		sec.N = big.NewInt(0)

		pub.N.Set(n)
		pub.E.Set(e)
		pub.Ident = []byte{0x00, 0x01}
		pub.Name = "Test RSA Public key"

		sec.N.Set(n)
		sec.D.Set(d)
		sec.Ident = []byte{0x00, 0x01}
		sec.Name = "Test RSA Secret key"

		encoded_pub, err := asn1.Marshal(pub)
		utils.CheckError(err)
		encoded_sec, err := asn1.Marshal(sec)
		utils.CheckError(err)

		utils.LogResult("Saving public key as " + outfile + ".pub")
		utils.LogResult("Saving secret key as " + outfile + ".sec")
		err = writeFile(outfile+".pub", encoded_pub)
		utils.CheckError(err)

		err = writeFile(outfile+".sec", encoded_sec)
		utils.CheckError(err)
	} else if algo == ALGORITHMS[1] {

		utils.LogInfo("Generating EL-GAMAL keys")

		p, g, y, x := gen_elgamal_keys()

		/*fmt.Printf("\t Public parameters:\n")
		fmt.Printf("\t p = %d\n", p)
		fmt.Printf("\t g = %d\n", g)
		fmt.Printf("\t y = %d\n", y)
		fmt.Printf("\t Secret parameters\n")
		fmt.Printf("\t x = %d\n", x)*/

		pub := PublicELGAMAL_ASN1{}
		sec := SecretELGAMAL_ASN1{}

		pub.P = big.NewInt(0)
		pub.G = big.NewInt(0)
		pub.Y = big.NewInt(0)

		sec.X = big.NewInt(0)

		pub.P.Set(p)
		pub.G.Set(g)
		pub.Y.Set(y)

		sec.X.Set(x)

		pub.Ident = []byte{0x00, 0x02}
		pub.Name = "Test ElGamal Public key"

		sec.Ident = []byte{0x00, 0x02}
		sec.Name = "Test ElGamal secret key"

		encoded_pub, err := asn1.Marshal(pub)
		utils.CheckError(err)
		encoded_sec, err := asn1.Marshal(sec)
		utils.CheckError(err)

		utils.LogResult("Saving public key as " + outfile + ".pub")
		utils.LogResult("Saving secret key as " + outfile + ".sec")
		err = writeFile(outfile+".pub", encoded_pub)
		utils.CheckError(err)

		err = writeFile(outfile+".sec", encoded_sec)
		utils.CheckError(err)
	} else if algo == ALGORITHMS[2] {

		utils.LogInfo("Generating Gost 34.10-2012 keys")

		pub, sec := gen_gost_keys()

		encoded_pub, err := asn1.Marshal(pub)
		utils.CheckError(err)
		encoded_sec, err := asn1.Marshal(sec)
		utils.CheckError(err)

		pub.Ident = []byte{0x00, 0x03}
		pub.Name = "Test Gost 34.10-2012 Public key"

		sec.Ident = []byte{0x00, 0x03}
		sec.Name = "Test Gost 34.10-2012 secret key"

		res2B, _ := json.Marshal(pub)
		fmt.Println(string(res2B))

		res3B, _ := json.Marshal(sec)
		fmt.Println(string(res3B))

		utils.LogResult("Saving public key as " + outfile + ".pub")
		utils.LogResult("Saving secret key as " + outfile + ".sec")
		err = writeFile(outfile+".pub", encoded_pub)
		utils.CheckError(err)

		err = writeFile(outfile+".sec", encoded_sec)
		utils.CheckError(err)

	} else {
		check_err(errors.New("Unknown algorithm"))
	}

}

func sign_file(infile string, seckey string, pubkey string, algo string) {
	data, err := readFile(infile)

	check_err(err)

	m := big.NewInt(0)
	m.SetBytes(makeSHA256(data))
	fmt.Printf("SHA-256 hash (%s) = %x \n\n1",infile,m.Bytes())
	if algo == ALGORITHMS[0] {

		utils.LogInfo("Signing file " + infile + "(" + strconv.Itoa(len(data)) + ") with RSA ")

		secretkey_struct := SecretRSA_ASN1{}
		secret_key, err := readFile(seckey)
		check_err(err)

		asn1.Unmarshal(secret_key, &secretkey_struct)

		pub := PublicRSA_ASN1{}
		pubkey_asn1, err := readFile(pubkey)

		_, err = asn1.Unmarshal(pubkey_asn1, &pub)
		check_err(err)

		main_struct := SignRSA{}

		main_struct.PublicKey = pub
		main_struct.Name = "SHA-256"
		main_struct.FileName = infile

		c := rsa_magic(secretkey_struct.D, secretkey_struct.N, m)

		main_struct.Sign.Value = c

		encoded, err := asn1.Marshal(main_struct)
		check_err(err)

		utils.LogResult("Saving sign file as " + infile + ".sign")
		err = writeFile(infile+".sign", encoded)

		check_err(err)

	} else if algo == ALGORITHMS[1] {

		utils.LogInfo("Signing file " + infile + "(" + strconv.Itoa(len(data)) + ") with ElGamal ")

		secretkey_struct := SecretELGAMAL_ASN1{}
		secret_key, err := readFile(seckey)
		check_err(err)

		asn1.Unmarshal(secret_key, &secretkey_struct)

		pub := PublicELGAMAL_ASN1{}
		pubkey_asn1, err := readFile(pubkey)

		_, err = asn1.Unmarshal(pubkey_asn1, &pub)
		check_err(err)

		main_struct := SignElGamal{}

		main_struct.PublicKey = pub
		main_struct.Name = "SHA-256"
		main_struct.FileName = infile

		r, s := elgamal_sign(m, pub.P, pub.G, secretkey_struct.X)
		main_struct.Sign.A = r
		main_struct.Sign.B = s

		encoded, err := asn1.Marshal(main_struct)
		check_err(err)

		utils.LogResult("Saving sign file as " + infile + ".sign")
		err = writeFile(infile+".sign", encoded)

		check_err(err)

	} else if algo == ALGORITHMS[2] {
		utils.LogInfo("Signing file " + infile + "(" + strconv.Itoa(len(data)) + ") with Gost 34.10-2012 ")

		secretkey_struct := SecretGost_key{}
		secret_key, err := readFile(seckey)
		check_err(err)

		asn1.Unmarshal(secret_key, &secretkey_struct)

		pub := PublicGost_key{}
		pubkey_asn1, err := readFile(pubkey)

		_, err = asn1.Unmarshal(pubkey_asn1, &pub)
		check_err(err)

		main_struct := GostSign{}

		main_struct.PublicKey = pub
		main_struct.Name = "SHA-256"
		main_struct.FileName = infile

		Rx, s := gost_sign(secretkey_struct, m)

		main_struct.Sign.Rx = Rx
		main_struct.Sign.S = s

		encoded, err := asn1.Marshal(main_struct)
		check_err(err)

		utils.LogResult("Saving sign file as " + infile + ".sign")
		err = writeFile(infile+".sign", encoded)

		check_err(err)

	} else {
		check_err(errors.New("Unknown algorithm"))
	}
}

func check_sign(infile string, sign_f string, pubkey string, algo string) {
	data, err := readFile(infile)

	check_err(err)
	m := big.NewInt(0)
	m.SetBytes(makeSHA256(data))

	if algo == ALGORITHMS[0] {

		pub := PublicRSA_ASN1{}
		pubkey_asn1, err := readFile(pubkey)

		_, err = asn1.Unmarshal(pubkey_asn1, &pub)
		check_err(err)

		main_struct := SignRSA{}

		sign, err := readFile(sign_f)
		asn1.Unmarshal(sign, &main_struct)

		utils.LogResult("Check signature of " + infile + " with RSA")

		e := rsa_magic(pub.E, pub.N, main_struct.Sign.Value)

		if e.Cmp(m) == 0 {
			utils.LogResult("Right signature!! File is ok!")
		} else {
			utils.LogWarning("Wrong signature!")
		}

	} else if algo == ALGORITHMS[1] {

		pub := PublicELGAMAL_ASN1{}
		pubkey_asn1, err := readFile(pubkey)

		_, err = asn1.Unmarshal(pubkey_asn1, &pub)
		check_err(err)

		main_struct := SignElGamal{}

		sign, err := readFile(sign_f)
		asn1.Unmarshal(sign, &main_struct)

		utils.LogResult("Check signature of " + infile + " with ElGamal")

		r := main_struct.Sign.A
		s := main_struct.Sign.B
		p := pub.P
		g := pub.G
		y := pub.Y

		if elgamal_check(p, g, y, m, r, s) {
			utils.LogResult("Right signature!! File is ok!")
		} else {
			utils.LogWarning("Wrong signature!")
		}

	} else if algo == ALGORITHMS[2] {
		pub := PublicGost_key{}
		pubkey_asn1, err := readFile(pubkey)

		_, err = asn1.Unmarshal(pubkey_asn1, &pub)
		check_err(err)

		main_struct := GostSign{}

		sign, err := readFile(sign_f)
		asn1.Unmarshal(sign, &main_struct)

		utils.LogResult("Check signature of " + infile + " with Gost 34.10-2012")

		if gost_check(pub, m, main_struct.Sign) {
			utils.LogResult("Right signature!! File is ok!")
		} else {
			utils.LogWarning("Wrong signature!")
		}

	} else {
		check_err(errors.New("Unknown algorithm"))
	}

}

func main() {

	init_256 := make([]byte, 32)
	for i := range init_256 {
		init_256[i] = 0xff
	}

	MAX_INT_256.SetBytes(init_256)

	init_1024 := make([]byte, 128)
	for i := range init_1024 {
		init_1024[i] = 0xff
	}

	MAX_INT_1024.SetBytes(init_1024)

	pubkey := flag.String("pub", "none", "ASN1 public key")
	seckey := flag.String("sec", "none", "ASN1 secret key")
	infile := flag.String("in", "none", "Input file for crypt/decrypt sign/checksign")
	outfile := flag.String("out", "none", "Output file for crypt/decrypt sign/checksign")
	sign_f := flag.String("sign", "none", "ASN1 sign of file")
	algo := flag.String("a", "none", "Type of algorithm: RSA, ELGAMAL, GOST(only signing)") //RSA ELGAMAL GOST
	action := flag.String("t", "none", "Action crypt/decrypt, sign/checksign, generate keys")

	flag.Parse()

	if *algo != ALGORITHMS[0] && *algo != ALGORITHMS[1] && *algo != ALGORITHMS[2] {
		utils.LogError("Unknown ALGORITHM type!")
		return
	}

	switch *action {

	case ACTIONS[0]:
		encrypt(*infile, *pubkey, *algo)
	case ACTIONS[1]:
		decrypt(*infile, *outfile, *seckey, *algo)
	case ACTIONS[2]:
		sign_file(*infile, *seckey, *pubkey, *algo)
	case ACTIONS[3]:
		check_sign(*infile, *sign_f, *pubkey, *algo)
	case ACTIONS[4]:
		generate_keys(*outfile, *algo)
	default:
		utils.LogError("Unknown action")
	}

}
