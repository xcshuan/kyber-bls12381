package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	mrand "math/rand"
	"os"

	sig "github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/util/random"
	bls "github.com/xcshuan/kyber-bls12381"
)

type toWrite struct {
	Msg          string
	Ciphersuite  string
	G1Compressed []byte
	G2Compressed []byte
	BLSPrivKey   string
	BLSPubKey    []byte
	BLSSigG2     []byte
}
type testVector struct {
	msg    string
	cipher string
}

func main() {
	outputName := "compatibility.dat"
	var vectors []toWrite
	var tvs = []testVector{
		{
			msg:    "",
			cipher: "",
		},
		{
			msg:    "",
			cipher: string(bls.Domain),
		},
		{
			msg:    "1234",
			cipher: string(bls.Domain),
		},
	}
	tvs = fill(tvs)
	for _, tv := range tvs {
		bls.Domain = []byte(tv.cipher)
		g1 := bls.NullKyberG1().Hash([]byte(tv.msg))
		g1Buff, _ := g1.MarshalBinary()
		g2 := bls.NullKyberG2().Hash([]byte(tv.msg))
		g2Buff, _ := g2.MarshalBinary()
		s := toWrite{
			Msg:          tv.msg,
			Ciphersuite:  tv.cipher,
			G1Compressed: g1Buff,
			G2Compressed: g2Buff,
		}

		if bytes.Equal([]byte(tv.cipher), bls.Domain) {
			// SIGNATURE is always happening on bls.Domain
			pairing := bls.NewBLS12381Suite()
			scheme := sig.NewSchemeOnG2(pairing)
			priv, pub := scheme.NewKeyPair(random.New())
			privDecimal := priv.(*bls.Fr32).String()
			pubBuff, _ := pub.MarshalBinary()
			signature, err := scheme.Sign(priv, []byte(tv.msg))
			if err != nil {
				panic(err)
			}
			s.BLSPrivKey = privDecimal
			s.BLSPubKey = pubBuff
			s.BLSSigG2 = signature
		}
		vectors = append(vectors, s)
	}
	f, err := os.Create(outputName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(vectors); err != nil {
		panic(err)
	}
}

func fill(tvs []testVector) []testVector {
	tvs = append(tvs, testVector{
		msg:    randomString(32),
		cipher: string(bls.Domain),
	})
	tvs = append(tvs, testVector{
		msg:    randomString(64),
		cipher: string(bls.Domain),
	})
	for i := 0; i < 100; i++ {
		msgLen := mrand.Intn(2000)
		msg := randomString(msgLen)
		tvs = append(tvs, testVector{
			msg:    msg,
			cipher: string(bls.Domain),
		})
	}
	return tvs
}

func randomString(n int) string {
	out := make([]byte, n)
	io.ReadFull(rand.Reader, out)
	return hex.EncodeToString(out)
}
