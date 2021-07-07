package bls

import (
	"crypto/cipher"
	"errors"
	"io"

	"github.com/drand/kyber"
	bls12381 "github.com/kilic/bls12-381"
)

type Fr32 struct {
	V *bls12381.Fr // Integer value from 0 through N-1
}

func NewKyberScalar() kyber.Scalar {
	return NewFr32()
}

// NewInt creaters a new Int with a given big.Int and a big.Int modulus.
func NewFr32() *Fr32 {
	v := bls12381.NewFr()
	return &Fr32{
		V: v,
	}
}

// Equality test for two kyber.Scalars derived from the same Group.
func (s *Fr32) Equal(s2 kyber.Scalar) bool {
	return s.V.Equal(s2.(*Fr32).V)
}

// Set sets the receiver equal to another kyber.Scalar a.
func (s *Fr32) Set(a kyber.Scalar) kyber.Scalar {
	s.V.Set(a.(*Fr32).V)
	return s
}

// Clone creates a new kyber.Scalar with the same value.
func (s *Fr32) Clone() kyber.Scalar {
	v := bls12381.NewFr().Set(s.V)
	return &Fr32{
		V: v,
	}
}

// SetInt64 sets the receiver to a small integer value.
func (s *Fr32) SetInt64(v int64) kyber.Scalar {
	if v >= 0 {
		s.V.Zero()
		s.V[0] = uint64(v)
		return s
	}
	s.V.Zero()
	s.V[0] = uint64(-v)
	s.V.Neg(s.V)
	return s
}

// Set to the additive identity (0).
func (s *Fr32) Zero() kyber.Scalar {
	s.V.Zero()
	return s
}

// Set to the modular sum of kyber.Scalars a and b.
func (s *Fr32) Add(a, b kyber.Scalar) kyber.Scalar {
	s.V.Add(a.(*Fr32).V, b.(*Fr32).V)
	return s
}

// Set to the modular difference a - b.
func (s *Fr32) Sub(a, b kyber.Scalar) kyber.Scalar {
	s.V.Sub(a.(*Fr32).V, b.(*Fr32).V)
	return s
}

// Set to the modular negation of kyber.Scalar a.
func (s *Fr32) Neg(a kyber.Scalar) kyber.Scalar {
	s.V.Neg(a.(*Fr32).V)
	return s
}

// Set to the multiplicative identity (1).
func (s *Fr32) One() kyber.Scalar {
	s.V.One()
	return s
}

// Set to the modular product of kyber.Scalars a and b.
func (s *Fr32) Mul(a, b kyber.Scalar) kyber.Scalar {
	s.V.Mul(a.(*Fr32).V, b.(*Fr32).V)
	return s
}

// Set to the modular division of kyber.Scalar a by kyber.Scalar b.
func (s *Fr32) Div(a, b kyber.Scalar) kyber.Scalar {
	temp := NewFr32().Inv(b)
	s.Mul(a, temp)
	return s
}

// Set to the modular inverse of kyber.Scalar a.
func (s *Fr32) Inv(a kyber.Scalar) kyber.Scalar {
	s.V.Inverse(a.(*Fr32).V)
	return s
}

// Set to a fresh random or pseudo-random kyber.Scalar.
func (s *Fr32) Pick(rand cipher.Stream) kyber.Scalar {
	b := make([]byte, 32)
	rand.XORKeyStream(b, b)
	s.V.FromBytes(b)
	return s
}

// SetBytes sets the kyber.Scalar from a byte-slice,
// reducing if necessary to the appropriate modulus.
// The endianess of the byte-slice is determined by the
// implementation.
func (s *Fr32) SetBytes(b []byte) kyber.Scalar {
	s.V.FromBytes(b)
	return s
}

// String returns the human readable string representation of the object.
func (s *Fr32) String() string {
	return s.V.ToBig().String()
}

// Encoded length of this object in bytes.
func (s *Fr32) MarshalSize() int {
	return 32
}

// Encode the contents of this object and write it to an io.Writer.
func (s *Fr32) MarshalTo(w io.Writer) (int, error) {
	b := s.V.ToBytes()
	return w.Write(b)
}

// Decode the content of this object by reading from an io.Reader.
// If r is an XOF, it uses r to pick a valid object pseudo-randomly,
// which may entail reading more than Len bytes due to retries.
func (s *Fr32) UnmarshalFrom(r io.Reader) (int, error) {
	b := make([]byte, 32)
	n, err := r.Read(b)
	if err != nil && err != io.EOF {
		return n, err
	}
	if n != 32 {
		return n, errors.New("not enough")
	}
	s.V.FromBytes(b)
	return n, err
}

func (s *Fr32) MarshalBinary() (data []byte, err error) {
	b := s.V.ToBytes()
	return b, nil
}

func (s *Fr32) UnmarshalBinary(data []byte) error {
	s.V.FromBytes(data)
	return nil
}
