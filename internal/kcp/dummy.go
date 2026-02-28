package kcp

import (
    "crypto/cipher"
    "encoding/binary"
)

type BlockCrypt interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type aeadCrypt struct {
	aead cipher.AEAD
}
func (aeadCrypt) BlockSize() int { return 0 }
func (aeadCrypt) Encrypt(_, _ []byte) {}
func (aeadCrypt) Decrypt(_, _ []byte) {}
func (a *aeadCrypt) Seal(dst, nonce, plaintext, additionalData []byte) []byte { return nil }
func (a *aeadCrypt) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) { return nil, nil }
func (a *aeadCrypt) NonceSize() int { return 0 }
func (a *aeadCrypt) Overhead() int { return 0 }

type fecPacket []byte
func (bts fecPacket) seqid() uint32 { return binary.LittleEndian.Uint32(bts) }
func (bts fecPacket) flag() uint16  { return binary.LittleEndian.Uint16(bts[4:]) }
func (bts fecPacket) data() []byte  { return bts[6:] }

type fecDecoder struct{}
func newFECDecoder(rxlimit int, dataShards int) *fecDecoder { return nil }
func (f *fecDecoder) decodeBytes(data []byte) ([][]byte, error) { return nil, nil }
func (f *fecDecoder) decode(p fecPacket) [][]byte { return nil }

type fecEncoder struct{}
func newFECEncoder(dataShards, parityShards, rxlimit int) *fecEncoder { return nil }
func (f *fecEncoder) encode(data []byte, x uint16) [][]byte { return nil }
func (f *fecEncoder) encodeOOB(data []byte) [][]byte { return nil }

const (
    fecHeaderSize = 6
    fecHeaderSizePlus2 = 8
    typeData = 0
    typeParity = 1
    typeOOB = 2
)
