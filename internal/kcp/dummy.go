package kcp

import (
	"encoding/binary"
)

type BlockCrypt interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type fecPacket []byte

func (bts fecPacket) flag() uint16 { return binary.LittleEndian.Uint16(bts[4:]) }

type fecDecoder struct{}

func newFECDecoder(rxlimit int, dataShards int) *fecDecoder { return nil }
func (f *fecDecoder) decode(p fecPacket) [][]byte           { return nil }

type fecEncoder struct{}

func newFECEncoder(dataShards, parityShards, rxlimit int) *fecEncoder { return nil }
func (f *fecEncoder) encode(data []byte, x uint16) [][]byte           { return nil }
func (f *fecEncoder) encodeOOB(data []byte) [][]byte                  { return nil }

const (
	fecHeaderSize      = 6
	fecHeaderSizePlus2 = 8
	typeData           = 0
	typeParity         = 1
	typeOOB            = 2
)
