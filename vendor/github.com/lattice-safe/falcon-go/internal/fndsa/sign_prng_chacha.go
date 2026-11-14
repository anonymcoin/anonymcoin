package fndsa

import "encoding/binary"

type chachaPRNG struct {
	buf   [512]byte
	ptr   int
	state [256]byte
}

func newChaChaPRNG(seed []byte) *chachaPRNG {
	p := new(chachaPRNG)
	copy(p.state[:56], seed)
	p.refill()
	return p
}

var chachaCW = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

func (p *chachaPRNG) refill() {
	cc := binary.LittleEndian.Uint64(p.state[48:56])
	var initState [12]uint32
	for i := 0; i < 12; i++ {
		initState[i] = binary.LittleEndian.Uint32(p.state[i*4 : i*4+4])
	}
	for u := uint64(0); u < 8; u++ {
		var st [16]uint32
		st[0] = chachaCW[0]
		st[1] = chachaCW[1]
		st[2] = chachaCW[2]
		st[3] = chachaCW[3]
		copy(st[4:], initState[:])
		counter := cc + u
		st[14] ^= uint32(counter)
		st[15] ^= uint32(counter >> 32)
		initial := st
		for i := 0; i < 10; i++ {
			chachaQR(&st, 0, 4, 8, 12)
			chachaQR(&st, 1, 5, 9, 13)
			chachaQR(&st, 2, 6, 10, 14)
			chachaQR(&st, 3, 7, 11, 15)
			chachaQR(&st, 0, 5, 10, 15)
			chachaQR(&st, 1, 6, 11, 12)
			chachaQR(&st, 2, 7, 8, 13)
			chachaQR(&st, 3, 4, 9, 14)
		}
		for i := 0; i < 16; i++ {
			st[i] += initial[i]
		}
		uIdx := int(u)
		for v := 0; v < 16; v++ {
			off := (uIdx << 2) + (v << 5)
			binary.LittleEndian.PutUint32(p.buf[off:off+4], st[v])
		}
	}
	binary.LittleEndian.PutUint64(p.state[48:56], cc+8)
	p.ptr = 0
}

func chachaQR(st *[16]uint32, a, b, c, d int) {
	st[a] += st[b]
	st[d] ^= st[a]
	st[d] = st[d]<<16 | st[d]>>16
	st[c] += st[d]
	st[b] ^= st[c]
	st[b] = st[b]<<12 | st[b]>>20
	st[a] += st[b]
	st[d] ^= st[a]
	st[d] = st[d]<<8 | st[d]>>24
	st[c] += st[d]
	st[b] ^= st[c]
	st[b] = st[b]<<7 | st[b]>>25
}

func (p *chachaPRNG) next_u8() uint8 {
	v := p.buf[p.ptr]
	p.ptr++
	if p.ptr == 512 {
		p.refill()
	}
	return v
}

func (p *chachaPRNG) next_u64() uint64 {
	u := p.ptr
	if u >= 512-9 {
		p.refill()
		return p.next_u64()
	}
	p.ptr = u + 8
	return binary.LittleEndian.Uint64(p.buf[u : u+8])
}
