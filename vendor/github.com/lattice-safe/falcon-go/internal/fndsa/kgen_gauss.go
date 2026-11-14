package fndsa

// (f,g) sampling (Gaussian distribution), matching falcon-rs native keygen.

var gauss1024_12289 = []uint64{
	1283868770400643928,
	6416574995475331444,
	4078260278032692663,
	2353523259288686585,
	1227179971273316331,
	575931623374121527,
	242543240509105209,
	91437049221049666,
	30799446349977173,
	9255276791179340,
	2478152334826140,
	590642893610164,
	125206034929641,
	23590435911403,
	3948334035941,
	586753615614,
	77391054539,
	9056793210,
	940121950,
	86539696,
	7062824,
	510971,
	32764,
	1862,
	94,
	4,
	0,
}

func mkgauss(pc *shake256prng, logn uint) int32 {
	g := 1 << (10 - logn)
	val := int32(0)
	for i := 0; i < g; i++ {
		r := pc.next_u64()
		neg := uint32(r >> 63)
		r &^= 1 << 63
		f := uint32((r - gauss1024_12289[0]) >> 63)

		v := uint32(0)
		r2 := pc.next_u64()
		r2 &^= 1 << 63
		for k := 1; k < len(gauss1024_12289); k++ {
			t := uint32((r2-gauss1024_12289[k])>>63) ^ 1
			v |= uint32(k) & -uint32(t&(f^1))
			f |= t
		}
		v = (v ^ -neg) + neg
		val += int32(v)
	}
	return val
}

// Sample f (or g) from the provided SHAKE256-based PRNG. This function ensures
// that the sampled polynomial has odd parity using the native Rust retry flow.
func sample_f(logn uint, pc *shake256prng, f []int8) {
	n := 1 << logn
	mod2 := uint32(0)
	for i := 0; i < n; i++ {
		for {
			s := mkgauss(pc, logn)
			if s < -127 || s > 127 {
				continue
			}
			if i == n-1 {
				if (mod2 ^ (uint32(s) & 1)) == 0 {
					continue
				}
			} else {
				mod2 ^= uint32(s) & 1
			}
			f[i] = int8(s)
			break
		}
	}
}
