	.file	"sha2-e2k.c"
	.ignore	ld_st_style
	.ignore	strict_delay
	.text
	.global	sha256_use_4way
	.type	sha256_use_4way, #function
	.align	8
sha256_use_4way:
	{
	  nop 5
	  setwd	wsz = 0x4, nfx = 0x1, dbl = 0x0
	  return	%ctpr3
	  addd,3	0x0, 0x0, %r0
	}
	{
	  ct	%ctpr3
	}
	.size	sha256_use_4way, .- sha256_use_4way
	.global	sha256_init_4way
	.type	sha256_init_4way, #function
	.align	8
sha256_init_4way:
	{
	  nop 5
	  setwd	wsz = 0x4, nfx = 0x1, dbl = 0x0
	  return	%ctpr3
	}
	{
	  ct	%ctpr3
	}
	.size	sha256_init_4way, .- sha256_init_4way
	.global	sha256_transform_4way
	.type	sha256_transform_4way, #function
	.align	8
sha256_transform_4way:
	{
	  nop 5
	  setwd	wsz = 0x4, nfx = 0x1, dbl = 0x0
	  return	%ctpr3
	}
	{
	  ct	%ctpr3
	}
	.size	sha256_transform_4way, .- sha256_transform_4way
	.global	sha256d_ms_4way
	.type	sha256d_ms_4way, #function
	.align	8
sha256d_ms_4way:
	{
	  setwd	wsz = 0x50, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x2f, rbs = 0x20, rcur = 0x0
	  return	%ctpr3
	  qppackdl,1	0x0, 0x0, %g19
	  ldqp,2	0x10, %r3, %g16
	  ldqp,3	%r3, _f16s,_lts1lo 0x30, %g17
	  ldqp,5	%r3, _f16s,_lts1hi 0x20, %g18
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0x30, %g20
	  addd,1	0x0, _f64,_lts1 0xe9b5dba5e9b5dba5, %g21
	  ldqp,2	%r3, _f16s,_lts0hi 0x40, %g22
	  ldqp,3	%r3, 0x0, %g23
	  ldqp,5	%r1, _lit16_ref,_lts0hi 0x40, %g24
	}
	{
	  addd,0	0x0, _f64,_lts2 0x3956c25b3956c25b, %g26
	  addd,1	0x0, %g21, %g25
	  ldqp,2	%r3, _f16s,_lts0lo 0x70, %g27
	  ldqp,3	%r1, _f16s,_lts0hi 0x50, %g28
	  ldqp,5	%r3, _f16s,_lts1lo 0x60, %g29
	}
	{
	  qpsrcw,0	%g16, _f16s,_lts0lo 0x19, %g30
	  qpsrcw,1	%g16, 0xb, %g31
	  addd,2	0x0, %g26, %r6
	  ldqp,3	%r1, _f16s,_lts0hi 0x60, %r9
	  addd,4	0x0, _f64,_lts2 0x59f111f159f111f1, %r7
	  ldqp,5	%r3, _f16s,_lts1lo 0x50, %r3
	}
	{
	  qpsrcw,0	%g16, 0x6, %r10
	  qppackdl,1	%g25, %g21, %g21
	  addd,2	0x0, _f64,_lts2 0x923f82a4923f82a4, %r12
	  addd,3	0x0, %r7, %r11
	  qplog_0xca,4	%g16, %g18, %g17, %g25
	}
	{
	  qpaddw,0	%g20, %g21, %r13
	  qplog_0x96,1	%r10, %g31, %g30, %g30
	  addd,2	0x0, %r12, %r6
	  qppackdl,3	%r11, %r7, %g31
	  qppackdl,4	%r6, %g26, %g26
	  ldqp,5	%r1, _f16s,_lts0lo 0x70, %r7
	}
	{
	  qpaddw,0	%g22, %r13, %g22
	  qppackdl,1	%r6, %r12, %r6
	  addd,2	0x0, _f64,_lts1 0xab1c5ed5ab1c5ed5, %r10
	  qpaddw,3	%g24, %g26, %g24
	  qpsrcw,4	%r3, _f16s,_lts0lo 0x16, %r11
	  ldqp,5	%r1, _f16s,_lts0hi 0x80, %r12
	}
	{
	  qpaddw,0	%r9, %r6, %g24
	  qpsrcw,1	%r3, 0xd, %r13
	  addd,2	0x0, %r10, %r9
	  qpaddw,3	%g17, %g24, %g17
	  qpsrcw,4	%r3, 0x2, %r14
	  addd,5	0x0, _f64,_lts0 0xd807aa98d807aa98, %r15
	}
	{
	  qpaddw,0	%g30, %g25, %g25
	  qppackdl,1	%r9, %r10, %g30
	  ldqp,2	%r1, _f16s,_lts0lo 0x90, %r16
	  qpaddw,3	%g28, %g31, %g28
	  qplog_0xe8,4	%r3, %g29, %g27, %r9
	  addd,5	0x0, %r15, %r10
	}
	{
	  qpaddw,0	%g22, %g25, %g22
	  addd,1	0x0, _f64,_lts1 0x12835b0112835b01, %r10
	  ldqp,2	%r1, _f16s,_lts0lo 0xa0, %r15
	  qpaddw,3	%g18, %g28, %g25
	  qppackdl,4	%r10, %r15, %g28
	  ldqp,5	%r1, _f16s,_lts0hi 0xb0, %r17
	}
	{
	  qpaddw,0	%g23, %g22, %g23
	  addd,1	0x0, %r10, %r18
	  addd,2	0x0, _f64,_lts2 0x550c7dc3550c7dc3, %r20
	  qpaddw,3	%r12, %g28, %r12
	  addd,4	0x0, _f64,_lts0 0x243185be243185be, %r19
	  ldqp,5	%r2, 0x0, %r21
	}
	{
	  qpsrcw,0	%g23, 0xb, %r23
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x19, %r22
	  addd,2	0x0, %r20, %r14
	  qpaddw,3	%g16, %g24, %g24
	  qplog_0x96,4	%r14, %r13, %r11, %r11
	  addd,5	0x0, %r19, %r13
	}
	{
	  qplog_0xca,0	%g23, %g16, %g18, %g18
	  qpsrcw,1	%g23, 0x6, %r24
	  ldqp,2	%r1, _f16s,_lts0lo 0xc0, %r18
	  qpaddw,3	%r7, %g30, %r7
	  qppackdl,4	%r18, %r10, %r10
	  addd,5	0x0, _f64,_lts1 0x72be5d7472be5d74, %r25
	}
	{
	  qppackdl,0	%r14, %r20, %r13
	  qplog_0x96,1	%r24, %r23, %r22, %r22
	  ldqp,2	%r1, _f16s,_lts0lo 0xd0, %r19
	  qpaddw,3	%r11, %r9, %r9
	  qppackdl,4	%r13, %r19, %r11
	  addd,5	0x0, %r25, %r14
	}
	{
	  qpaddw,0	%r22, %g18, %g18
	  addd,1	0x0, _f64,_lts1 0x80deb1fe80deb1fe, %r20
	  ldqp,2	%r1, _f16s,_lts0lo 0xe0, %r22
	  qpaddw,3	%g23, %r7, %r7
	  qppackdl,4	%r14, %r25, %r14
	  ldqp,5	%r1, _f16s,_lts0hi 0xf0, %r23
	}
	{
	  qpaddw,0	%g17, %g18, %g17
	  addd,1	0x0, %r20, %g22
	  addd,2	0x0, _f64,_lts2 0xc19bf174c19bf174, %r24
	  qpaddw,3	%g22, %r9, %g18
	  addd,4	0x0, _f64,_lts0 0x9bdc06a79bdc06a7, %r9
	  ldqp,5	0x10, %r2, %r25
	}
	{
	  qpaddw,0	%g27, %g17, %g27
	  qppackdl,1	%g22, %r20, %g22
	  addd,2	0x0, %r24, %r28
	  qpsrcw,3	%g18, 0xd, %r27
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r26
	  addd,5	0x0, %r9, %r20
	}
	{
	  qpsrcw,0	%g27, _f16s,_lts0lo 0x19, %r29
	  qpsrcw,1	%g27, 0xb, %r30
	  ldqp,2	%r1, _f16s,_lts0hi 0x100, %r33
	  qplog_0xe8,3	%g18, %r3, %g29, %r32
	  qpsrcw,4	%g18, 0x2, %r31
	  addd,5	0x0, _f64,_lts1 0xe49b69c1e49b69c1, %r34
	}
	{
	  qplog_0xca,0	%g27, %g23, %g16, %g16
	  qpsrcw,1	%g27, 0x6, %r35
	  ldqp,2	%r1, _f16s,_lts0lo 0x110, %r31
	  qpaddw,3	%r16, %r10, %r16
	  qplog_0x96,4	%r31, %r27, %r26, %r26
	  addd,5	0x0, %r34, %r27
	}
	{
	  qpaddw,0	%g27, %r12, %r12
	  qplog_0x96,1	%r35, %r30, %r29, %r29
	  addd,2	0x0, _f64,_lts1 0xefbe4786efbe4786, %r20
	  qpaddw,3	%r26, %r32, %r26
	  qppackdl,4	%r20, %r9, %r9
	  ldqp,5	%r1, _f16s,_lts0lo 0x120, %r30
	}
	{
	  qpaddw,0	%r29, %g16, %g16
	  qppackdl,1	%r28, %r24, %r24
	  addd,2	0x0, %r20, %r27
	  qpaddw,3	%g17, %r26, %g17
	  qppackdl,4	%r27, %r34, %r26
	  addd,5	0x0, _f64,_lts0 0xfc19dc60fc19dc6, %r28
	}
	{
	  qpaddw,0	%g25, %g16, %g16
	  qppackdl,1	%r27, %r20, %r20
	  ldqp,2	%r1, _f16s,_lts0hi 0x130, %r32
	  qpsrcw,3	%g17, 0xd, %r29
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x16, %g25
	  addd,5	0x0, %r28, %r27
	}
	{
	  qpaddw,0	%g29, %g16, %g29
	  qpsrlw,1	%g20, 0x3, %r36
	  addd,2	0x0, _f64,_lts1 0x240ca1cc240ca1cc, %r37
	  qplog_0xe8,3	%g17, %g18, %r3, %r35
	  qpsrcw,4	%g17, 0x2, %r34
	  ldqp,5	%r1, _f16s,_lts0lo 0x140, %r38
	}
	{
	  qpsrcw,0	%g29, 0xb, %r40
	  qpsrcw,1	%g29, _f16s,_lts0lo 0x19, %r39
	  addd,2	0x0, %r37, %r29
	  qpaddw,3	%r15, %r11, %r15
	  qplog_0x96,4	%r34, %r29, %g25, %g25
	  addd,5	0x0, _f64,_lts1 0x2de92c6f2de92c6f, %r34
	}
	{
	  qplog_0xca,0	%g29, %g27, %g23, %g23
	  qpsrcw,1	%g29, 0x6, %r41
	  addd,2	0x0, _f64,_lts1 0x4a7484aa4a7484aa, %r43
	  qpaddw,3	%g25, %r35, %g25
	  qpsrcw,4	%g20, _f16s,_lts0lo 0x12, %r35
	  addd,5	0x0, %r34, %r42
	}
	{
	  qpaddw,0	%g29, %r16, %r16
	  qplog_0x96,1	%r41, %r40, %r39, %r39
	  addd,2	0x0, %r43, %r40
	  qpaddw,3	%g16, %g25, %g16
	  qpsrcw,4	%g20, 0x7, %g25
	  ldqp,5	%r1, _f16s,_lts0lo 0x160, %r41
	}
	{
	  qpaddw,0	%r39, %g23, %g23
	  qppackdl,1	%r27, %r28, %r27
	  addd,2	0x0, _f64,_lts1 0x5cb0a9dc5cb0a9dc, %r28
	  qpsrcw,3	%g16, 0xd, %r44
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x16, %r39
	  ldqp,5	%r1, _f16s,_lts0hi 0x170, %r45
	}
	{
	  qpaddw,0	%g24, %g23, %g23
	  qppackdl,1	%r29, %r37, %r29
	  addd,2	0x0, %r28, %r37
	  qplog_0xe8,3	%g16, %g17, %g18, %r46
	  qpsrcw,4	%g16, 0x2, %g24
	  addd,5	0x0, _f64,_lts0 0x76f988da76f988da, %r47
	}
	{
	  qpaddw,0	%r3, %g23, %r3
	  qppackdl,1	%r42, %r34, %r34
	  ldqp,2	%r1, _f16s,_lts0lo 0x180, %r42
	  qpaddw,3	%r17, %r13, %r17
	  qplog_0x96,4	%g24, %r44, %r39, %g24
	  addd,5	0x0, %r47, %r39
	}
	{
	  qpsrcw,0	%r3, 0xb, %r48
	  qpsrcw,1	%r3, _f16s,_lts0lo 0x19, %r44
	  addd,2	0x0, _f64,_lts1 0x983e5152983e5152, %r35
	  qpaddw,3	%g24, %r46, %g24
	  qplog_0x96,4	%g25, %r35, %r36, %g25
	  ldqp,5	%r1, _f16s,_lts0hi 0x1e0, %r36
	}
	{
	  qplog_0xca,0	%r3, %g29, %g27, %g27
	  qpsrcw,1	%r3, 0x6, %r46
	  addd,2	0x0, %r35, %r43
	  qpaddw,3	%r18, %r14, %r18
	  qppackdl,4	%r40, %r43, %r40
	  addd,5	0x0, _f64,_lts0 0xa831c66da831c66d, %r49
	}
	{
	  qpaddw,0	%r3, %r15, %r15
	  qplog_0x96,1	%r46, %r48, %r44, %r44
	  addd,2	0x0, _f64,_lts0 0xb00327c8b00327c8, %r37
	  qpaddw,3	%g23, %g24, %g23
	  qppackdl,4	%r37, %r28, %g24
	  addd,5	0x0, %r49, %r28
	}
	{
	  qpaddw,0	%r44, %g27, %g27
	  qppackdl,1	%r39, %r47, %r39
	  addd,2	0x0, %r37, %r47
	  qpsrcw,3	%g23, 0xd, %r46
	  qpsrcw,4	%g23, _f16s,_lts0lo 0x16, %r44
	  addd,5	0x0, _f64,_lts1 0xbf597fc7bf597fc7, %r48
	}
	{
	  qpaddw,0	%r7, %g27, %g27
	  qppackdl,1	%r43, %r35, %r35
	  addd,2	0x0, _f64,_lts0 0xc6e00bf3c6e00bf3, %r51
	  qplog_0xe8,3	%g23, %g16, %g17, %r50
	  qpsrcw,4	%g23, 0x2, %r7
	  addd,5	0x0, %r48, %r43
	}
	{
	  qpaddw,0	%g18, %g27, %g18
	  qppackdl,1	%r28, %r49, %r28
	  addd,2	0x0, %r51, %r44
	  qpaddw,3	%r19, %g22, %r19
	  qplog_0x96,4	%r7, %r46, %r44, %r7
	  addd,5	0x0, _f64,_lts0 0xd5a79147d5a79147, %r46
	}
	{
	  qpsrcw,0	%g18, 0xb, %r52
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %r49
	  addd,2	0x0, _f64,_lts1 0x6ca635106ca6351, %r50
	  qpaddw,3	%r7, %r50, %r7
	  qppackdl,4	%r47, %r37, %r37
	  addd,5	0x0, %r46, %r47
	}
	{
	  qplog_0xca,0	%g18, %r3, %g29, %g29
	  qpsrcw,1	%g18, 0x6, %r53
	  addd,2	0x0, %r50, %r48
	  qpaddw,3	%r22, %r9, %r22
	  qppackdl,4	%r43, %r48, %r43
	  ldqp,5	%r1, _f16s,_lts0lo 0x1f0, %r54
	}
	{
	  qpaddw,0	%g18, %r17, %r17
	  qplog_0x96,1	%r53, %r52, %r49, %r49
	  addd,2	0x0, _f64,_lts0 0x1429296714292967, %r44
	  qpaddw,3	%g27, %r7, %g27
	  qppackdl,4	%r44, %r51, %r7
	  addd,5	0x0, _f64,_lts2 0x27b70a8527b70a85, %r51
	}
	{
	  qpaddw,0	%r49, %g29, %g29
	  qppackdl,1	%r47, %r46, %r46
	  addd,2	0x0, %r44, %r47
	  qpsrcw,3	%g27, 0xd, %r52
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x16, %r49
	  addd,5	0x0, %r51, %r53
	}
	{
	  qpaddw,0	%r12, %g29, %g29
	  qppackdl,1	%r48, %r50, %r48
	  addd,2	0x0, _f64,_lts0 0x2e1b21382e1b2138, %r50
	  qplog_0xe8,3	%g27, %g23, %g16, %r55
	  qpsrcw,4	%g27, 0x2, %r12
	  addd,5	0x0, _f64,_lts2 0x4d2c6dfc4d2c6dfc, %r56
	}
	{
	  qpaddw,0	%g17, %g29, %g17
	  qppackdl,1	%r47, %r44, %r44
	  addd,2	0x0, %r50, %r47
	  qpaddw,3	%r23, %r24, %r23
	  qplog_0x96,4	%r12, %r52, %r49, %r12
	  addd,5	0x0, %r56, %r49
	}
	{
	  qpsrcw,0	%g17, 0xb, %r57
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x19, %r52
	  addd,2	0x0, _f64,_lts1 0x53380d1353380d13, %r58
	  qpaddw,3	%r12, %r55, %r12
	  qpsrlw,4	%r31, 0x3, %r55
	  ldqp,5	%r2, _f16s,_lts0hi 0x20, %r59
	}
	{
	  qplog_0xca,0	%g17, %g18, %r3, %r3
	  qpsrcw,1	%g17, 0x6, %r60
	  addd,2	0x0, %r58, %r63
	  qpaddw,3	%r33, %r26, %r61
	  qpsrcw,4	%r31, _f16s,_lts0lo 0x12, %r62
	  addd,5	0x0, _f64,_lts1 0x650a7354650a7354, %b[0]
	}
	{
	  qpaddw,0	%g17, %r18, %r18
	  qplog_0x96,1	%r60, %r57, %r52, %r52
	  addd,2	0x0, _f64,_lts0 0x766a0abb766a0abb, %r60
	  qpaddw,3	%g29, %r12, %g29
	  qpsrcw,4	%r31, 0x7, %r12
	  addd,5	0x0, %b[0], %r57
	}
	{
	  qpaddw,0	%r52, %r3, %r3
	  qppackdl,1	%r53, %r51, %r51
	  addd,2	0x0, %r60, %r53
	  qpsrcw,3	%g29, 0xd, %b[1]
	  qpsrcw,4	%g29, _f16s,_lts0lo 0x16, %r52
	  addd,5	0x0, _f64,_lts1 0x81c2c92e81c2c92e, %b[2]
	}
	{
	  qpaddw,0	%r16, %r3, %r3
	  qppackdl,1	%r47, %r50, %r47
	  addd,2	0x0, _f64,_lts0 0x92722c8592722c85, %b[4]
	  qplog_0xe8,3	%g29, %g27, %g23, %b[3]
	  qpsrcw,4	%g29, 0x2, %r16
	  addd,5	0x0, %b[2], %r50
	}
	{
	  qpaddw,0	%g16, %r3, %g16
	  qppackdl,1	%r49, %r56, %r49
	  addd,2	0x0, %b[4], %r56
	  qpaddw,3	%r31, %r20, %r52
	  qplog_0x96,4	%r16, %b[1], %r52, %r16
	  addd,5	0x0, _f64,_lts0 0xa2bfe8a1a2bfe8a1, %b[1]
	}
	{
	  qpsrcw,0	%g16, 0xb, %b[6]
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x19, %b[5]
	  addd,2	0x0, _f64,_lts1 0xa81a664ba81a664b, %r62
	  qpaddw,3	%r16, %b[3], %r16
	  qplog_0x96,4	%r12, %r62, %r55, %r12
	  addd,5	0x0, %b[1], %r55
	}
	{
	  qplog_0xca,0	%g16, %g17, %g18, %g18
	  qpsrcw,1	%g16, 0x6, %b[3]
	  addd,2	0x0, %r62, %r63
	  qpaddw,3	%r30, %g25, %g25
	  qppackdl,4	%r63, %r58, %r58
	  addd,5	0x0, _f64,_lts0 0xc24b8b70c24b8b70, %b[7]
	}
	{
	  qpaddw,0	%g16, %r19, %r19
	  qplog_0x96,1	%b[3], %b[6], %b[5], %b[3]
	  addd,2	0x0, _f64,_lts0 0xc76c51a3c76c51a3, %b[6]
	  qpaddw,3	%r3, %r16, %r3
	  qpsrlw,4	%g25, 0xa, %r16
	  addd,5	0x0, %b[7], %b[5]
	}
	{
	  qpaddw,0	%b[3], %g18, %g18
	  qppackdl,1	%r57, %b[0], %r57
	  addd,2	0x0, %b[6], %b[0]
	  qpsrcw,3	%r3, 0xd, %b[8]
	  qpsrcw,4	%r3, _f16s,_lts0lo 0x16, %b[3]
	  addd,5	0x0, _f64,_lts1 0xd192e819d192e819, %b[9]
	}
	{
	  qpaddw,0	%r15, %g18, %g18
	  qppackdl,1	%r53, %r60, %r53
	  addd,2	0x0, _f64,_lts0 0xd6990624d6990624, %b[11]
	  qplog_0xe8,3	%r3, %g29, %g27, %b[10]
	  qpsrcw,4	%r3, 0x2, %r15
	  addd,5	0x0, %b[9], %r60
	}
	{
	  qpaddw,0	%g23, %g18, %g23
	  qpsrcw,1	%g25, _f16s,_lts0lo 0x13, %b[8]
	  addd,2	0x0, %b[11], %b[12]
	  qpaddw,3	%g25, %r27, %b[3]
	  qplog_0x96,4	%r15, %b[8], %b[3], %r15
	  addd,5	0x0, _f64,_lts1 0xf40e3585f40e3585, %b[13]
	}
	{
	  qpsrcw,0	%g23, 0xb, %b[15]
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x19, %b[14]
	  addd,2	0x0, _f64,_lts1 0x106aa070106aa070, %b[17]
	  qpaddw,3	%r15, %b[10], %r15
	  qpsrcw,4	%g25, _f16s,_lts0hi 0x11, %b[10]
	  addd,5	0x0, %b[13], %b[16]
	}
	{
	  qplog_0xca,0	%g23, %g16, %g17, %g17
	  qpsrcw,1	%g23, 0x6, %b[18]
	  addd,2	0x0, %b[17], %b[20]
	  qpaddw,3	%r32, %g20, %g20
	  qpsrlw,4	%g25, 0x3, %b[19]
	  addd,5	0x0, _f64,_lts0 0x19a4c11619a4c116, %b[21]
	}
	{
	  qpaddw,0	%g23, %r22, %r22
	  qplog_0x96,1	%b[18], %b[15], %b[14], %b[14]
	  addd,2	0x0, _f64,_lts0 0x1e376c081e376c08, %b[18]
	  qpaddw,3	%g18, %r15, %g18
	  qpsrlw,4	%g20, 0xa, %r15
	  addd,5	0x0, %b[21], %b[15]
	}
	{
	  qpaddw,0	%b[14], %g17, %g17
	  qpsrcw,1	%g25, _f16s,_lts0lo 0x12, %b[23]
	  addd,2	0x0, %b[18], %b[24]
	  qpsrcw,3	%g18, 0xd, %b[22]
	  qpsrcw,4	%g18, _f16s,_lts0hi 0x16, %b[14]
	  addd,5	0x0, _f64,_lts1 0x2748774c2748774c, %b[25]
	}
	{
	  qpaddw,0	%r17, %g17, %g17
	  qplog_0x96,1	%b[10], %b[8], %r16, %r16
	  addd,2	0x0, _f64,_lts0 0x34b0bcb534b0bcb5, %b[10]
	  qplog_0xe8,3	%g18, %r3, %g29, %b[26]
	  qpsrcw,4	%g18, 0x2, %r17
	  addd,5	0x0, %b[25], %b[8]
	}
	{
	  qpaddw,0	%g27, %g17, %g27
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x13, %b[22]
	  addd,2	0x0, %b[10], %b[27]
	  qpaddw,3	%g20, %r29, %b[14]
	  qplog_0x96,4	%r17, %b[22], %b[14], %r17
	  addd,5	0x0, _f64,_lts1 0x391c0cb3391c0cb3, %b[28]
	}
	{
	  qpsrcw,0	%g27, 0xb, %b[30]
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x19, %b[29]
	  addd,2	0x0, _f64,_lts1 0x4ed8aa4a4ed8aa4a, %b[32]
	  qpaddw,3	%r17, %b[26], %r17
	  qpsrcw,4	%g20, _f16s,_lts0hi 0x11, %b[26]
	  addd,5	0x0, %b[28], %b[31]
	}
	{
	  qplog_0xca,0	%g27, %g23, %g16, %g16
	  qpsrcw,1	%g27, 0x6, %b[33]
	  addd,2	0x0, %b[32], %b[36]
	  qpsrcw,3	%g25, 0x7, %b[34]
	  qpsrlw,4	%g20, 0x3, %b[35]
	  addd,5	0x0, _f64,_lts0 0x5b9cca4f5b9cca4f, %b[37]
	}
	{
	  qpaddw,0	%g27, %r23, %r23
	  qplog_0x96,1	%b[33], %b[30], %b[29], %b[29]
	  addd,2	0x0, _f64,_lts0 0x682e6ff3682e6ff3, %b[23]
	  qpaddw,3	%g17, %r17, %g17
	  qplog_0x96,4	%b[34], %b[23], %b[19], %r17
	  addd,5	0x0, %b[37], %b[19]
	}
	{
	  qpaddw,0	%b[29], %g16, %g16
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x12, %b[33]
	  addd,2	0x0, %b[23], %b[34]
	  qpsrcw,3	%g17, 0xd, %b[30]
	  qpsrcw,4	%g17, _f16s,_lts0hi 0x16, %b[29]
	  addd,5	0x0, _f64,_lts1 0x748f82ee748f82ee, %b[38]
	}
	{
	  qpaddw,0	%r18, %g16, %g16
	  qplog_0x96,1	%b[26], %b[22], %r15, %r15
	  addd,2	0x0, _f64,_lts0 0x78a5636f78a5636f, %b[26]
	  qplog_0xe8,3	%g17, %g18, %r3, %b[39]
	  qpsrcw,4	%g17, 0x2, %r18
	  addd,5	0x0, %b[38], %b[22]
	}
	{
	  qpaddw,0	%g29, %g16, %g29
	  qpsrlw,1	%r15, 0xa, %b[29]
	  addd,2	0x0, %b[26], %b[30]
	  qpaddw,3	%r38, %r16, %r16
	  qplog_0x96,4	%r18, %b[30], %b[29], %r18
	  addd,5	0x0, _f64,_lts0 0x84c8781484c87814, %b[40]
	}
	{
	  qpsrcw,0	%g29, 0xb, %b[42]
	  qpsrcw,1	%g29, _f16s,_lts0lo 0x19, %b[41]
	  addd,2	0x0, _f64,_lts1 0x8cc702088cc70208, %b[44]
	  qpaddw,3	%r18, %b[39], %r18
	  qpsrlw,4	%r16, 0xa, %b[39]
	  addd,5	0x0, %b[40], %b[43]
	}
	{
	  qplog_0xca,0	%g29, %g27, %g23, %g23
	  qpsrcw,1	%g29, 0x6, %b[45]
	  addd,2	0x0, %b[44], %b[48]
	  qpaddw,3	%r16, %r34, %b[46]
	  qpsrcw,4	%r16, _f16s,_lts0lo 0x13, %b[47]
	  addd,5	0x0, _f64,_lts1 0x90befffa90befffa, %b[49]
	}
	{
	  qpaddw,0	%g29, %r61, %r61
	  qplog_0x96,1	%b[45], %b[42], %b[41], %b[41]
	  addd,2	0x0, _f64,_lts1 0xa4506ceba4506ceb, %b[45]
	  qpaddw,3	%g16, %r18, %g16
	  qpsrcw,4	%r16, _f16s,_lts0lo 0x11, %r18
	  addd,5	0x0, %b[49], %b[42]
	}
	{
	  qpaddw,0	%b[41], %g23, %g23
	  qpsrcw,1	%r15, _f16s,_lts0lo 0x13, %b[51]
	  addd,2	0x0, %b[45], %b[52]
	  qpsrcw,3	%g16, 0xd, %b[50]
	  qpsrcw,4	%g16, _f16s,_lts0hi 0x16, %b[41]
	  addd,5	0x0, _f64,_lts1 0xbef9a3f7bef9a3f7, %b[53]
	}
	{
	  qpaddw,0	%r19, %g23, %g23
	  qpsrcw,1	%r15, _f16s,_lts0lo 0x11, %b[55]
	  addd,2	0x0, _f64,_lts1 0xc67178f2c67178f2, %b[57]
	  qplog_0xe8,3	%g16, %g17, %g18, %b[54]
	  qpsrcw,4	%g16, 0x2, %r19
	  addd,5	0x0, %b[53], %b[56]
	}
	{
	  qpaddw,0	%r3, %g23, %r3
	  qplog_0x96,1	%b[55], %b[51], %b[29], %b[29]
	  addd,2	0x0, %b[57], %b[50]
	  qpaddw,3	%r15, %r40, %b[41]
	  qplog_0x96,4	%r19, %b[50], %b[41], %r19
	  addd,5	0x0, _f64,_lts0 0x510e527f510e527f, %b[51]
	}
	{
	  qpsrcw,0	%r3, 0xb, %b[58]
	  qpsrcw,1	%r3, _f16s,_lts0lo 0x19, %b[55]
	  addd,2	0x0, _f64,_lts1 0x1f83d9ab1f83d9ab, %b[39]
	  qpaddw,3	%r19, %b[54], %r19
	  qplog_0x96,4	%r18, %b[47], %b[39], %r18
	  addd,5	0x0, %b[51], %b[47]
	}
	{
	  qplog_0xca,0	%r3, %g29, %g27, %g27
	  qpsrcw,1	%r3, 0x6, %b[54]
	  addd,2	0x0, _f64,_lts0 0x9b05688c9b05688c, %b[60]
	  qpaddw,3	%r41, %r18, %r18
	  qpsrcw,4	%g20, 0x7, %b[59]
	  addd,5	0x0, _f64,_lts2 0x9e6afcb19e6afcb1, %b[61]
	}
	{
	  qpaddw,0	%r3, %r52, %r52
	  qplog_0x96,1	%b[54], %b[58], %b[55], %b[54]
	  addd,2	0x0, %b[39], %b[55]
	  qpaddw,3	%g23, %r19, %g23
	  qpsrlw,4	%r18, 0xa, %r19
	  addd,5	0x0, %b[61], %b[58]
	}
	{
	  qpaddw,0	%b[54], %g27, %g27
	  qpsrlw,1	%r16, 0x3, %b[63]
	  addd,2	0x0, %b[60], %b[64]
	  qpsrcw,3	%g23, 0xd, %b[62]
	  qpsrcw,4	%g23, _f16s,_lts0lo 0x16, %b[54]
	  addd,5	0x0, _f64,_lts1 0xa54ff53aa54ff53a, %b[65]
	}
	{
	  qpaddw,0	%r22, %g27, %g27
	  qpsrcw,1	%r16, _f16s,_lts0lo 0x12, %b[67]
	  addd,2	0x0, _f64,_lts1 0x7137449171374491, %b[69]
	  qplog_0xe8,3	%g23, %g16, %g17, %b[66]
	  qpsrcw,4	%g23, 0x2, %r22
	  addd,5	0x0, %b[65], %b[68]
	}
	{
	  qpaddw,0	%g18, %g27, %g18
	  qpsrcw,1	%r18, _f16s,_lts0lo 0x13, %b[62]
	  addd,2	0x0, %b[69], %b[70]
	  qpaddw,3	%r18, %g24, %b[54]
	  qplog_0x96,4	%r22, %b[62], %b[54], %r22
	  addd,5	0x0, _f64,_lts1 0x3c6ef3723c6ef372, %b[71]
	}
	{
	  qpsrcw,0	%g18, 0xb, %b[73]
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %b[72]
	  addd,2	0x0, _f64,_lts1 0xb5c0fbcfb5c0fbcf, %b[75]
	  qpaddw,3	%r22, %b[66], %r22
	  qpsrcw,4	%r18, _f16s,_lts0hi 0x11, %b[66]
	  addd,5	0x0, %b[71], %b[74]
	}
	{
	  qplog_0xca,0	%g18, %r3, %g29, %g29
	  qpsrcw,1	%g18, 0x6, %b[76]
	  addd,2	0x0, %b[75], %b[35]
	  qpaddw,3	%r45, %b[29], %b[29]
	  qplog_0x96,4	%b[59], %b[33], %b[35], %b[33]
	  addd,5	0x0, _f64,_lts0 0xbb67ae85bb67ae85, %b[59]
	}
	{
	  qpaddw,0	%g18, %b[3], %b[3]
	  qplog_0x96,1	%b[76], %b[73], %b[72], %b[72]
	  ldqp,2	%r2, _f16s,_lts0lo 0x30, %b[73]
	  qpaddw,3	%g27, %r22, %g27
	  qpsrlw,4	%b[29], 0xa, %r22
	  addd,5	0x0, %b[59], %b[76]
	}
	{
	  qpaddw,0	%b[72], %g29, %g29
	  qpsrcw,1	%r16, 0x7, %b[78]
	  addd,2	0x0, _f64,_lts1 0x6a09e6676a09e667, %b[79]
	  qpsrcw,3	%g27, 0xd, %b[77]
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x16, %b[72]
	  ldqp,5	%r2, _f16s,_lts0hi 0x40, %b[80]
	}
	{
	  qpaddw,0	%r23, %g29, %g29
	  qplog_0x96,1	%b[66], %b[62], %r19, %r19
	  addd,2	0x0, %b[79], %b[62]
	  qplog_0xe8,3	%g27, %g23, %g16, %b[81]
	  qpsrcw,4	%g27, 0x2, %r23
	  ldqp,5	%r2, _f16s,_lts0lo 0x50, %b[66]
	}
	{
	  qpaddw,0	%g17, %g29, %g17
	  qpsrcw,1	%b[29], _f16s,_lts0lo 0x13, %b[77]
	  ldqp,2	%r2, _f16s,_lts0hi 0x60, %b[82]
	  qpaddw,3	%b[29], %r39, %b[72]
	  qplog_0x96,4	%r23, %b[77], %b[72], %r23
	  ldqp,5	%r2, _f16s,_lts1lo 0x70, %r2
	}
	{
	  qpsrcw,0	%g17, 0xb, %b[84]
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x19, %b[83]
	  addd,2	0x0, _f64,_lts2 0x8000000080000000, %b[85]
	  qpaddw,3	%r23, %b[81], %r23
	  qpsrcw,4	%b[29], _f16s,_lts0hi 0x11, %b[81]
	  stqp,5	%r1, _f16s,_lts1lo 0x120, %r30
	}
	{
	  qplog_0xca,0	%g17, %g18, %r3, %r3
	  qpsrcw,1	%g17, 0x6, %r30
	  addd,2	0x0, %b[85], %b[67]
	  qpaddw,3	%r36, %b[29], %b[86]
	  qplog_0x96,4	%b[78], %b[67], %b[63], %b[63]
	  addd,5	0x0, _f64,_lts0 0x10000000100, %b[78]
	}
	{
	  qpaddw,0	%g17, %b[14], %b[14]
	  qplog_0x96,1	%r30, %b[84], %b[83], %r30
	  addd,2	0x0, _f64,_lts0 0xec9fcd13ec9fcd13, %b[84]
	  qpaddw,3	%g29, %r23, %g29
	  qpsrlw,4	%r15, 0x3, %r23
	  addd,5	0x0, %b[78], %b[83]
	}
	{
	  qpaddw,0	%r30, %r3, %r3
	  qpsrcw,1	%r15, _f16s,_lts0lo 0x12, %b[88]
	  addd,2	0x0, %b[84], %b[89]
	  qpsrcw,3	%g29, 0xd, %b[87]
	  qpsrcw,4	%g29, _f16s,_lts0hi 0x16, %r30
	  stqp,5	%r1, _f16s,_lts1lo 0x130, %r32
	}
	{
	  qpaddw,0	%r61, %r3, %r3
	  qplog_0x96,1	%b[81], %b[77], %r22, %r22
	  stqp,2	%r1, _f16s,_lts0lo 0x140, %r38
	  qplog_0xe8,3	%g29, %g27, %g23, %r61
	  qpsrcw,4	%g29, 0x2, %r32
	  stqp,5	%r1, _f16s,_lts0hi 0x160, %r41
	}
	{
	  qpaddw,0	%g16, %r3, %g16
	  qpsrcw,1	%r15, 0x7, %r32
	  stqp,2	%r1, _f16s,_lts0lo 0x170, %r45
	  qpaddw,3	%r42, %r19, %r19
	  qplog_0x96,4	%r32, %b[87], %r30, %r30
	  stqp,5	%r1, _f16s,_lts0hi 0x180, %r42
	}
	{
	  qpsrcw,0	%g16, 0xb, %r41
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x19, %r38
	  stqp,2	%r1, _f16s,_lts0hi 0x1e0, %r36
	  qpaddw,3	%r30, %r61, %r30
	  qpsrlw,4	%r19, 0xa, %r42
	  stqp,5	%r1, _f16s,_lts1lo 0x1f0, %r54
	}
	{
	  qplog_0xca,0	%g16, %g17, %g18, %g18
	  qpsrcw,1	%g16, 0x6, %r36
	  stqp,2	%r1, _f16s,_lts0hi 0x150, %r15
	  qpaddw,3	%r19, %r35, %r45
	  qpsrcw,4	%r19, _f16s,_lts0lo 0x13, %r61
	}
	{
	  qpaddw,0	%g16, %b[46], %r38
	  qplog_0x96,1	%r36, %r41, %r38, %r36
	  qpaddw,3	%r3, %r30, %r3
	  qpsrcw,4	%r19, _f16s,_lts0lo 0x11, %r30
	}
	{
	  qpaddw,0	%r36, %g18, %g18
	  qplog_0x96,1	%r32, %b[88], %r23, %r23
	  qpsrcw,3	%r3, 0xd, %r41
	  qpsrcw,4	%r3, _f16s,_lts0lo 0x16, %r36
	}
	{
	  qpaddw,0	%r52, %g18, %g18
	  qpsrlw,1	%r18, 0x3, %b[46]
	  qplog_0xe8,3	%r3, %g29, %g27, %r52
	  qpsrcw,4	%r3, 0x2, %r32
	}
	{
	  qpaddw,0	%g23, %g18, %g23
	  qpsrcw,1	%r18, _f16s,_lts0lo 0x12, %r36
	  qpaddw,3	%r22, %g25, %r22
	  qplog_0x96,4	%r32, %r41, %r36, %r32
	}
	{
	  qpsrcw,0	%g23, 0xb, %b[77]
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x19, %r41
	  qpaddw,3	%r32, %r52, %r32
	  qplog_0x96,4	%r30, %r61, %r42, %r30
	  stqp,5	%r1, _f16s,_lts0hi 0x190, %r22
	}
	{
	  qplog_0xca,0	%g23, %g16, %g17, %g17
	  qpsrcw,1	%g23, 0x6, %r42
	  qpaddw,3	%r22, %r28, %r52
	  qpsrlw,4	%r22, 0xa, %r61
	}
	{
	  qpaddw,0	%g23, %b[41], %r42
	  qplog_0x96,1	%r42, %b[77], %r41, %r41
	  qpaddw,3	%g18, %r32, %g18
	  qpsrcw,4	%r22, _f16s,_lts0lo 0x13, %r32
	}
	{
	  qpaddw,0	%r41, %g17, %g17
	  qpsrcw,1	%r22, _f16s,_lts0hi 0x11, %b[77]
	  qpsrcw,3	%g18, 0xd, %b[41]
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r41
	}
	{
	  qpaddw,0	%b[3], %g17, %g17
	  qpsrcw,1	%r18, 0x7, %b[87]
	  qplog_0xe8,3	%g18, %r3, %g29, %b[81]
	  qpsrcw,4	%g18, 0x2, %b[3]
	}
	{
	  qpaddw,0	%g27, %g17, %g27
	  qplog_0x96,1	%b[87], %r36, %b[46], %r36
	  qpaddw,3	%r30, %g20, %r30
	  qplog_0x96,4	%b[3], %b[41], %r41, %r41
	}
	{
	  qpsrcw,0	%g27, 0xb, %b[41]
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x19, %b[3]
	  qpaddw,3	%r41, %b[81], %r41
	  qpsrlw,4	%r30, 0xa, %b[46]
	  stqp,5	%r1, _f16s,_lts0hi 0x1a0, %r30
	}
	{
	  qplog_0xca,0	%g27, %g23, %g16, %g16
	  qpsrcw,1	%g27, 0x6, %b[81]
	  qpaddw,3	%r30, %r37, %b[87]
	  qplog_0x96,4	%b[77], %r32, %r61, %r32
	}
	{
	  qpaddw,0	%g27, %b[54], %b[3]
	  qplog_0x96,1	%b[81], %b[41], %b[3], %r61
	  qpaddw,3	%g17, %r41, %g17
	  qpsrcw,4	%r30, _f16s,_lts0lo 0x13, %r41
	}
	{
	  qpaddw,0	%r61, %g16, %g16
	  qpsrcw,1	%r30, _f16s,_lts0hi 0x11, %b[54]
	  qpsrcw,3	%g17, 0xd, %b[41]
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x16, %r61
	}
	{
	  qpaddw,0	%b[14], %g16, %g16
	  qpsrlw,1	%b[29], 0x3, %b[81]
	  qplog_0xe8,3	%g17, %g18, %r3, %b[77]
	  qpsrcw,4	%g17, 0x2, %b[14]
	}
	{
	  qpaddw,0	%g29, %g16, %g29
	  qpsrcw,1	%b[29], _f16s,_lts0lo 0x12, %b[14]
	  qpaddw,3	%r32, %r16, %r32
	  qplog_0x96,4	%b[14], %b[41], %r61, %r61
	}
	{
	  qpsrcw,0	%g29, 0xb, %b[88]
	  qpsrcw,1	%g29, _f16s,_lts0lo 0x19, %b[41]
	  qpaddw,3	%r61, %b[77], %r61
	  qpsrlw,4	%r32, 0xa, %b[77]
	  stqp,5	%r1, _f16s,_lts0hi 0x1b0, %r32
	}
	{
	  qplog_0xca,0	%g29, %g27, %g23, %g23
	  qpsrcw,1	%g29, 0x6, %b[90]
	  qpaddw,3	%r32, %r43, %b[91]
	  qplog_0x96,4	%b[54], %r41, %b[46], %r41
	}
	{
	  qpaddw,0	%g29, %b[72], %b[46]
	  qplog_0x96,1	%b[90], %b[88], %b[41], %b[41]
	  qpaddw,3	%g16, %r61, %g16
	  qpsrcw,4	%r32, _f16s,_lts0lo 0x13, %r61
	}
	{
	  qpaddw,0	%b[41], %g23, %g23
	  qpsrcw,1	%r32, _f16s,_lts0hi 0x11, %b[72]
	  qpsrcw,3	%g16, 0xd, %b[54]
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x16, %b[41]
	}
	{
	  qpaddw,0	%r38, %g23, %g23
	  qpsrcw,1	%b[29], 0x7, %b[90]
	  qplog_0xe8,3	%g16, %g17, %g18, %b[88]
	  qpsrcw,4	%g16, 0x2, %r38
	}
	{
	  qpaddw,0	%r3, %g23, %r3
	  qplog_0x96,1	%b[90], %b[14], %b[81], %b[14]
	  qpaddw,3	%r41, %r15, %r41
	  qplog_0x96,4	%r38, %b[54], %b[41], %r38
	}
	{
	  qpsrcw,0	%r3, 0xb, %b[54]
	  qpsrcw,1	%r3, _f16s,_lts0lo 0x19, %b[41]
	  qpaddw,3	%r38, %b[88], %r38
	  qpsrlw,4	%r41, 0xa, %b[81]
	  stqp,5	%r1, _f16s,_lts0hi 0x1c0, %r41
	}
	{
	  qplog_0xca,0	%r3, %g29, %g27, %g27
	  qpsrcw,1	%r3, 0x6, %b[88]
	  qpaddw,3	%r41, %r7, %b[90]
	  qplog_0x96,4	%b[72], %r61, %b[77], %r61
	}
	{
	  qpaddw,0	%r3, %r45, %r45
	  qplog_0x96,1	%b[88], %b[54], %b[41], %b[41]
	  qpaddw,3	%g23, %r38, %g23
	  qpsrcw,4	%r41, _f16s,_lts0lo 0x13, %r38
	}
	{
	  qpaddw,0	%b[41], %g27, %g27
	  qpsrcw,1	%r41, _f16s,_lts0hi 0x11, %b[72]
	  qpsrcw,3	%g23, 0xd, %b[54]
	  qpsrcw,4	%g23, _f16s,_lts0lo 0x16, %b[41]
	}
	{
	  qpaddw,0	%r42, %g27, %g27
	  qppackdl,1	%r50, %b[2], %r50
	  qplog_0xe8,3	%g23, %g16, %g17, %b[77]
	  qpsrcw,4	%g23, 0x2, %r42
	}
	{
	  qpaddw,0	%g18, %g27, %g18
	  qpsrlw,1	%r19, 0x3, %b[2]
	  qpaddw,3	%r61, %r18, %r61
	  qplog_0x96,4	%r42, %b[54], %b[41], %r42
	}
	{
	  qpsrcw,0	%g18, 0xb, %b[54]
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %b[41]
	  qpaddw,3	%r42, %b[77], %r42
	  qpsrlw,4	%r61, 0xa, %b[77]
	  stqp,5	%r1, _f16s,_lts0hi 0x1d0, %r61
	}
	{
	  qplog_0xca,0	%g18, %r3, %g29, %g29
	  qpsrcw,1	%g18, 0x6, %b[88]
	  qpaddw,3	%r61, %r46, %b[92]
	  qplog_0x96,4	%b[72], %r38, %b[81], %r38
	}
	{
	  qpaddw,0	%g18, %r52, %r52
	  qplog_0x96,1	%b[88], %b[54], %b[41], %b[41]
	  qpaddw,3	%g27, %r42, %g27
	  qpsrcw,4	%r61, _f16s,_lts0lo 0x13, %r42
	}
	{
	  qpaddw,0	%b[41], %g29, %g29
	  qpsrcw,1	%r61, _f16s,_lts0hi 0x11, %b[72]
	  qpsrcw,3	%g27, 0xd, %b[54]
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x16, %b[41]
	}
	{
	  qpaddw,0	%b[3], %g29, %g29
	  qpsrcw,1	%r19, _f16s,_lts0lo 0x12, %b[88]
	  qplog_0xe8,3	%g27, %g23, %g16, %b[81]
	  qpsrcw,4	%g27, 0x2, %b[3]
	}
	{
	  qpaddw,0	%g17, %g29, %g17
	  qpsrcw,1	%r19, 0x7, %b[41]
	  qpaddw,3	%b[86], %r38, %r38
	  qplog_0x96,4	%b[3], %b[54], %b[41], %b[3]
	}
	{
	  qpsrcw,0	%g17, 0xb, %b[86]
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x19, %b[54]
	  qpaddw,3	%b[3], %b[81], %b[3]
	  qpsrlw,4	%r38, 0xa, %b[81]
	}
	{
	  qplog_0xca,0	%g17, %g18, %r3, %r3
	  qpsrcw,1	%g17, 0x6, %b[93]
	  qpaddw,3	%r38, %r48, %b[94]
	  qplog_0x96,4	%b[72], %r42, %b[77], %r42
	}
	{
	  qpaddw,0	%g17, %b[87], %b[72]
	  qplog_0x96,1	%b[93], %b[86], %b[54], %b[54]
	  qpaddw,3	%g29, %b[3], %g29
	  qpsrcw,4	%r38, _f16s,_lts0lo 0x13, %b[3]
	}
	{
	  qpaddw,0	%b[54], %r3, %r3
	  qpsrcw,1	%r38, _f16s,_lts0hi 0x11, %b[86]
	  qpsrcw,3	%g29, 0xd, %b[77]
	  qpsrcw,4	%g29, _f16s,_lts0lo 0x16, %b[54]
	}
	{
	  qpaddw,0	%b[46], %r3, %r3
	  qplog_0x96,1	%b[41], %b[88], %b[2], %b[2]
	  qplog_0xe8,3	%g29, %g27, %g23, %b[87]
	  qpsrcw,4	%g29, 0x2, %b[46]
	}
	{
	  qpaddw,0	%g16, %r3, %g16
	  qppackdl,1	%r56, %b[4], %r56
	  qpaddw,3	%r54, %r19, %r54
	  qplog_0x96,4	%b[46], %b[77], %b[54], %b[41]
	}
	{
	  qpsrcw,0	%g16, 0xb, %b[46]
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x19, %b[4]
	  qpaddw,3	%b[41], %b[87], %b[41]
	  qpsrlw,4	%r22, 0x3, %b[54]
	}
	{
	  qplog_0xca,0	%g16, %g17, %g18, %g18
	  qpsrcw,1	%g16, 0x6, %b[77]
	  qpaddw,3	%r54, %r42, %r42
	  qplog_0x96,4	%b[86], %b[3], %b[81], %r54
	}
	{
	  qpaddw,0	%g16, %b[91], %b[4]
	  qplog_0x96,1	%b[77], %b[46], %b[4], %b[3]
	  qpaddw,3	%r3, %b[41], %r3
	  qpsrlw,4	%r42, 0xa, %b[41]
	}
	{
	  qpaddw,0	%b[3], %g18, %g18
	  qpsrcw,1	%r22, _f16s,_lts0hi 0x12, %b[77]
	  qpsrcw,3	%r3, 0xd, %b[46]
	  qpsrcw,4	%r3, _f16s,_lts0lo 0x16, %b[3]
	}
	{
	  qpaddw,0	%r45, %g18, %g18
	  qpsrcw,1	%r22, 0x7, %b[86]
	  qplog_0xe8,3	%r3, %g29, %g27, %b[81]
	  qpsrcw,4	%r3, 0x2, %r45
	}
	{
	  qpaddw,0	%g23, %g18, %g23
	  qpsrcw,1	%r42, _f16s,_lts0lo 0x13, %b[46]
	  qpaddw,3	%r42, %r44, %b[3]
	  qplog_0x96,4	%r45, %b[46], %b[3], %r45
	}
	{
	  qpsrcw,0	%g23, 0xb, %b[88]
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x19, %b[87]
	  qpaddw,3	%r45, %b[81], %r45
	  qpsrcw,4	%r42, _f16s,_lts0hi 0x11, %b[81]
	}
	{
	  qplog_0xca,0	%g23, %g16, %g17, %g17
	  qpsrcw,1	%g23, 0x6, %b[91]
	  qpaddw,3	%r33, %r22, %r33
	  qppackdl,4	%r55, %b[1], %r55
	}
	{
	  qpaddw,0	%g23, %b[90], %b[87]
	  qplog_0x96,1	%b[91], %b[88], %b[87], %b[1]
	  qpaddw,3	%g18, %r45, %g18
	  qplog_0x96,4	%b[86], %b[77], %b[54], %r45
	}
	{
	  qpaddw,0	%b[1], %g17, %g17
	  qpsrlw,1	%r30, 0x3, %b[77]
	  qpsrcw,3	%g18, 0xd, %b[54]
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %b[1]
	}
	{
	  qpaddw,0	%r52, %g17, %g17
	  qplog_0x96,1	%b[81], %b[46], %b[41], %b[41]
	  qplog_0xe8,3	%g18, %r3, %g29, %b[86]
	  qpsrcw,4	%g18, 0x2, %r52
	}
	{
	  qpaddw,0	%g27, %g17, %g27
	  qpsrcw,1	%r30, _f16s,_lts0lo 0x12, %r54
	  qpaddw,3	%r12, %r54, %r12
	  qplog_0x96,4	%r52, %b[54], %b[1], %r52
	}
	{
	  qpsrcw,0	%g27, 0xb, %b[46]
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x19, %b[1]
	  qpaddw,3	%r52, %b[86], %r52
	  qpsrcw,4	%r30, 0x7, %b[54]
	}
	{
	  qplog_0xca,0	%g27, %g23, %g16, %g16
	  qpsrcw,1	%g27, 0x6, %b[81]
	  qpaddw,3	%r33, %r12, %r12
	  qppackdl,4	%r63, %r62, %r33
	}
	{
	  qpaddw,0	%g27, %b[92], %r63
	  qplog_0x96,1	%b[81], %b[46], %b[1], %r62
	  qpaddw,3	%g17, %r52, %g17
	  qpsrlw,4	%r12, 0xa, %r52
	  stqp,5	%r1, _f16s,_lts0lo 0x200, %r12
	}
	{
	  qpaddw,0	%r62, %g16, %g16
	  qpsrlw,1	%r32, 0x3, %b[46]
	  qpsrcw,3	%g17, 0xd, %b[1]
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x16, %r62
	}
	{
	  qpaddw,0	%b[72], %g16, %g16
	  qplog_0x96,1	%b[54], %r54, %b[77], %r54
	  qplog_0xe8,3	%g17, %g18, %r3, %b[81]
	  qpsrcw,4	%g17, 0x2, %b[72]
	}
	{
	  qpaddw,0	%g29, %g16, %g29
	  qpsrcw,1	%r12, _f16s,_lts0lo 0x13, %b[54]
	  qpaddw,3	%r12, %r51, %b[1]
	  qplog_0x96,4	%b[72], %b[1], %r62, %r62
	}
	{
	  qpsrcw,0	%g29, 0xb, %b[77]
	  qpsrcw,1	%g29, _f16s,_lts0lo 0x19, %b[72]
	  qpaddw,3	%r62, %b[81], %r62
	  qpsrcw,4	%r12, _f16s,_lts0hi 0x11, %b[81]
	}
	{
	  qplog_0xca,0	%g29, %g27, %g23, %g23
	  qpsrcw,1	%g29, 0x6, %b[86]
	  qpaddw,3	%r31, %r30, %r31
	  qpsrcw,4	%r32, _f16s,_lts0lo 0x12, %b[88]
	}
	{
	  qpaddw,0	%g29, %b[94], %b[77]
	  qplog_0x96,1	%b[86], %b[77], %b[72], %b[72]
	  qpaddw,3	%g16, %r62, %g16
	  qpsrcw,4	%r32, 0x7, %r62
	}
	{
	  qpaddw,0	%b[72], %g23, %g23
	  qppackdl,1	%b[5], %b[7], %b[5]
	  qpsrcw,3	%g16, 0xd, %b[86]
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x16, %b[72]
	}
	{
	  qpaddw,0	%b[4], %g23, %g23
	  qplog_0x96,1	%b[81], %b[54], %r52, %r52
	  qplog_0xe8,3	%g16, %g17, %g18, %b[7]
	  qpsrcw,4	%g16, 0x2, %b[4]
	}
	{
	  qpaddw,0	%r3, %g23, %r3
	  qpsrlw,1	%r41, 0x3, %b[41]
	  qpaddw,3	%r17, %b[41], %r17
	  qplog_0x96,4	%b[4], %b[86], %b[72], %b[4]
	}
	{
	  qpsrcw,0	%r3, 0xb, %b[72]
	  qpsrcw,1	%r3, _f16s,_lts0lo 0x19, %b[54]
	  qpaddw,3	%b[4], %b[7], %b[4]
	  qplog_0x96,4	%r62, %b[88], %b[46], %r62
	}
	{
	  qplog_0xca,0	%r3, %g29, %g27, %g27
	  qpsrcw,1	%r3, 0x6, %b[7]
	  qpaddw,3	%r31, %r17, %r17
	  qpsrcw,4	%r41, _f16s,_lts0lo 0x12, %r31
	}
	{
	  qpaddw,0	%r3, %b[3], %b[3]
	  qplog_0x96,1	%b[7], %b[72], %b[54], %b[7]
	  qpaddw,3	%g23, %b[4], %g23
	  qpsrlw,4	%r17, 0xa, %b[4]
	  stqp,5	%r1, _f16s,_lts0lo 0x210, %r17
	}
	{
	  qpaddw,0	%b[7], %g27, %g27
	  qpsrcw,1	%r41, 0x7, %b[54]
	  qpsrcw,3	%g23, 0xd, %b[46]
	  qpsrcw,4	%g23, _f16s,_lts0lo 0x16, %b[7]
	}
	{
	  qpaddw,0	%b[87], %g27, %g27
	  qppackdl,1	%b[0], %b[6], %b[0]
	  qplog_0xe8,3	%g23, %g16, %g17, %b[81]
	  qpsrcw,4	%g23, 0x2, %b[72]
	}
	{
	  qpaddw,0	%g18, %g27, %g18
	  qpsrcw,1	%r17, _f16s,_lts0lo 0x13, %b[46]
	  qpaddw,3	%r17, %r47, %b[7]
	  qplog_0x96,4	%b[72], %b[46], %b[7], %b[6]
	}
	{
	  qpsrcw,0	%g18, 0xb, %b[86]
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %b[72]
	  qpaddw,3	%b[6], %b[81], %b[6]
	  qpsrcw,4	%r17, _f16s,_lts0hi 0x11, %b[81]
	}
	{
	  qplog_0xca,0	%g18, %r3, %g29, %g29
	  qpsrcw,1	%g18, 0x6, %b[87]
	  qpaddw,3	%g25, %r32, %g25
	  qplog_0x96,4	%b[54], %r31, %b[41], %r31
	}
	{
	  qpaddw,0	%g18, %b[1], %b[1]
	  qplog_0x96,1	%b[87], %b[86], %b[72], %b[41]
	  qpaddw,3	%g27, %b[6], %g27
	  qpsrlw,4	%r61, 0x3, %b[6]
	}
	{
	  qpaddw,0	%b[41], %g29, %g29
	  qpsrcw,1	%r61, _f16s,_lts0hi 0x12, %b[72]
	  qpsrcw,3	%g27, 0xd, %b[54]
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x16, %b[41]
	}
	{
	  qpaddw,0	%r63, %g29, %g29
	  qplog_0x96,1	%b[81], %b[46], %b[4], %b[4]
	  qplog_0xe8,3	%g27, %g23, %g16, %b[86]
	  qpsrcw,4	%g27, 0x2, %r63
	}
	{
	  qpaddw,0	%g17, %g29, %g17
	  qpsrcw,1	%r61, 0x7, %b[33]
	  qpaddw,3	%b[33], %r52, %r52
	  qplog_0x96,4	%r63, %b[54], %b[41], %r63
	}
	{
	  qpsrcw,0	%g17, 0xb, %b[46]
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x19, %b[41]
	  qpaddw,3	%r63, %b[86], %r63
	  qppackdl,4	%r60, %b[9], %r60
	}
	{
	  qplog_0xca,0	%g17, %g18, %r3, %r3
	  qpsrcw,1	%g17, 0x6, %b[9]
	  qpaddw,3	%g25, %r52, %g25
	  qpsrlw,4	%r38, 0x3, %r52
	}
	{
	  qpaddw,0	%g17, %b[7], %b[7]
	  qplog_0x96,1	%b[9], %b[46], %b[41], %b[9]
	  qpaddw,3	%g29, %r63, %g29
	  qpsrlw,4	%g25, 0xa, %r63
	  stqp,5	%r1, _f16s,_lts0lo 0x220, %g25
	}
	{
	  qpaddw,0	%b[9], %r3, %r3
	  qplog_0x96,1	%b[33], %b[72], %b[6], %b[6]
	  qpsrcw,3	%g29, 0xd, %b[41]
	  qpsrcw,4	%g29, _f16s,_lts0lo 0x16, %b[9]
	}
	{
	  qpaddw,0	%b[77], %r3, %r3
	  qpsrcw,1	%r38, _f16s,_lts0lo 0x12, %b[54]
	  qpaddw,3	%g25, %r49, %b[46]
	  qpsrcw,4	%g29, 0x2, %b[33]
	}
	{
	  qpaddw,0	%g16, %r3, %g16
	  qpsrcw,1	%g25, _f16s,_lts0lo 0x13, %b[33]
	  qplog_0x96,3	%b[33], %b[41], %b[9], %b[9]
	  qplog_0xe8,4	%g29, %g27, %g23, %b[72]
	}
	{
	  qpsrcw,0	%g16, 0xb, %b[77]
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x19, %b[41]
	  qpaddw,3	%b[9], %b[72], %b[9]
	  qpsrcw,4	%g25, _f16s,_lts0hi 0x11, %b[72]
	}
	{
	  qplog_0xca,0	%g16, %g17, %g18, %g18
	  qpsrcw,1	%g16, 0x6, %b[81]
	  qpaddw,3	%g20, %r41, %g20
	  qpsrcw,4	%r38, 0x7, %b[86]
	}
	{
	  qpaddw,0	%g16, %b[46], %b[46]
	  qplog_0x96,1	%b[81], %b[77], %b[41], %b[41]
	  qpaddw,3	%r3, %b[9], %r3
	  qplog_0x96,4	%b[86], %b[54], %r52, %r52
	}
	{
	  qpaddw,0	%b[41], %g18, %g18
	  qppackdl,1	%b[12], %b[11], %b[11]
	  qpaddw,3	%b[63], %b[4], %b[4]
	  qpsrcw,4	%r3, _f16s,_lts0lo 0x16, %b[9]
	}
	{
	  qpaddw,0	%b[3], %g18, %g18
	  qplog_0x96,1	%b[72], %b[33], %r63, %r63
	  qpaddw,3	%g20, %b[4], %g20
	  qpsrcw,4	%r3, 0xd, %b[3]
	}
	{
	  qpaddw,0	%g23, %g18, %g23
	  qpsrlw,1	%r42, 0x3, %b[33]
	  qpaddw,3	%g20, %r58, %b[12]
	  qpsrcw,4	%r3, 0x2, %b[4]
	  stqp,5	%r1, _f16s,_lts0lo 0x230, %g20
	}
	{
	  qpsrcw,0	%g23, _f16s,_lts0lo 0x19, %b[41]
	  qpsrcw,1	%g23, 0xb, %b[54]
	  qplog_0x96,3	%b[4], %b[3], %b[9], %b[3]
	  qplog_0xe8,4	%r3, %g29, %g27, %b[63]
	}
	{
	  qplog_0xca,0	%g23, %g16, %g17, %g17
	  qpsrcw,1	%g23, 0x6, %b[4]
	  qpaddw,3	%b[3], %b[63], %b[3]
	  qpsrlw,4	%g20, 0xa, %b[9]
	}
	{
	  qpaddw,0	%r16, %r61, %r16
	  qplog_0x96,1	%b[4], %b[54], %b[41], %b[4]
	  qpaddw,3	%g18, %b[3], %g18
	  qpsrcw,4	%g20, _f16s,_lts0lo 0x13, %b[3]
	}
	{
	  qpaddw,0	%b[4], %g17, %g17
	  qpsrcw,1	%g20, _f16s,_lts0hi 0x11, %b[41]
	  qpaddw,3	%g23, %b[12], %b[4]
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %b[12]
	}
	{
	  qpaddw,0	%b[1], %g17, %g17
	  qpsrcw,1	%r42, _f16s,_lts0lo 0x12, %b[1]
	  qpaddw,3	%r23, %r63, %r23
	  qpsrcw,4	%g18, 0xd, %r63
	}
	{
	  qpaddw,0	%g27, %g17, %g27
	  qpsrcw,1	%r42, 0x7, %b[72]
	  qplog_0xe8,3	%g18, %r3, %g29, %b[63]
	  qpsrcw,4	%g18, 0x2, %b[54]
	}
	{
	  qpsrcw,0	%g27, 0xb, %b[81]
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x19, %b[77]
	  qpaddw,3	%r16, %r23, %r16
	  qplog_0x96,4	%b[54], %r63, %b[12], %r23
	}
	{
	  qplog_0xca,0	%g27, %g23, %g16, %g16
	  qpsrcw,1	%g27, 0x6, %r63
	  qpaddw,3	%r16, %r57, %b[12]
	  qplog_0x96,4	%b[41], %b[3], %b[9], %b[3]
	  stqp,5	%r1, _f16s,_lts0lo 0x240, %r16
	}
	{
	  qpaddw,0	%r15, %r38, %r15
	  qplog_0x96,1	%r63, %b[81], %b[77], %r63
	  qpaddw,3	%r23, %b[63], %r23
	  qpsrlw,4	%r16, 0xa, %b[9]
	}
	{
	  qpaddw,0	%r63, %g16, %g16
	  qplog_0x96,1	%b[72], %b[1], %b[33], %b[1]
	  qpaddw,3	%g27, %b[12], %r63
	  qpsrcw,4	%r16, _f16s,_lts0lo 0x13, %b[12]
	}
	{
	  qpaddw,0	%b[7], %g16, %g16
	  qpsrcw,1	%r16, _f16s,_lts0lo 0x11, %r23
	  qpaddw,3	%g17, %r23, %g17
	  qppackdl,4	%b[16], %b[13], %b[7]
	}
	{
	  qpaddw,0	%g29, %g16, %g29
	  qpsrlw,1	%r12, 0x3, %b[13]
	  qpaddw,3	%r36, %b[3], %r36
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x16, %b[3]
	}
	{
	  qpsrcw,0	%g29, 0xb, %b[33]
	  qpsrcw,1	%g29, _f16s,_lts0lo 0x19, %b[16]
	  qpaddw,3	%r15, %r36, %r15
	  qpsrcw,4	%g17, 0xd, %r36
	}
	{
	  qplog_0xca,0	%g29, %g27, %g23, %g23
	  qpsrcw,1	%g29, 0x6, %b[41]
	  qpaddw,3	%r15, %r53, %b[63]
	  qpsrcw,4	%g17, 0x2, %b[54]
	  stqp,5	%r1, _f16s,_lts0lo 0x250, %r15
	}
	{
	  qplog_0xe8,0	%g17, %g18, %r3, %b[33]
	  qplog_0x96,1	%b[41], %b[33], %b[16], %b[16]
	  qplog_0x96,3	%r23, %b[12], %b[9], %r23
	  qplog_0x96,4	%b[54], %r36, %b[3], %r36
	}
	{
	  qpaddw,0	%b[16], %g23, %g23
	  qpsrcw,1	%r12, _f16s,_lts0lo 0x12, %b[12]
	  qpaddw,3	%g29, %b[63], %b[3]
	  qpsrlw,4	%r15, 0xa, %b[9]
	}
	{
	  qpaddw,0	%b[46], %g23, %g23
	  qpsrcw,1	%r15, _f16s,_lts0lo 0x13, %b[16]
	  qpaddw,3	%r18, %r42, %r18
	  qpsrcw,4	%r15, _f16s,_lts0hi 0x11, %b[41]
	}
	{
	  qpaddw,0	%r3, %g23, %r3
	  qpsrcw,1	%r12, 0x7, %b[14]
	  qpaddw,3	%b[14], %r23, %r23
	  qppackdl,4	%b[20], %b[17], %b[17]
	}
	{
	  qpsrcw,0	%r3, 0xb, %b[46]
	  qpsrcw,1	%r3, _f16s,_lts0lo 0x19, %b[20]
	  qpaddw,3	%r36, %b[33], %r36
	  qpsrlw,4	%r17, 0x3, %b[33]
	}
	{
	  qplog_0xca,0	%r3, %g29, %g27, %g27
	  qpsrcw,1	%r3, 0x6, %b[54]
	  qpaddw,3	%g16, %r36, %g16
	  qpsrcw,4	%r17, _f16s,_lts0lo 0x12, %r36
	}
	{
	  qplog_0x96,0	%b[41], %b[16], %b[9], %b[9]
	  qplog_0x96,1	%b[54], %b[46], %b[20], %b[20]
	  qpaddw,3	%r18, %r23, %r18
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x16, %r23
	}
	{
	  qpaddw,0	%b[20], %g27, %g27
	  qplog_0x96,1	%b[14], %b[12], %b[13], %b[12]
	  qpsrcw,3	%g16, 0x2, %b[20]
	  qpsrcw,4	%g16, 0xd, %b[16]
	  stqp,5	%r1, _f16s,_lts0lo 0x260, %r18
	}
	{
	  qpaddw,0	%b[4], %g27, %g27
	  qpsrcw,1	%r17, 0x7, %b[14]
	  qpaddw,3	%r18, %r50, %b[4]
	  qplog_0xe8,4	%g16, %g17, %g18, %b[13]
	}
	{
	  qpaddw,0	%g18, %g27, %g18
	  qplog_0x96,1	%b[14], %r36, %b[33], %r36
	  qpaddw,3	%r3, %b[4], %b[4]
	  qplog_0x96,4	%b[20], %b[16], %r23, %r23
	}
	{
	  qpsrcw,0	%g18, 0xb, %b[16]
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %b[14]
	  qpaddw,3	%r23, %b[13], %r23
	  qpsrlw,4	%r18, 0xa, %b[13]
	}
	{
	  qplog_0xca,0	%g18, %r3, %g29, %g29
	  qpsrcw,1	%g18, 0x6, %b[20]
	  qpaddw,3	%g23, %r23, %g23
	  qpsrcw,4	%r18, _f16s,_lts0lo 0x13, %r23
	}
	{
	  qpaddw,0	%b[29], %r12, %b[16]
	  qplog_0x96,1	%b[20], %b[16], %b[14], %b[14]
	  qpaddw,3	%b[2], %b[9], %b[2]
	  qpsrcw,4	%g23, _f16s,_lts0lo 0x16, %b[9]
	}
	{
	  qpaddw,0	%b[14], %g29, %g29
	  qpsrcw,1	%r18, _f16s,_lts0lo 0x11, %b[29]
	  qpsrcw,3	%g23, 0x2, %b[20]
	  qpsrcw,4	%g23, 0xd, %b[14]
	}
	{
	  qpaddw,0	%r63, %g29, %g29
	  qppackdl,1	%b[15], %b[21], %b[14]
	  qplog_0x96,3	%b[20], %b[14], %b[9], %b[9]
	  qplog_0xe8,4	%g23, %g16, %g17, %r63
	}
	{
	  qpaddw,0	%g17, %g29, %g17
	  qplog_0x96,1	%b[29], %r23, %b[13], %r23
	  qpaddw,3	%b[9], %r63, %r63
	  qpsrlw,4	%g25, 0x3, %b[9]
	}
	{
	  qpsrcw,0	%g17, 0xb, %b[15]
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x19, %b[13]
	  qpaddw,3	%b[16], %b[2], %b[2]
	  qpsrcw,4	%g25, _f16s,_lts0hi 0x12, %b[16]
	}
	{
	  qplog_0xca,0	%g17, %g18, %r3, %r3
	  qpsrcw,1	%g17, 0x6, %b[20]
	  qpaddw,3	%b[2], %r56, %b[21]
	  qpsrlw,4	%b[2], 0xa, %b[29]
	  stqp,5	%r1, _f16s,_lts0lo 0x270, %b[2]
	}
	{
	  qpaddw,0	%r19, %r17, %r19
	  qplog_0x96,1	%b[20], %b[15], %b[13], %b[13]
	  qpaddw,3	%g18, %b[21], %b[15]
	  qpsrcw,4	%b[2], _f16s,_lts0lo 0x13, %b[20]
	}
	{
	  qpaddw,0	%b[13], %r3, %r3
	  qpsrcw,1	%g25, 0x7, %b[13]
	  qpaddw,3	%g27, %r63, %g27
	  qpsrcw,4	%b[2], _f16s,_lts0lo 0x11, %r63
	}
	{
	  qpaddw,0	%b[3], %r3, %r3
	  qplog_0x96,1	%b[13], %b[16], %b[9], %b[3]
	  qpaddw,3	%r45, %r23, %r23
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x16, %r45
	}
	{
	  qpaddw,0	%g16, %r3, %b[9]
	  qppackdl,1	%b[24], %b[18], %b[18]
	  qpsrcw,3	%g27, 0x2, %b[16]
	  qpsrcw,4	%g27, 0xd, %b[13]
	}
	{
	  qpsrcw,0	%b[9], 0xb, %b[24]
	  qpsrcw,1	%b[9], _f16s,_lts0lo 0x19, %b[21]
	  qpaddw,3	%r19, %r23, %r19
	  qplog_0xe8,4	%g27, %g23, %g16, %g16
	}
	{
	  qplog_0xca,0	%b[9], %g17, %g18, %g18
	  qpsrcw,1	%b[9], 0x6, %r23
	  qpaddw,3	%r19, %r55, %b[33]
	  qplog_0x96,4	%b[16], %b[13], %r45, %r45
	  stqp,5	%r1, _f16s,_lts0lo 0x280, %r19
	}
	{
	  qpaddw,0	%r22, %g25, %r22
	  qplog_0x96,1	%r23, %b[24], %b[21], %r23
	  qpaddw,3	%g17, %b[33], %b[13]
	  qplog_0x96,4	%r63, %b[20], %b[29], %r63
	}
	{
	  qpaddw,0	%r23, %g18, %g18
	  qpsrlw,1	%g20, 0x3, %r45
	  qpaddw,3	%r45, %g16, %g16
	  qpsrlw,4	%r19, 0xa, %r23
	}
	{
	  qpaddw,0	%b[4], %g18, %g18
	  qpsrcw,1	%r19, _f16s,_lts0lo 0x13, %g29
	  qpaddw,3	%g29, %g16, %g16
	  qpsrcw,4	%r19, _f16s,_lts0hi 0x11, %b[4]
	}
	{
	  qpaddw,0	%g23, %g18, %b[16]
	  qpsrcw,1	%g20, _f16s,_lts0hi 0x12, %b[20]
	  qpaddw,3	%r54, %r63, %r54
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x16, %r63
	}
	{
	  qpsrcw,0	%b[16], 0xb, %b[24]
	  qpsrcw,1	%b[16], _f16s,_lts0lo 0x19, %b[21]
	  qpaddw,3	%r22, %r54, %r22
	  qpsrcw,4	%g16, 0xd, %r54
	}
	{
	  qplog_0xca,0	%b[16], %b[9], %g17, %g17
	  qpsrcw,1	%b[16], 0x6, %b[29]
	  qpaddw,3	%r22, %r33, %b[41]
	  qpsrcw,4	%g16, 0x2, %b[33]
	  stqp,5	%r1, _f16s,_lts0lo 0x290, %r22
	}
	{
	  qplog_0xe8,0	%g16, %g27, %g23, %g23
	  qplog_0x96,1	%b[29], %b[24], %b[21], %b[21]
	  qpaddw,3	%b[9], %b[41], %r63
	  qplog_0x96,4	%b[33], %r54, %r63, %r54
	}
	{
	  qpaddw,0	%b[21], %g17, %g17
	  qplog_0x96,1	%b[4], %g29, %r23, %g29
	  qpaddw,3	%r30, %g20, %r23
	  qpsrlw,4	%r22, 0xa, %r30
	}
	{
	  qpaddw,0	%b[15], %g17, %g17
	  qpsrcw,1	%r22, _f16s,_lts0lo 0x13, %b[4]
	  qpaddw,3	%r32, %r16, %r32
	  qpsrcw,4	%r22, _f16s,_lts0hi 0x11, %b[15]
	}
	{
	  qpaddw,0	%g27, %g17, %b[21]
	  qpsrcw,1	%g20, 0x7, %b[24]
	  qpaddw,3	%r41, %r15, %r41
	  qppackdl,4	%b[8], %b[25], %b[8]
	}
	{
	  qpsrcw,0	%b[21], 0xb, %b[29]
	  qpsrcw,1	%b[21], _f16s,_lts0lo 0x19, %b[25]
	  qpaddw,3	%r54, %g23, %g23
	  qpsrlw,4	%r16, 0x3, %r54
	}
	{
	  qplog_0xca,0	%b[21], %b[16], %b[9], %b[9]
	  qpsrcw,1	%b[21], 0x6, %b[33]
	  qpaddw,3	%r3, %g23, %g23
	  qpsrcw,4	%r16, _f16s,_lts0lo 0x12, %r3
	}
	{
	  qpaddw,0	%r62, %g29, %g29
	  qplog_0x96,1	%b[33], %b[29], %b[25], %b[25]
	  qpsrcw,3	%g23, 0xd, %b[29]
	  qpsrcw,4	%g23, _f16s,_lts0lo 0x16, %r62
	}
	{
	  qpaddw,0	%b[25], %b[9], %b[9]
	  qplog_0x96,1	%b[15], %b[4], %r30, %r30
	  qplog_0xe8,3	%g23, %g16, %g27, %g27
	  qpsrcw,4	%g23, 0x2, %b[25]
	}
	{
	  qpaddw,0	%b[13], %b[9], %b[4]
	  qplog_0x96,1	%b[24], %b[20], %r45, %r45
	  qpaddw,3	%r61, %r18, %r61
	  qplog_0x96,4	%b[25], %b[29], %r62, %r62
	}
	{
	  qpaddw,0	%g16, %b[4], %b[9]
	  qpsrcw,1	%r16, 0x7, %r62
	  qpaddw,3	%r62, %g27, %g27
	  qppackdl,4	%b[27], %b[10], %b[10]
	}
	{
	  qpsrcw,0	%b[9], 0xb, %b[15]
	  qpsrcw,1	%b[9], _f16s,_lts0lo 0x19, %b[13]
	  qpaddw,3	%r23, %g29, %g29
	  qpsrlw,4	%r15, 0x3, %r23
	}
	{
	  qplog_0xca,0	%b[9], %b[21], %b[16], %b[24]
	  qpsrcw,1	%b[9], 0x6, %b[20]
	  qpaddw,3	%g29, %b[5], %b[25]
	  qpsrlw,4	%g29, 0xa, %b[27]
	  stqp,5	%r1, _f16s,_lts0lo 0x2a0, %g29
	}
	{
	  qpaddw,0	%r31, %r30, %r30
	  qplog_0x96,1	%b[20], %b[15], %b[13], %b[13]
	  qpaddw,3	%b[16], %b[25], %b[15]
	  qpsrcw,4	%g29, _f16s,_lts0lo 0x13, %r31
	}
	{
	  qpaddw,0	%b[13], %b[24], %b[13]
	  qplog_0x96,1	%r62, %r3, %r54, %r3
	  qpaddw,3	%g18, %g27, %g18
	  qpsrcw,4	%g29, _f16s,_lts0lo 0x11, %g27
	}
	{
	  qpaddw,0	%r63, %b[13], %r54
	  qpsrcw,1	%r15, _f16s,_lts0hi 0x12, %b[13]
	  qpsrcw,3	%g18, 0xd, %r63
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r62
	}
	{
	  qpaddw,0	%g23, %r54, %b[16]
	  qpsrcw,1	%r15, 0x7, %b[24]
	  qplog_0xe8,3	%g18, %g23, %g16, %g16
	  qpsrcw,4	%g18, 0x2, %b[20]
	}
	{
	  qpsrcw,0	%b[16], 0xb, %b[29]
	  qpsrcw,1	%b[16], _f16s,_lts0lo 0x19, %b[25]
	  qpaddw,3	%r32, %r30, %r30
	  qplog_0x96,4	%b[20], %r63, %r62, %r32
	}
	{
	  qplog_0xca,0	%b[16], %b[9], %b[21], %r63
	  qpsrcw,1	%b[16], 0x6, %r62
	  qpaddw,3	%r30, %b[0], %b[20]
	  qplog_0x96,4	%g27, %r31, %b[27], %g27
	  stqp,5	%r1, _f16s,_lts0lo 0x2b0, %r30
	}
	{
	  qpaddw,0	%r38, %b[2], %r38
	  qplog_0x96,1	%r62, %b[29], %b[25], %r31
	  qpaddw,3	%r32, %g16, %g16
	  qpsrlw,4	%r30, 0xa, %r32
	}
	{
	  qpaddw,0	%r31, %r63, %r31
	  qplog_0x96,1	%b[24], %b[13], %r23, %r23
	  qpaddw,3	%b[21], %b[20], %r62
	  qpsrcw,4	%r30, _f16s,_lts0lo 0x13, %r63
	}
	{
	  qpaddw,0	%b[15], %r31, %r31
	  qpsrcw,1	%r30, _f16s,_lts0lo 0x11, %g17
	  qpaddw,3	%g17, %g16, %g16
	  qppackdl,4	%b[31], %b[28], %b[13]
	}
	{
	  qpaddw,0	%g18, %r31, %b[15]
	  qpsrlw,1	%r18, 0x3, %b[20]
	  qpaddw,3	%b[6], %g27, %g27
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x16, %b[6]
	}
	{
	  qpsrcw,0	%b[15], 0xb, %b[24]
	  qpsrcw,1	%b[15], _f16s,_lts0lo 0x19, %b[21]
	  qpaddw,3	%r41, %g27, %g27
	  qpsrcw,4	%g16, 0xd, %r41
	}
	{
	  qplog_0xca,0	%b[15], %b[16], %b[9], %b[27]
	  qpsrcw,1	%b[15], 0x6, %b[25]
	  qpaddw,3	%g27, %r60, %b[29]
	  qpsrcw,4	%g16, 0x2, %b[28]
	  stqp,5	%r1, _f16s,_lts0lo 0x2c0, %g27
	}
	{
	  qplog_0xe8,0	%g16, %g18, %g23, %g23
	  qplog_0x96,1	%b[25], %b[24], %b[21], %b[21]
	  qpaddw,3	%b[9], %b[29], %b[6]
	  qplog_0x96,4	%b[28], %r41, %b[6], %r41
	}
	{
	  qpaddw,0	%b[21], %b[27], %b[9]
	  qplog_0x96,1	%g17, %r63, %r32, %g17
	  qpsrcw,3	%g27, _f16s,_lts0lo 0x13, %r63
	  qpsrlw,4	%g27, 0xa, %r32
	}
	{
	  qpaddw,0	%r62, %b[9], %r62
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x11, %b[9]
	  qpaddw,3	%r42, %r19, %r42
	  qpsrcw,4	%r18, _f16s,_lts0hi 0x12, %b[21]
	}
	{
	  qpaddw,0	%g16, %r62, %b[24]
	  qpsrcw,1	%r18, 0x7, %b[25]
	  qpaddw,3	%r12, %r22, %r12
	  qppackdl,4	%b[36], %b[32], %b[27]
	}
	{
	  qpsrcw,0	%b[24], 0xb, %b[29]
	  qpsrcw,1	%b[24], _f16s,_lts0lo 0x19, %b[28]
	  qpaddw,3	%r41, %g23, %g23
	  qpsrlw,4	%b[2], 0x3, %r41
	}
	{
	  qplog_0xca,0	%b[24], %b[15], %b[16], %b[32]
	  qpsrcw,1	%b[24], 0x6, %b[31]
	  qpaddw,3	%b[4], %g23, %g23
	  qpsrcw,4	%b[2], _f16s,_lts0lo 0x12, %b[4]
	}
	{
	  qpaddw,0	%r52, %g17, %g17
	  qplog_0x96,1	%b[31], %b[29], %b[28], %b[28]
	  qpsrcw,3	%g23, 0xd, %b[29]
	  qpsrcw,4	%g23, _f16s,_lts0lo 0x16, %r52
	}
	{
	  qpaddw,0	%b[28], %b[32], %b[28]
	  qplog_0x96,1	%b[9], %r63, %r32, %r32
	  qplog_0xe8,3	%g23, %g16, %g18, %g18
	  qpsrcw,4	%g23, 0x2, %b[31]
	}
	{
	  qpaddw,0	%b[6], %b[28], %r63
	  qplog_0x96,1	%b[25], %b[21], %b[20], %b[6]
	  qpaddw,3	%r17, %g29, %r17
	  qplog_0x96,4	%b[31], %b[29], %r52, %r52
	}
	{
	  qpaddw,0	%g23, %r63, %b[9]
	  qpsrcw,1	%b[2], 0x7, %r52
	  qpaddw,3	%r52, %g18, %g18
	  qppackdl,4	%b[19], %b[37], %b[19]
	}
	{
	  qpaddw,0	%r61, %g17, %g17
	  qpsrcw,1	%b[9], _f16s,_lts0lo 0x19, %r61
	  qpaddw,3	%r54, %g18, %g18
	  qpsrlw,4	%r19, 0x3, %r54
	}
	{
	  qpsrcw,0	%b[9], 0x6, %b[21]
	  qpsrcw,1	%b[9], 0xb, %b[20]
	  stqp,2	%r1, _f16s,_lts0hi 0x2d0, %g17
	  qpaddw,3	%b[1], %r32, %r32
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %b[1]
	}
	{
	  qpaddw,0	%g17, %b[11], %b[25]
	  qplog_0xca,1	%b[9], %b[24], %b[15], %b[28]
	  qpaddw,3	%r38, %r32, %r32
	  qpsrcw,4	%g18, 0xd, %r38
	}
	{
	  qpaddw,0	%b[16], %b[25], %b[16]
	  qplog_0x96,1	%b[21], %b[20], %r61, %r61
	  qpaddw,3	%r32, %b[7], %b[21]
	  qpsrcw,4	%g18, 0x2, %b[20]
	  stqp,5	%r1, _f16s,_lts0lo 0x2e0, %r32
	}
	{
	  qpaddw,0	%r61, %b[28], %r61
	  qplog_0xe8,1	%g18, %g23, %g16, %g16
	  qpaddw,3	%b[15], %b[21], %b[1]
	  qplog_0x96,4	%b[20], %r38, %b[1], %r38
	}
	{
	  qpaddw,0	%b[16], %r61, %r61
	  qpsrlw,1	%g17, 0xa, %b[15]
	  qpsrcw,3	%g17, _f16s,_lts0hi 0x11, %b[20]
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x13, %b[16]
	}
	{
	  qpaddw,0	%g18, %r61, %b[21]
	  qpsrlw,1	%r32, 0xa, %b[25]
	  qpsrcw,3	%r32, _f16s,_lts0hi 0x11, %b[29]
	  qpsrcw,4	%r32, _f16s,_lts0lo 0x13, %b[28]
	}
	{
	  qpsrcw,0	%b[21], 0xb, %b[32]
	  qpsrcw,1	%b[21], _f16s,_lts0lo 0x19, %b[31]
	  qpaddw,3	%g25, %r30, %g25
	  qplog_0x96,4	%r52, %b[4], %r41, %r41
	}
	{
	  qplog_0xca,0	%b[21], %b[9], %b[24], %b[4]
	  qpsrcw,1	%b[21], 0x6, %r52
	  qpaddw,3	%r38, %g16, %g16
	  qpsrcw,4	%r19, _f16s,_lts0lo 0x12, %r38
	}
	{
	  qpaddw,0	%g20, %g27, %g20
	  qplog_0x96,1	%r52, %b[32], %b[31], %r52
	  qpaddw,3	%r31, %g16, %g16
	  qplog_0x96,4	%b[20], %b[16], %b[15], %r31
	}
	{
	  qpaddw,0	%r52, %b[4], %r52
	  qplog_0x96,1	%b[29], %b[28], %b[25], %b[12]
	  qpaddw,3	%b[12], %r31, %r31
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x16, %b[4]
	}
	{
	  qpaddw,0	%b[1], %r52, %r52
	  qpsrcw,1	%r19, 0x7, %b[1]
	  qpaddw,3	%r42, %r31, %r31
	  qpsrcw,4	%g16, 0xd, %r42
	}
	{
	  qpaddw,0	%r36, %b[12], %r36
	  qplog_0x96,1	%b[1], %r38, %r54, %r38
	  qpaddw,3	%r31, %b[17], %b[16]
	  qpsrcw,4	%g16, 0x2, %b[15]
	  stqp,5	%r1, _f16s,_lts0lo 0x2f0, %r31
	}
	{
	  qpaddw,0	%g16, %r52, %r54
	  qplog_0xe8,1	%g16, %g18, %g23, %g23
	  qpaddw,3	%b[24], %b[16], %b[1]
	  qplog_0x96,4	%b[15], %r42, %b[4], %r42
	}
	{
	  qpsrcw,0	%r54, 0xb, %b[12]
	  qpsrcw,1	%r54, _f16s,_lts0lo 0x19, %b[4]
	  qpsrcw,3	%r31, _f16s,_lts0hi 0x13, %b[16]
	  qpsrlw,4	%r31, 0xa, %b[15]
	}
	{
	  qplog_0xca,0	%r54, %b[21], %b[9], %b[24]
	  qpsrcw,1	%r54, 0x6, %b[20]
	  qpaddw,3	%r16, %g17, %r16
	  qpsrcw,4	%r31, _f16s,_lts0lo 0x11, %b[25]
	}
	{
	  qpaddw,0	%r12, %r36, %r12
	  qplog_0x96,1	%b[20], %b[12], %b[4], %b[4]
	  qpaddw,3	%r15, %r32, %r15
	  qplog_0x96,4	%b[25], %b[16], %b[15], %r36
	}
	{
	  qpaddw,0	%r42, %g23, %g23
	  qpsrlw,1	%r12, 0xa, %r42
	  stqp,2	%r1, _f16s,_lts0lo 0x300, %r12
	  qpaddw,3	%b[3], %r36, %r36
	  qppackdl,4	%b[34], %b[23], %b[3]
	}
	{
	  qpaddw,0	%b[4], %b[24], %b[4]
	  qpsrcw,1	%r12, _f16s,_lts0lo 0x13, %r36
	  qpaddw,3	%r17, %r36, %r17
	  qpsrlw,4	%r22, 0x3, %b[12]
	}
	{
	  qpaddw,0	%r62, %g23, %g23
	  qpsrcw,1	%r12, _f16s,_lts0lo 0x11, %b[15]
	  qpaddw,3	%r17, %b[18], %r62
	  qpsrlw,4	%r17, 0xa, %b[16]
	  stqp,5	%r1, _f16s,_lts0hi 0x310, %r17
	}
	{
	  qpaddw,0	%b[1], %b[4], %b[1]
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x16, %b[4]
	  qpaddw,3	%r12, %b[14], %b[20]
	  qpsrcw,4	%r17, _f16s,_lts0hi 0x13, %b[23]
	}
	{
	  qpaddw,0	%g23, %b[1], %b[24]
	  qpsrcw,1	%g23, 0xd, %b[25]
	  qpaddw,3	%b[9], %b[20], %b[9]
	  qpsrcw,4	%r17, _f16s,_lts0lo 0x11, %b[20]
	}
	{
	  qpsrcw,0	%g23, 0x2, %b[28]
	  qpsrcw,1	%b[24], _f16s,_lts0lo 0x19, %b[29]
	  qpaddw,3	%b[21], %r62, %r62
	  qplog_0x96,4	%b[20], %b[23], %b[16], %b[16]
	}
	{
	  qpsrcw,0	%b[24], 0xb, %b[20]
	  qpsrcw,1	%b[24], 0x6, %b[23]
	  qplog_0x96,3	%b[15], %r36, %r42, %r36
	  qplog_0xe8,4	%g23, %g16, %g18, %g18
	}
	{
	  qplog_0xca,0	%b[24], %r54, %b[21], %b[4]
	  qplog_0x96,1	%b[28], %b[25], %b[4], %r42
	  qpaddw,3	%r45, %r36, %r36
	  qpsrcw,4	%r22, _f16s,_lts0lo 0x12, %r45
	}
	{
	  qpaddw,0	%r18, %r31, %r18
	  qplog_0x96,1	%b[23], %b[20], %b[29], %b[15]
	  qpaddw,3	%g25, %r36, %g25
	  qpsrcw,4	%r22, 0x7, %r36
	}
	{
	  qpaddw,0	%b[15], %b[4], %b[4]
	  qppackdl,1	%b[22], %b[38], %b[21]
	  qpaddw,3	%g25, %b[8], %b[15]
	  qpsrlw,4	%g25, 0xa, %b[20]
	  stqp,5	%r1, _f16s,_lts0lo 0x320, %g25
	}
	{
	  qpaddw,0	%r42, %g18, %g18
	  qpsrlw,1	%g29, 0x3, %b[22]
	  qpaddw,3	%r54, %b[15], %r42
	  qpsrcw,4	%g25, _f16s,_lts0lo 0x13, %b[15]
	}
	{
	  qpaddw,0	%b[9], %b[4], %b[4]
	  qpsrcw,1	%g29, _f16s,_lts0hi 0x12, %b[16]
	  qpaddw,3	%r3, %b[16], %r3
	  qpsrcw,4	%g25, _f16s,_lts0lo 0x11, %b[9]
	}
	{
	  qpaddw,0	%r63, %g18, %g18
	  qplog_0x96,1	%r36, %r45, %b[12], %r36
	  qpaddw,3	%g20, %r3, %g20
	  qplog_0x96,4	%b[9], %b[15], %b[20], %r3
	}
	{
	  qpaddw,0	%g18, %b[4], %r45
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x16, %r63
	  qpaddw,3	%g20, %b[10], %b[9]
	  qpsrlw,4	%g20, 0xa, %b[12]
	  stqp,5	%r1, _f16s,_lts0hi 0x330, %g20
	}
	{
	  qpsrcw,0	%g18, 0xd, %b[15]
	  qpsrcw,1	%g18, 0x2, %b[20]
	  qpaddw,3	%b[24], %b[9], %b[9]
	  qpsrcw,4	%g20, _f16s,_lts0lo 0x13, %b[23]
	}
	{
	  qplog_0xe8,0	%g18, %g23, %g16, %g16
	  qplog_0x96,1	%b[20], %b[15], %r63, %r63
	  qpaddw,3	%r23, %r3, %r3
	  qpsrcw,4	%g20, _f16s,_lts0lo 0x11, %r23
	}
	{
	  qpsrcw,0	%r45, 0xb, %b[20]
	  qpsrcw,1	%r45, _f16s,_lts0lo 0x19, %b[15]
	  qpaddw,3	%r16, %r3, %r3
	  qplog_0x96,4	%r23, %b[23], %b[12], %r16
	}
	{
	  qpaddw,0	%r63, %g16, %g16
	  qpsrcw,1	%r45, 0x6, %r23
	  qpaddw,3	%r3, %b[13], %r63
	  qplog_0xca,4	%r45, %b[24], %r54, %r54
	  stqp,5	%r1, _f16s,_lts0lo 0x340, %r3
	}
	{
	  qpaddw,0	%r61, %g16, %g16
	  qplog_0x96,1	%r23, %b[20], %b[15], %r23
	  qpaddw,3	%r45, %r63, %r61
	  qpsrlw,4	%r3, 0xa, %r63
	}
	{
	  qpsrcw,0	%g16, 0xd, %b[15]
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x16, %b[12]
	  qpaddw,3	%b[6], %r16, %r16
	  qpsrcw,4	%r3, _f16s,_lts0hi 0x13, %b[6]
	}
	{
	  qplog_0xe8,0	%g16, %g18, %g23, %g23
	  qpsrcw,1	%g16, 0x2, %b[20]
	  qpaddw,3	%r15, %r16, %r15
	  qpsrcw,4	%r3, _f16s,_lts0lo 0x11, %r16
	}
	{
	  qpaddw,0	%r23, %r54, %r23
	  qplog_0x96,1	%b[20], %b[15], %b[12], %r54
	  qpaddw,3	%r15, %b[27], %b[12]
	  qplog_0x96,4	%r16, %b[6], %r63, %r16
	  stqp,5	%r1, _f16s,_lts0lo 0x350, %r15
	}
	{
	  qpaddw,0	%r62, %r23, %r23
	  qpsrcw,1	%g29, 0x7, %r62
	  qpaddw,3	%r41, %r16, %r16
	  qpsrlw,4	%r15, 0xa, %r41
	}
	{
	  qpaddw,0	%g16, %r23, %r63
	  qplog_0x96,1	%r62, %b[16], %b[22], %r62
	  qpaddw,3	%r18, %r16, %r16
	  qpsrcw,4	%r15, _f16s,_lts0lo 0x13, %r18
	}
	{
	  qpaddw,0	%r54, %g23, %g23
	  qpsrcw,1	%r63, _f16s,_lts0lo 0x19, %r54
	  qpaddw,3	%r16, %b[19], %b[6]
	  qpsrcw,4	%r15, _f16s,_lts0hi 0x11, %b[15]
	  stqp,5	%r1, _f16s,_lts1lo 0x360, %r16
	}
	{
	  qpsrcw,0	%r63, 0x6, %b[20]
	  qpsrcw,1	%r63, 0xb, %b[16]
	  qpaddw,3	%b[2], %r12, %r41
	  qplog_0x96,4	%b[15], %r18, %r41, %r18
	}
	{
	  qpaddw,0	%r52, %g23, %g23
	  qplog_0xca,1	%r63, %r45, %b[24], %r52
	  qpaddw,3	%r38, %r18, %r18
	  qpsrlw,4	%r16, 0xa, %r38
	}
	{
	  qpsrcw,0	%g23, _f16s,_lts0lo 0x16, %b[2]
	  qplog_0x96,1	%b[20], %b[16], %r54, %r54
	  qpaddw,3	%r63, %b[12], %b[12]
	  qpsrcw,4	%r16, _f16s,_lts0hi 0x13, %b[15]
	}
	{
	  qpaddw,0	%r54, %r52, %r52
	  qpsrcw,1	%g23, 0xd, %r54
	  qpaddw,3	%r41, %r18, %r18
	  qpsrcw,4	%r16, _f16s,_lts0lo 0x11, %r41
	}
	{
	  qpaddw,0	%r42, %r52, %r42
	  qpsrcw,1	%g23, 0x2, %b[16]
	  qpaddw,3	%r18, %b[3], %r52
	  qplog_0x96,4	%r41, %b[15], %r38, %r38
	  stqp,5	%r1, _f16s,_lts0lo 0x370, %r18
	}
	{
	  qplog_0x96,0	%b[16], %r54, %b[2], %r41
	  qplog_0xe8,1	%g23, %g16, %g18, %g18
	  qpaddw,3	%r19, %r17, %r17
	  qpsrlw,4	%r18, 0xa, %r19
	}
	{
	  qpaddw,0	%g23, %r42, %r54
	  qppackdl,1	%b[30], %b[26], %b[2]
	  qpaddw,3	%r36, %r38, %r36
	  qpsrcw,4	%r18, _f16s,_lts0lo 0x13, %r38
	}
	{
	  qpaddw,0	%r41, %g18, %g18
	  qpsrcw,1	%r54, _f16s,_lts0lo 0x19, %r41
	  qpaddw,3	%r17, %r36, %r17
	  qpsrcw,4	%r18, _f16s,_lts0hi 0x11, %r36
	}
	{
	  qpaddw,0	%b[1], %g18, %g18
	  qpsrcw,1	%r54, 0xb, %b[1]
	  qpaddw,3	%r17, %b[21], %b[15]
	  qplog_0x96,4	%r36, %r38, %r19, %r19
	  stqp,5	%r1, _f16s,_lts0lo 0x380, %r17
	}
	{
	  qpsrcw,0	%r54, 0x6, %r36
	  qplog_0xca,1	%r54, %r63, %r45, %r38
	  qpaddw,3	%r22, %g25, %g25
	  qpsrlw,4	%r30, 0x3, %r22
	}
	{
	  qpsrcw,0	%g18, 0xd, %b[16]
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x16, %r45
	  qpaddw,3	%r54, %b[6], %b[6]
	  qpsrcw,4	%r30, _f16s,_lts0hi 0x12, %b[20]
	}
	{
	  qplog_0x96,0	%r36, %b[1], %r41, %r36
	  qpsrcw,1	%g18, 0x2, %b[22]
	  qpaddw,3	%r62, %r19, %r19
	  qpsrcw,4	%r30, 0x7, %r41
	}
	{
	  qpaddw,0	%r36, %r38, %r36
	  qplog_0xe8,1	%g18, %g23, %g16, %g16
	  qpaddw,3	%g25, %r19, %g25
	  qpsrlw,4	%r17, 0xa, %r19
	}
	{
	  qpaddw,0	%b[9], %r36, %r36
	  qplog_0x96,1	%b[22], %b[16], %r45, %r38
	  qpaddw,3	%g25, %b[2], %r45
	  qpsrcw,4	%r17, _f16s,_lts0lo 0x13, %r62
	  stqp,5	%r1, _f16s,_lts0hi 0x390, %g25
	}
	{
	  qpaddw,0	%r38, %g16, %g16
	  qpsrcw,1	%r17, _f16s,_lts0lo 0x11, %r38
	  qpaddw,3	%g29, %g20, %g20
	  qplog_0x96,4	%r41, %b[20], %r22, %r22
	}
	{
	  qpaddw,0	%g18, %r36, %g29
	  qppackdl,1	%b[43], %b[40], %r41
	  qpsrlw,3	%g27, 0x3, %b[1]
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x12, %b[9]
	}
	{
	  qpaddw,0	%b[4], %g16, %g16
	  qpsrcw,1	%g29, _f16s,_lts0lo 0x19, %b[4]
	  qpsrlw,3	%g25, 0xa, %b[20]
	  qpsrcw,4	%g27, 0x7, %b[16]
	}
	{
	  qpsrcw,0	%g29, 0xb, %b[22]
	  qpsrcw,1	%g29, 0x6, %b[23]
	  qpsrcw,3	%g25, _f16s,_lts0hi 0x11, %g25
	  qpsrcw,4	%g25, _f16s,_lts0lo 0x13, %b[24]
	}
	{
	  qpsrcw,0	%g16, _f16s,_lts0lo 0x16, %b[25]
	  qpsrcw,1	%g16, 0xd, %b[26]
	  qplog_0x96,3	%b[16], %b[9], %b[1], %r38
	  qplog_0x96,4	%r38, %r62, %r19, %r19
	}
	{
	  qplog_0xca,0	%g29, %r54, %r63, %r63
	  qpsrcw,1	%g16, 0x2, %r62
	  qpaddw,3	%g29, %r52, %r52
	  qplog_0x96,4	%g25, %b[24], %b[20], %g25
	}
	{
	  qplog_0xe8,0	%g16, %g18, %g23, %g23
	  qplog_0x96,1	%b[23], %b[22], %b[4], %b[1]
	  qpaddw,3	%r22, %r19, %r19
	  qppackdl,4	%b[48], %b[44], %r22
	}
	{
	  qpaddw,0	%b[1], %r63, %r63
	  qplog_0x96,1	%r62, %b[26], %b[25], %r62
	  qpaddw,3	%g20, %r19, %g20
	  qpsrlw,4	%g17, 0x3, %r19
	}
	{
	  qpaddw,0	%r62, %g23, %g23
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x12, %b[1]
	  qpaddw,3	%g20, %r41, %r62
	  qpsrcw,4	%g17, 0x7, %b[4]
	  stqp,5	%r1, _f16s,_lts0hi 0x3a0, %g20
	}
	{
	  qpaddw,0	%r61, %r63, %r61
	  qppackdl,1	%b[42], %b[49], %r63
	  qpaddw,3	%r30, %r3, %r3
	  qpsrlw,4	%g20, 0xa, %r30
	}
	{
	  qpaddw,0	%r23, %g23, %g23
	  qpsrlw,1	%r32, 0x3, %r38
	  qpaddw,3	%r38, %g25, %g25
	  qpsrcw,4	%g20, _f16s,_lts0lo 0x13, %r23
	}
	{
	  qpaddw,0	%g16, %r61, %b[9]
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x16, %b[16]
	  qpaddw,3	%r3, %g25, %g25
	  qpsrcw,4	%g20, _f16s,_lts0hi 0x11, %g20
	}
	{
	  qpsrcw,0	%g23, 0xd, %r3
	  qpsrcw,1	%g23, 0x2, %b[20]
	  qpaddw,3	%g25, %r22, %b[22]
	  qplog_0x96,4	%b[4], %b[1], %r19, %r19
	  stqp,5	%r1, _f16s,_lts0lo 0x3b0, %g25
	}
	{
	  qplog_0xe8,0	%g23, %g16, %g18, %g18
	  qplog_0x96,1	%b[20], %r3, %b[16], %r3
	  qpaddw,3	%g27, %r15, %g27
	  qplog_0x96,4	%g20, %r23, %r30, %g20
	}
	{
	  qpsrcw,0	%b[9], 0xb, %r23
	  qpsrcw,1	%b[9], _f16s,_lts0lo 0x19, %r15
	  qpaddw,3	%r19, %g20, %g20
	  qpsrcw,4	%r32, _f16s,_lts0hi 0x12, %r19
	}
	{
	  qpaddw,0	%r3, %g18, %g18
	  qpsrcw,1	%b[9], 0x6, %r30
	  qpaddw,3	%b[9], %b[15], %r54
	  qplog_0xca,4	%b[9], %g29, %r54, %r3
	}
	{
	  qpaddw,0	%r42, %g18, %g18
	  qplog_0x96,1	%r30, %r23, %r15, %r15
	  qpaddw,3	%g27, %g20, %g20
	  qpsrcw,4	%r32, 0x7, %g27
	}
	{
	  qpsrcw,0	%g18, 0xd, %r30
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x16, %r23
	  qpaddw,3	%g20, %r63, %r42
	  qpsrlw,4	%g25, 0xa, %r63
	  stqp,5	%r1, _f16s,_lts0hi 0x3c0, %g20
	}
	{
	  qplog_0xe8,0	%g18, %g23, %g16, %g16
	  qpsrcw,1	%g18, 0x2, %b[1]
	  qpsrcw,3	%g25, _f16s,_lts0hi 0x11, %g25
	  qpsrcw,4	%g25, _f16s,_lts0lo 0x13, %b[4]
	}
	{
	  qpaddw,0	%r15, %r3, %r3
	  qplog_0x96,1	%b[1], %r30, %r23, %r15
	  qplog_0x96,3	%g25, %b[4], %r63, %g25
	  qplog_0x96,4	%g27, %r19, %r38, %g27
	}
	{
	  qpaddw,0	%b[12], %r3, %r3
	  qppackdl,1	%b[52], %b[45], %r16
	  qpaddw,3	%g17, %r16, %g17
	  qpsrlw,4	%r31, 0x3, %r19
	}
	{
	  qpaddw,0	%g23, %r3, %r23
	  qpsrcw,1	%r31, _f16s,_lts0lo 0x12, %g27
	  qpaddw,3	%g27, %g25, %g25
	  qpsrcw,4	%r31, 0x7, %r30
	}
	{
	  qpaddw,0	%r15, %g16, %g16
	  qpsrcw,1	%r23, _f16s,_lts0lo 0x19, %r15
	  qpaddw,3	%g17, %g25, %g17
	  qpsrlw,4	%g20, 0xa, %g25
	}
	{
	  qpsrcw,0	%r23, 0x6, %r63
	  qpsrcw,1	%r23, 0xb, %r38
	  qpsrcw,3	%g20, _f16s,_lts0lo 0x11, %g20
	  qpsrcw,4	%g20, _f16s,_lts0hi 0x13, %b[1]
	  stqp,5	%r1, _f16s,_lts1lo 0x3d0, %g17
	}
	{
	  qpaddw,0	%r36, %g16, %g16
	  qplog_0xca,1	%r23, %b[9], %g29, %g29
	  qpaddw,3	%g17, %r16, %r16
	  qplog_0x96,4	%g20, %b[1], %g25, %g20
	}
	{
	  qpsrcw,0	%g16, _f16s,_lts0lo 0x16, %r15
	  qplog_0x96,1	%r63, %r38, %r15, %g25
	  qpaddw,3	%r23, %r45, %r36
	  qplog_0x96,4	%r30, %g27, %r19, %g27
	}
	{
	  qpaddw,0	%g25, %g29, %g25
	  qpsrcw,1	%g16, 0xd, %g29
	  qpaddw,3	%r32, %r18, %r18
	  qppackdl,4	%b[56], %b[53], %r19
	}
	{
	  qpaddw,0	%b[6], %g25, %g25
	  qpsrcw,1	%g16, 0x2, %r30
	  qpaddw,3	%g27, %g20, %g20
	  qpsrlw,4	%r12, 0x3, %g27
	}
	{
	  qplog_0x96,0	%r30, %g29, %r15, %g29
	  qplog_0xe8,1	%g16, %g18, %g23, %g23
	  qpaddw,3	%r18, %g20, %g20
	  qpsrcw,4	%r12, _f16s,_lts0lo 0x12, %r15
	}
	{
	  qpaddw,0	%g18, %g25, %r18
	  qpsrcw,1	%r12, 0x7, %r12
	  qpaddw,3	%g20, %r19, %r19
	  qpsrlw,4	%g17, 0xa, %r30
	  stqp,5	%r1, _f16s,_lts0lo 0x3e0, %g20
	}
	{
	  qpaddw,0	%g29, %g23, %g20
	  qpsrcw,1	%r18, _f16s,_lts0lo 0x19, %g23
	  qpsrcw,3	%g17, _f16s,_lts1lo 0x11, %g17
	  qpsrcw,4	%g17, _f16s,_lts0hi 0x13, %g29
	}
	{
	  qpaddw,0	%r61, %g20, %g20
	  qpsrcw,1	%r18, 0xb, %r32
	  qpaddw,3	%r31, %r17, %g29
	  qplog_0x96,4	%g17, %g29, %r30, %g17
	}
	{
	  qpsrcw,0	%r18, 0x6, %r17
	  qplog_0xca,1	%r18, %r23, %b[9], %r30
	  qppackdl,3	%b[50], %b[57], %r31
	  qppackdl,4	%b[47], %b[51], %r38
	}
	{
	  qpsrcw,0	%g20, 0xd, %r61
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x16, %r45
	  qpaddw,3	%r18, %r62, %r62
	  qplog_0x96,4	%r12, %r15, %g27, %g27
	}
	{
	  qplog_0x96,0	%r17, %r32, %g23, %g23
	  qpsrcw,1	%g20, 0x2, %r12
	  qpaddw,3	%g27, %g17, %g17
	  qppackdl,4	%b[55], %b[39], %g27
	}
	{
	  qpaddw,0	%g23, %r30, %g23
	  qplog_0xe8,1	%g20, %g16, %g18, %g18
	  qpaddw,3	%g29, %g17, %g17
	  qppackdl,4	%b[64], %b[60], %g29
	}
	{
	  qpaddw,0	%r52, %g23, %g23
	  qplog_0x96,1	%r12, %r61, %r45, %r12
	  qpaddw,3	%g17, %r31, %r15
	  qpsrcw,4	%r38, _f16s,_lts0lo 0x19, %r17
	  stqp,5	%r1, _f16s,_lts0hi 0x3f0, %g17
	}
	{
	  qpaddw,0	%r12, %g18, %g17
	  qpsrcw,1	%r38, 0xb, %g18
	  qpsrcw,3	%r38, 0x6, %r1
	  qppackdl,4	%b[58], %b[61], %r12
	}
	{
	  qpaddw,0	%g16, %g23, %r30
	  qppackdl,1	%b[68], %b[65], %r32
	  qplog_0xca,3	%r38, %g29, %g27, %r31
	  qppackdl,4	%b[70], %b[69], %r45
	}
	{
	  qpaddw,0	%r3, %g17, %g17
	  qpsrcw,1	%r30, _f16s,_lts0lo 0x19, %r3
	  qppackdl,3	%b[35], %b[75], %r61
	  qppackdl,4	%b[74], %b[71], %r52
	}
	{
	  qpsrcw,0	%r30, 0xb, %r63
	  qpsrcw,1	%r30, 0x6, %b[1]
	  qppackdl,3	%b[62], %b[79], %b[6]
	  qppackdl,4	%b[76], %b[59], %b[4]
	}
	{
	  qpsrcw,0	%g17, _f16s,_lts0lo 0x16, %b[9]
	  qpsrcw,1	%g17, 0xd, %b[12]
	  qplog_0x96,3	%r1, %g18, %r17, %g18
	  qpsrcw,4	%b[6], _lit16_ref,_lts0lo 0x16, %r1
	}
	{
	  qplog_0xca,0	%r30, %r18, %r23, %r23
	  qpsrcw,1	%g17, 0x2, %r17
	  qpaddw,3	%r30, %b[22], %b[15]
	  qpsrcw,4	%b[6], 0xd, %b[16]
	}
	{
	  qplog_0xe8,0	%g17, %g20, %g16, %g16
	  qplog_0x96,1	%b[1], %r63, %r3, %r3
	  qpaddw,3	%g18, %r31, %g18
	  qpsrcw,4	%b[6], 0x2, %r31
	}
	{
	  qpaddw,0	%r3, %r23, %r3
	  qplog_0x96,1	%r17, %b[12], %b[9], %r17
	  qplog_0x96,3	%r31, %b[16], %r1, %r1
	  qplog_0xe8,4	%b[6], %b[4], %r52, %r23
	}
	{
	  qpaddw,0	%r17, %g16, %g16
	  qppackdl,1	%b[67], %b[85], %r17
	  qpaddw,3	%r1, %r23, %r1
	  qppackdl,4	%b[83], %b[78], %r23
	}
	{
	  qpaddw,0	%r54, %r3, %r3
	  qpsrlw,1	%g19, 0xa, %r31
	  qpaddw,3	%g19, %r10, %r10
	  qpsrcw,4	%g19, _f16s,_lts0lo 0x13, %r54
	}
	{
	  qpaddw,0	%g25, %g16, %g16
	  qpsrcw,1	%g19, _f16s,_lts0lo 0x11, %r11
	  qpaddw,3	%g19, %r11, %g25
	  qpsrlw,4	%r23, 0xa, %r63
	}
	{
	  qpaddw,0	%g20, %r3, %b[1]
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x16, %b[9]
	  qpaddw,3	%g19, %r13, %r13
	  qpsrcw,4	%r23, _f16s,_lts0hi 0x13, %b[12]
	}
	{
	  qpsrcw,0	%g16, 0xd, %b[16]
	  qpsrcw,1	%g16, 0x2, %b[20]
	  qpaddw,3	%r17, %g28, %g28
	  qpsrcw,4	%r23, _f16s,_lts0lo 0x11, %b[22]
	}
	{
	  qplog_0xe8,0	%g16, %g17, %g20, %g20
	  qplog_0x96,1	%b[20], %b[16], %b[9], %b[9]
	  qpaddw,3	%g19, %r14, %r14
	  qplog_0x96,4	%b[22], %b[12], %r63, %r63
	}
	{
	  qpsrcw,0	%b[1], 0xb, %b[16]
	  qpsrcw,1	%b[1], _f16s,_lts0lo 0x19, %b[12]
	  qpaddw,3	%g19, %g22, %g22
	  qplog_0x96,4	%r11, %r54, %r31, %r11
	}
	{
	  qpaddw,0	%b[9], %g20, %g20
	  qpsrcw,1	%b[1], 0x6, %r31
	  qpaddw,3	%b[1], %r42, %r42
	  qplog_0xca,4	%b[1], %r30, %r18, %r18
	}
	{
	  qpaddw,0	%g23, %g20, %g20
	  qplog_0x96,1	%r31, %b[16], %b[12], %r31
	  qpaddw,3	%g19, %r9, %g23
	  qpsrlw,4	%r17, 0x3, %r9
	}
	{
	  qpsrcw,0	%g20, 0xd, %b[9]
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x16, %r54
	  qpaddw,3	%r23, %r24, %r24
	  qpsrcw,4	%r17, _f16s,_lts0hi 0x12, %b[12]
	}
	{
	  qplog_0xe8,0	%g20, %g16, %g17, %b[20]
	  qpsrcw,1	%g20, 0x2, %b[16]
	  qpaddw,3	%r11, %g19, %r11
	  qpsrcw,4	%r17, 0x7, %b[22]
	}
	{
	  qpaddw,0	%r31, %r18, %r18
	  qplog_0x96,1	%b[16], %b[9], %r54, %r31
	  qpaddw,3	%r63, %g19, %r54
	  qplog_0x96,4	%b[22], %b[12], %r9, %r9
	}
	{
	  qpaddw,0	%r36, %r18, %r18
	  qpsrlw,1	%g19, 0x3, %r36
	  qpsrcw,3	%g19, _f16s,_lts0lo 0x12, %r63
	  qpsrcw,4	%g19, 0x7, %b[9]
	}
	{
	  qpaddw,0	%g17, %r18, %g17
	  qpsrlw,1	%r23, 0x3, %b[12]
	  qpsrcw,3	%r23, _f16s,_lts0lo 0x12, %b[16]
	  qpsrcw,4	%r23, 0x7, %b[22]
	}
	{
	  qpaddw,0	%r31, %b[20], %r31
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x19, %b[20]
	  qppackdl,3	%b[89], %b[84], %b[23]
	}
	{
	  qpsrcw,0	%g17, 0x6, %b[25]
	  qpsrcw,1	%g17, 0xb, %b[24]
	}
	{
	  qpaddw,0	%r3, %r31, %r3
	  qplog_0xca,1	%g17, %b[1], %r30, %r30
	  qplog_0x96,3	%b[9], %r63, %r36, %r31
	  qplog_0x96,4	%b[9], %r63, %r36, %b[26]
	}
	{
	  qpsrcw,0	%r3, _f16s,_lts0lo 0x16, %b[24]
	  qplog_0x96,1	%b[25], %b[24], %b[20], %b[20]
	  qpaddw,3	%g17, %r16, %r16
	  qplog_0x96,4	%b[9], %r63, %r36, %b[25]
	}
	{
	  qpaddw,0	%b[20], %r30, %r30
	  qpsrcw,1	%r3, 0xd, %b[20]
	  qpaddw,3	%r31, %r17, %r17
	  qplog_0x96,4	%b[9], %r63, %r36, %r31
	}
	{
	  qpaddw,0	%r62, %r30, %r30
	  qpsrcw,1	%r3, 0x2, %b[28]
	  qpaddw,3	%b[26], %g19, %r62
	  qplog_0x96,4	%b[9], %r63, %r36, %b[26]
	}
	{
	  qplog_0x96,0	%b[28], %b[20], %b[24], %b[20]
	  qplog_0xe8,1	%r3, %g20, %g16, %b[29]
	  qpaddw,3	%b[25], %g19, %b[24]
	  qplog_0x96,4	%b[9], %r63, %r36, %r36
	}
	{
	  qpaddw,0	%g16, %r30, %g16
	  qplog_0x96,1	%b[22], %b[16], %b[12], %r63
	  qpaddw,3	%r31, %g19, %r31
	}
	{
	  qpaddw,0	%b[20], %b[29], %b[9]
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x19, %b[12]
	  qpaddw,3	%b[26], %g19, %b[16]
	}
	{
	  qpaddw,0	%r18, %b[9], %r18
	  qpsrcw,1	%g16, 0xb, %b[9]
	  qpaddw,3	%r36, %g19, %r36
	}
	{
	  qpsrcw,0	%g16, 0x6, %b[20]
	  qplog_0xca,1	%g16, %g17, %b[1], %b[1]
	}
	{
	  qpsrcw,0	%r18, 0xd, %b[25]
	  qpsrcw,1	%r18, _f16s,_lts0lo 0x16, %b[22]
	  qpaddw,3	%g16, %r19, %r19
	}
	{
	  qplog_0x96,0	%b[20], %b[9], %b[12], %b[9]
	  qpsrcw,1	%r18, 0x2, %b[26]
	  qpaddw,3	%r63, %g19, %r63
	}
	{
	  qpaddw,0	%b[9], %b[1], %b[1]
	  qplog_0xe8,1	%r18, %r3, %g20, %b[9]
	}
	{
	  qpaddw,0	%b[15], %b[1], %b[1]
	  qplog_0x96,1	%b[26], %b[25], %b[22], %b[12]
	}
	{
	  qpaddw,0	%b[12], %b[9], %b[9]
	}
	{
	  qpaddw,0	%g20, %b[1], %g20
	}
	{
	  qpaddw,0	%r30, %b[9], %r30
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x19, %b[9]
	}
	{
	  qpsrcw,0	%g20, 0xb, %b[12]
	  qpsrcw,1	%g20, 0x6, %b[15]
	}
	{
	  qpsrcw,0	%r30, _f16s,_lts0lo 0x16, %b[20]
	  qpsrcw,1	%r30, 0xd, %b[22]
	}
	{
	  qplog_0xca,0	%g20, %g16, %g17, %g17
	  qpsrcw,1	%r30, 0x2, %b[25]
	  qpaddw,3	%g20, %r15, %r15
	}
	{
	  qplog_0x96,0	%b[15], %b[12], %b[9], %b[9]
	  qplog_0xe8,1	%r30, %r18, %r3, %b[12]
	}
	{
	  qpaddw,0	%b[9], %g17, %g17
	  qplog_0x96,1	%b[25], %b[22], %b[20], %b[15]
	}
	{
	  qpaddw,0	%b[15], %b[12], %b[9]
	}
	{
	  qpaddw,0	%r42, %g17, %g17
	}
	{
	  qpaddw,0	%b[1], %b[9], %r42
	}
	{
	  qpaddw,0	%r3, %g17, %r3
	  qpsrcw,1	%r42, _f16s,_lts0lo 0x16, %b[1]
	}
	{
	  qpsrcw,0	%r42, 0xd, %b[9]
	  qpsrcw,1	%r42, 0x2, %b[12]
	}
	{
	  qplog_0xe8,0	%r42, %r30, %r18, %b[15]
	  qplog_0x96,1	%b[12], %b[9], %b[1], %b[1]
	}
	{
	  qpsrcw,0	%r3, 0xb, %b[12]
	  qpsrcw,1	%r3, _f16s,_lts0lo 0x19, %b[9]
	}
	{
	  qpaddw,0	%b[1], %b[15], %b[1]
	  qpsrcw,1	%r3, 0x6, %b[20]
	  qpaddw,3	%r3, %r2, %r2
	  qplog_0xca,4	%r3, %g20, %g16, %g16
	}
	{
	  qpaddw,0	%g17, %b[1], %g17
	  qplog_0x96,1	%b[20], %b[12], %b[9], %b[9]
	  qpaddw,3	%r2, %g30, %g30
	  qpsrlw,4	%r2, 0x3, %b[1]
	}
	{
	  qpsrcw,0	%g17, 0xd, %b[15]
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x16, %b[12]
	  qpsrcw,3	%r2, 0x7, %b[22]
	  qpsrcw,4	%r2, _f16s,_lts0hi 0x12, %b[20]
	}
	{
	  qplog_0xe8,0	%g17, %r42, %r30, %b[26]
	  qpsrcw,1	%g17, 0x2, %b[25]
	  qpaddw,3	%r9, %r2, %r2
	  qplog_0x96,4	%b[22], %b[20], %b[1], %b[1]
	}
	{
	  qpaddw,0	%b[9], %g16, %g16
	  qplog_0x96,1	%b[25], %b[15], %b[12], %r9
	}
	{
	  qpaddw,0	%r16, %g16, %g16
	  qpaddw,3	%g17, %b[73], %r16
	}
	{
	  qpaddw,0	%r18, %g16, %r18
	  qpaddw,3	%r16, %g21, %g21
	  qpsrlw,4	%r16, 0x3, %b[9]
	}
	{
	  qpaddw,0	%r9, %b[26], %r9
	  qpsrcw,1	%r18, _f16s,_lts0lo 0x19, %b[12]
	  qpaddw,3	%r38, %g21, %g21
	  qpsrcw,4	%r16, _f16s,_lts0hi 0x12, %b[15]
	}
	{
	  qpsrcw,0	%r18, 0x6, %b[22]
	  qpsrcw,1	%r18, 0xb, %b[20]
	  qpsrcw,3	%r16, 0x7, %b[25]
	}
	{
	  qpaddw,0	%g16, %r9, %g16
	  qplog_0xca,1	%r18, %r3, %g20, %g20
	  qplog_0x96,3	%b[25], %b[15], %b[9], %r9
	}
	{
	  qpsrcw,0	%g16, _f16s,_lts0lo 0x16, %b[12]
	  qplog_0x96,1	%b[22], %b[20], %b[12], %b[9]
	  qpaddw,3	%r18, %b[82], %b[15]
	}
	{
	  qpaddw,0	%b[9], %g20, %g20
	  qpsrcw,1	%g16, 0xd, %b[9]
	  qpaddw,3	%b[15], %r6, %r6
	  qpsrlw,4	%b[15], 0x3, %b[20]
	}
	{
	  qpaddw,0	%r19, %g20, %g20
	  qpsrcw,1	%g16, 0x2, %b[22]
	  qpsrcw,3	%b[15], 0x7, %b[25]
	  qpsrcw,4	%b[15], _f16s,_lts0lo 0x12, %r19
	}
	{
	  qplog_0x96,0	%b[22], %b[9], %b[12], %b[9]
	  qplog_0xe8,1	%g16, %g17, %r42, %b[26]
	  qpaddw,3	%g16, %r59, %r59
	  qplog_0x96,4	%b[25], %r19, %b[20], %r19
	}
	{
	  qpaddw,0	%r30, %g20, %r30
	  qpaddw,3	%r59, %r61, %r61
	  qpsrlw,4	%r59, 0x3, %b[12]
	}
	{
	  qpaddw,0	%b[9], %b[26], %b[9]
	  qpsrcw,1	%r30, _f16s,_lts0lo 0x19, %b[20]
	  qpaddw,3	%g29, %r61, %r61
	  qpsrcw,4	%r59, _f16s,_lts0hi 0x12, %b[22]
	}
	{
	  qpaddw,0	%g20, %b[9], %g20
	  qpsrcw,1	%r30, 0xb, %b[9]
	  qpaddw,3	%r9, %r59, %r9
	  qpsrcw,4	%r59, 0x7, %b[25]
	}
	{
	  qpsrcw,0	%r30, 0x6, %r59
	  qplog_0xca,1	%r30, %r18, %r3, %r3
	  qpaddw,3	%b[1], %b[15], %b[1]
	  qplog_0x96,4	%b[25], %b[22], %b[12], %r18
	}
	{
	  qpsrcw,0	%g20, 0xd, %b[15]
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x16, %b[12]
	  qpaddw,3	%r30, %b[66], %r30
	}
	{
	  qplog_0x96,0	%r59, %b[9], %b[20], %r59
	  qpsrcw,1	%g20, 0x2, %b[22]
	  qpaddw,3	%r30, %g31, %g31
	  qpsrlw,4	%r30, 0x3, %b[9]
	}
	{
	  qpaddw,0	%r59, %r3, %r3
	  qplog_0xe8,1	%g20, %g16, %g17, %g16
	  qpaddw,3	%g20, %r25, %g17
	  qpsrcw,4	%r30, _f16s,_lts0lo 0x12, %g20
	}
	{
	  qpaddw,0	%r15, %r3, %r3
	  qplog_0x96,1	%b[22], %b[15], %b[12], %r25
	  qpaddw,3	%g17, %r45, %r15
	  qpsrlw,4	%g17, 0x3, %r45
	}
	{
	  qpaddw,0	%r25, %g16, %g16
	  qpsrcw,1	%r30, 0x7, %r25
	  qpaddw,3	%g27, %r15, %g27
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x12, %r15
	}
	{
	  qpaddw,0	%r3, %g16, %g16
	  qpaddw,3	%r18, %g17, %g17
	  qpsrcw,4	%g17, 0x7, %r59
	}
	{
	  qpaddw,0	%g16, %r21, %g16
	  qplog_0x96,1	%r25, %g20, %b[9], %g20
	  qpaddw,3	%r54, %g17, %g17
	  qplog_0x96,4	%r59, %r15, %r45, %r15
	}
	{
	  qpaddw,0	%g16, %r12, %r12
	  qpaddw,3	%r42, %r3, %r3
	  qpsrlw,4	%g17, 0xa, %r18
	}
	{
	  qpaddw,0	%r12, %g18, %g18
	  qpaddw,3	%r3, %b[80], %r3
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x13, %r12
	}
	{
	  qpaddw,0	%r32, %g18, %r21
	  qpaddw,3	%r3, %g26, %g26
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x11, %r25
	}
	{
	  qpsrcw,0	%r21, 0xb, %r42
	  qpsrcw,1	%r21, _f16s,_lts0lo 0x19, %r32
	  qpaddw,3	%r15, %g16, %g16
	  qpsrlw,4	%r3, 0x3, %r15
	}
	{
	  qplog_0xca,0	%r21, %r38, %g29, %g29
	  qpsrcw,1	%r21, 0x6, %r45
	  qpaddw,3	%r11, %g16, %g16
	  qpsrcw,4	%r3, _f16s,_lts0lo 0x12, %r11
	}
	{
	  qpaddw,0	%g18, %r1, %g18
	  qplog_0x96,1	%r45, %r42, %r32, %r32
	  qpaddw,3	%g16, %r26, %r1
	  qpsrlw,4	%g16, 0xa, %r26
	}
	{
	  qpaddw,0	%r32, %g29, %g29
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x16, %r32
	  qpaddw,3	%r21, %g26, %g26
	  qpsrcw,4	%g16, _f16s,_lts0hi 0x13, %r42
	}
	{
	  qpaddw,0	%g27, %g29, %g27
	  qpsrcw,1	%g18, 0xd, %g29
	  qpaddw,3	%g17, %r20, %r20
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x11, %r45
	}
	{
	  qpaddw,0	%r52, %g27, %r52
	  qpsrcw,1	%g18, 0x2, %r54
	  qpsrcw,3	%r3, 0x7, %r42
	  qplog_0x96,4	%r45, %r42, %r26, %r26
	}
	{
	  qpsrcw,0	%r52, _f16s,_lts0lo 0x19, %r45
	  qpsrcw,1	%r52, 0xb, %r59
	  qpaddw,3	%r26, %g19, %r26
	  qplog_0xe8,4	%g18, %b[6], %b[4], %b[9]
	}
	{
	  qplog_0xca,0	%r52, %r21, %r38, %r38
	  qpsrcw,1	%r52, 0x6, %b[12]
	  qpaddw,3	%r26, %r9, %r9
	  qplog_0x96,4	%r25, %r12, %r18, %r12
	}
	{
	  qplog_0x96,0	%r54, %g29, %r32, %g29
	  qplog_0x96,1	%b[12], %r59, %r45, %r18
	  qpaddw,3	%r9, %r27, %r25
	  qplog_0x96,4	%r42, %r11, %r15, %r11
	}
	{
	  qpaddw,0	%r18, %r38, %r15
	  qpsrlw,1	%g16, 0x3, %r26
	  qpaddw,3	%r52, %g31, %g31
	  qpsrlw,4	%r9, 0xa, %r18
	}
	{
	  qpaddw,0	%r61, %r15, %r15
	  qpsrcw,1	%g16, _f16s,_lts0hi 0x12, %r32
	  qpaddw,3	%r12, %g19, %r12
	  qpsrcw,4	%r9, _f16s,_lts0lo 0x13, %r27
	}
	{
	  qpaddw,0	%b[4], %r15, %r38
	  qpsrcw,1	%r9, _f16s,_lts0lo 0x11, %r16
	  qpaddw,3	%r11, %r16, %r11
	  qpsrcw,4	%g16, 0x7, %r42
	}
	{
	  qpsrcw,0	%r38, 0xb, %r54
	  qpsrcw,1	%r38, _f16s,_lts0lo 0x19, %r45
	  qpaddw,3	%g29, %b[9], %g29
	  qpsrlw,4	%g17, 0x3, %r59
	}
	{
	  qplog_0xca,0	%r38, %r52, %r21, %r21
	  qpsrcw,1	%r38, 0x6, %r61
	  qpaddw,3	%g27, %g29, %g27
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x12, %g29
	}
	{
	  qpaddw,0	%r38, %r6, %r6
	  qplog_0x96,1	%r61, %r54, %r45, %r45
	  qpsrcw,3	%g27, 0xd, %r61
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x16, %r54
	}
	{
	  qpaddw,0	%r45, %r21, %r21
	  qplog_0x96,1	%r16, %r27, %r18, %r16
	  qplog_0xe8,3	%g27, %g18, %b[6], %b[4]
	  qpsrcw,4	%g27, 0x2, %r45
	}
	{
	  qpaddw,0	%g21, %r21, %g21
	  qplog_0x96,1	%r42, %r32, %r26, %r12
	  qpaddw,3	%r12, %r11, %r11
	  qplog_0x96,4	%r45, %r61, %r54, %r18
	}
	{
	  qpaddw,0	%b[6], %g21, %r21
	  qpsrcw,1	%g17, 0x7, %r27
	  qpaddw,3	%r18, %b[4], %r18
	  qpsrlw,4	%r11, 0xa, %r26
	}
	{
	  qpsrcw,0	%r21, 0xb, %r42
	  qpsrcw,1	%r21, _f16s,_lts0lo 0x19, %r32
	  qpaddw,3	%r15, %r18, %r15
	  qpsrcw,4	%r11, _f16s,_lts0hi 0x13, %r18
	}
	{
	  qpsrcw,0	%r21, 0x6, %r45
	  qplog_0xca,1	%r21, %r38, %r52, %r52
	  qpsrcw,3	%r15, 0xd, %r61
	  qpsrcw,4	%r15, _f16s,_lts0lo 0x16, %r54
	}
	{
	  qpaddw,0	%r21, %g30, %g30
	  qplog_0x96,1	%r45, %r42, %r32, %r32
	  qplog_0xe8,3	%r15, %g27, %g18, %r45
	  qpsrcw,4	%r15, 0x2, %r42
	}
	{
	  qpaddw,0	%r32, %r52, %r32
	  qpsrcw,1	%r11, _f16s,_lts0lo 0x11, %r52
	  qpaddw,3	%r11, %r29, %r29
	  qplog_0x96,4	%r42, %r61, %r54, %r42
	}
	{
	  qpaddw,0	%g26, %r32, %g26
	  qplog_0x96,1	%r52, %r18, %r26, %r18
	  qpaddw,3	%r42, %r45, %r32
	  qplog_0x96,4	%r27, %g29, %r59, %g29
	}
	{
	  qpaddw,0	%g18, %g26, %g18
	  qpsrlw,1	%r9, 0x3, %r26
	  qpaddw,3	%g21, %r32, %g21
	  qpsrcw,4	%r9, _f16s,_lts0lo 0x12, %r27
	}
	{
	  qpsrcw,0	%g18, _f16s,_lts0lo 0x19, %r32
	  qpsrcw,1	%g18, 0xb, %r42
	  qpsrcw,3	%g21, 0xd, %r52
	  qpsrcw,4	%g21, _f16s,_lts0hi 0x16, %r45
	}
	{
	  qplog_0xca,0	%g18, %r21, %r38, %r38
	  qpsrcw,1	%g18, 0x6, %r54
	  qplog_0xe8,3	%g21, %r15, %g27, %r61
	  qpsrcw,4	%g21, 0x2, %r59
	}
	{
	  qpaddw,0	%g18, %g28, %g28
	  qplog_0x96,1	%r54, %r42, %r32, %r32
	  qpaddw,3	%g20, %r3, %g20
	  qplog_0x96,4	%r59, %r52, %r45, %r42
	}
	{
	  qpaddw,0	%r32, %r38, %r3
	  qpsrcw,1	%r9, 0x7, %r38
	  qpaddw,3	%r42, %r61, %r32
	  qpsrlw,4	%r11, 0x3, %r42
	}
	{
	  qpaddw,0	%g31, %r3, %g31
	  qplog_0x96,1	%r38, %r27, %r26, %r3
	  qpaddw,3	%g26, %r32, %g26
	  qpsrcw,4	%r11, _f16s,_lts0lo 0x12, %r26
	}
	{
	  qpaddw,0	%g27, %g31, %g27
	  qpsrcw,1	%r11, 0x7, %r38
	  qpsrcw,3	%g26, 0xd, %r32
	  qpsrcw,4	%g26, _f16s,_lts0lo 0x16, %r27
	}
	{
	  qpsrcw,0	%g27, _f16s,_lts0lo 0x19, %r45
	  qpsrcw,1	%g27, 0xb, %r52
	  qplog_0xe8,3	%g26, %g21, %r15, %r59
	  qpsrcw,4	%g26, 0x2, %r54
	}
	{
	  qplog_0xca,0	%g27, %g18, %r21, %r21
	  qpsrcw,1	%g27, 0x6, %r61
	  qpaddw,3	%r16, %g19, %r16
	  qplog_0x96,4	%r54, %r32, %r27, %r27
	}
	{
	  qpaddw,0	%g27, %r10, %r10
	  qplog_0x96,1	%r61, %r52, %r45, %r32
	  qpaddw,3	%r27, %r59, %r27
	}
	{
	  qpaddw,0	%r32, %r21, %r21
	  qplog_0x96,1	%r38, %r26, %r42, %r26
	  qpaddw,3	%g31, %r27, %g31
	}
	{
	  qpaddw,0	%r6, %r21, %r6
	  qpsrcw,3	%g31, 0xd, %r27
	  qpsrcw,4	%g31, _f16s,_lts0lo 0x16, %r21
	}
	{
	  qpaddw,0	%r15, %r6, %r15
	  qplog_0xe8,3	%g31, %g26, %g21, %r38
	  qpsrcw,4	%g31, 0x2, %r32
	}
	{
	  qpsrcw,0	%r15, 0xb, %r45
	  qpsrcw,1	%r15, _f16s,_lts0lo 0x19, %r42
	  qpaddw,3	%r16, %g20, %g20
	  qplog_0x96,4	%r32, %r27, %r21, %r21
	}
	{
	  qplog_0xca,0	%r15, %g27, %g18, %g18
	  qpsrcw,1	%r15, 0x6, %r16
	  qpaddw,3	%r21, %r38, %r21
	  qpsrlw,4	%g20, 0xa, %r27
	}
	{
	  qpaddw,0	%r15, %g25, %g25
	  qplog_0x96,1	%r16, %r45, %r42, %r16
	  qpaddw,3	%r6, %r21, %r6
	  qpsrcw,4	%g20, _f16s,_lts0lo 0x13, %r21
	}
	{
	  qpaddw,0	%r16, %g18, %g18
	  qpsrcw,3	%r6, 0xd, %r32
	  qpsrcw,4	%r6, _f16s,_lts0lo 0x16, %r16
	}
	{
	  qpaddw,0	%g30, %g18, %g18
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x11, %r42
	  qplog_0xe8,3	%r6, %g31, %g26, %r38
	  qpsrcw,4	%r6, 0x2, %g30
	}
	{
	  qpaddw,0	%g21, %g18, %g21
	  qpsrlw,1	%g20, 0x3, %r32
	  qpaddw,3	%g20, %r34, %r16
	  qplog_0x96,4	%g30, %r32, %r16, %g30
	}
	{
	  qpsrcw,0	%g21, 0xb, %r45
	  qpsrcw,1	%g21, _f16s,_lts0lo 0x19, %r34
	  qpaddw,3	%g30, %r38, %g30
	  qpsrcw,4	%g20, _f16s,_lts0hi 0x12, %r38
	}
	{
	  qplog_0xca,0	%g21, %r15, %g27, %g27
	  qpsrcw,1	%g21, 0x6, %r52
	  qpaddw,3	%r19, %r30, %r19
	  qpsrcw,4	%g20, 0x7, %r30
	}
	{
	  qpaddw,0	%g21, %r13, %r13
	  qplog_0x96,1	%r52, %r45, %r34, %r34
	  qpaddw,3	%g18, %g30, %g18
	  qplog_0x96,4	%r42, %r21, %r27, %g30
	}
	{
	  qpaddw,0	%r34, %g27, %g27
	  qpsrcw,3	%g18, 0xd, %r27
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r21
	}
	{
	  qpaddw,0	%g28, %g27, %g27
	  qplog_0xe8,3	%g18, %r6, %g31, %r34
	  qpsrcw,4	%g18, 0x2, %g28
	}
	{
	  qpaddw,0	%g26, %g27, %g26
	  qplog_0x96,1	%r30, %r38, %r32, %r18
	  qpaddw,3	%r18, %g19, %g19
	  qplog_0x96,4	%g28, %r27, %r21, %g28
	}
	{
	  qpsrcw,0	%g26, 0xb, %r27
	  qpsrcw,1	%g26, _f16s,_lts0lo 0x19, %r21
	  qpaddw,3	%g28, %r34, %g28
	}
	{
	  qplog_0xca,0	%g26, %g21, %r15, %r15
	  qpsrcw,1	%g26, 0x6, %r30
	  qpaddw,3	%g19, %r19, %g19
	}
	{
	  qpaddw,0	%g26, %r14, %r14
	  qplog_0x96,1	%r30, %r27, %r21, %r19
	  qpaddw,3	%g27, %g28, %g27
	  qpsrlw,4	%g19, 0xa, %g28
	}
	{
	  qpaddw,0	%r19, %r15, %r15
	  qpsrcw,3	%g27, 0xd, %r21
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x16, %r19
	}
	{
	  qpaddw,0	%r10, %r15, %r10
	  qplog_0xe8,3	%g27, %g18, %r6, %r27
	  qpsrcw,4	%g27, 0x2, %r15
	}
	{
	  qpaddw,0	%g31, %r10, %g31
	  qpsrcw,1	%g19, _f16s,_lts0lo 0x13, %r21
	  qpaddw,3	%g19, %r40, %r19
	  qplog_0x96,4	%r15, %r21, %r19, %r15
	}
	{
	  qpsrcw,0	%g31, 0xb, %r32
	  qpsrcw,1	%g31, _f16s,_lts0lo 0x19, %r30
	  qpaddw,3	%r15, %r27, %r15
	  qpsrcw,4	%g19, _f16s,_lts0hi 0x11, %r27
	}
	{
	  qplog_0xca,0	%g31, %g26, %g21, %g21
	  qpsrcw,1	%g31, 0x6, %r34
	  qpaddw,3	%g30, %r23, %g30
	  qpsrlw,4	%g19, 0x3, %r38
	}
	{
	  qpaddw,0	%g31, %g22, %g22
	  qplog_0x96,1	%r34, %r32, %r30, %r30
	  qpaddw,3	%r10, %r15, %r10
	  qpsrcw,4	%g19, _f16s,_lts0lo 0x12, %r15
	}
	{
	  qpaddw,0	%r30, %g21, %g21
	  qpsrcw,1	%g19, 0x7, %r34
	  qpsrcw,3	%r10, 0xd, %r32
	  qpsrcw,4	%r10, _f16s,_lts0lo 0x16, %r30
	}
	{
	  qpaddw,0	%g25, %g21, %g21
	  qplog_0x96,1	%r27, %r21, %g28, %g28
	  qplog_0xe8,3	%r10, %g27, %g18, %r40
	  qpsrcw,4	%r10, 0x2, %g25
	}
	{
	  qpaddw,0	%r6, %g21, %r6
	  qpaddw,3	%g30, %b[1], %g30
	  qplog_0x96,4	%g25, %r32, %r30, %g25
	}
	{
	  qpsrcw,0	%r6, 0xb, %r27
	  qpsrcw,1	%r6, _f16s,_lts0lo 0x19, %r21
	  qpaddw,3	%g25, %r40, %g25
	  qpsrlw,4	%g30, 0xa, %r30
	}
	{
	  qplog_0xca,0	%r6, %g31, %g26, %g26
	  qpsrcw,1	%r6, 0x6, %r32
	  qpaddw,3	%g30, %g24, %g24
	  qpsrcw,4	%g30, _f16s,_lts0lo 0x13, %r40
	}
	{
	  qpaddw,0	%r6, %g23, %g23
	  qplog_0x96,1	%r32, %r27, %r21, %r21
	  qpaddw,3	%g21, %g25, %g21
	  qpsrcw,4	%g30, _f16s,_lts0lo 0x11, %g25
	}
	{
	  qpaddw,0	%r21, %g26, %g26
	  qplog_0x96,1	%r34, %r15, %r38, %r15
	  qpsrcw,3	%g21, 0xd, %r27
	  qpsrcw,4	%g21, _f16s,_lts0lo 0x16, %r21
	}
	{
	  qpaddw,0	%r13, %g26, %g26
	  qpsrlw,1	%g30, 0x3, %r34
	  qplog_0xe8,3	%g21, %r10, %g27, %r32
	  qpsrcw,4	%g21, 0x2, %r13
	}
	{
	  qpaddw,0	%g18, %g26, %g18
	  qpsrcw,1	%g30, _f16s,_lts0lo 0x12, %r21
	  qpaddw,3	%g28, %g16, %g28
	  qplog_0x96,4	%r13, %r27, %r21, %r13
	}
	{
	  qpsrcw,0	%g18, 0xb, %r38
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %r27
	  qpaddw,3	%r13, %r32, %r13
	  qplog_0x96,4	%g25, %r40, %r30, %g25
	}
	{
	  qplog_0xca,0	%g18, %r6, %g31, %g31
	  qpsrcw,1	%g18, 0x6, %r30
	  qpaddw,3	%g28, %r2, %g28
	  qpsrcw,4	%g30, 0x7, %r2
	}
	{
	  qpaddw,0	%g18, %r24, %r24
	  qplog_0x96,1	%r30, %r38, %r27, %r27
	  qpaddw,3	%g26, %r13, %g26
	  qpsrlw,4	%g28, 0xa, %r13
	}
	{
	  qpaddw,0	%r27, %g31, %g31
	  qpsrcw,3	%g26, 0xd, %r30
	  qpsrcw,4	%g26, _f16s,_lts0lo 0x16, %r27
	}
	{
	  qpaddw,0	%r14, %g31, %g31
	  qplog_0xe8,3	%g26, %g21, %r10, %r32
	  qpsrcw,4	%g26, 0x2, %r14
	}
	{
	  qpaddw,0	%g27, %g31, %g27
	  qpsrcw,1	%g28, _f16s,_lts0lo 0x13, %r30
	  qpaddw,3	%g28, %r39, %r27
	  qplog_0x96,4	%r14, %r30, %r27, %r14
	}
	{
	  qpsrcw,0	%g27, 0xb, %r39
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x19, %r38
	  qpaddw,3	%r14, %r32, %r14
	  qpsrcw,4	%g28, _f16s,_lts0hi 0x11, %r32
	}
	{
	  qplog_0xca,0	%g27, %g18, %r6, %r6
	  qpsrcw,1	%g27, 0x6, %r40
	  qpaddw,3	%g25, %g17, %g25
	  qplog_0x96,4	%r2, %r21, %r34, %r2
	}
	{
	  qpaddw,0	%g27, %r1, %r1
	  qplog_0x96,1	%r40, %r39, %r38, %r21
	  qpaddw,3	%g31, %r14, %g31
	  qpsrlw,4	%g28, 0x3, %r14
	}
	{
	  qpaddw,0	%r21, %r6, %r6
	  qpsrcw,1	%g28, _f16s,_lts0hi 0x12, %r38
	  qpsrcw,3	%g31, 0xd, %r34
	  qpsrcw,4	%g31, _f16s,_lts0lo 0x16, %r21
	}
	{
	  qpaddw,0	%g22, %r6, %g22
	  qplog_0x96,1	%r32, %r30, %r13, %r13
	  qplog_0xe8,3	%g31, %g26, %g21, %r39
	  qpsrcw,4	%g31, 0x2, %r6
	}
	{
	  qpaddw,0	%r10, %g22, %r10
	  qpsrcw,1	%g28, 0x7, %r17
	  qpaddw,3	%g25, %r17, %g25
	  qplog_0x96,4	%r6, %r34, %r21, %r6
	}
	{
	  qpsrcw,0	%r10, 0xb, %r30
	  qpsrcw,1	%r10, _f16s,_lts0lo 0x19, %r21
	  qpaddw,3	%r6, %r39, %r6
	  qpsrlw,4	%g25, 0xa, %r32
	}
	{
	  qplog_0xca,0	%r10, %g27, %g18, %g18
	  qpsrcw,1	%r10, 0x6, %r34
	  qpaddw,3	%g25, %r35, %r35
	  qpsrcw,4	%g25, _f16s,_lts0lo 0x13, %r39
	}
	{
	  qpaddw,0	%r10, %r20, %r20
	  qplog_0x96,1	%r34, %r30, %r21, %r21
	  qpaddw,3	%g22, %r6, %g22
	  qpsrcw,4	%g25, _f16s,_lts0lo 0x11, %r6
	}
	{
	  qpaddw,0	%r21, %g18, %g18
	  qplog_0x96,1	%r17, %r38, %r14, %r14
	  qpsrcw,3	%g22, 0xd, %r30
	  qpsrcw,4	%g22, _f16s,_lts0lo 0x16, %r21
	}
	{
	  qpaddw,0	%g23, %g18, %g18
	  qpsrlw,1	%g25, 0x3, %r34
	  qplog_0xe8,3	%g22, %g31, %g26, %r17
	  qpsrcw,4	%g22, 0x2, %g23
	}
	{
	  qpaddw,0	%g21, %g18, %g21
	  qpsrcw,1	%g25, _f16s,_lts0lo 0x12, %r21
	  qpaddw,3	%r13, %r9, %r13
	  qplog_0x96,4	%g23, %r30, %r21, %g23
	}
	{
	  qpsrcw,0	%g21, 0xb, %r38
	  qpsrcw,1	%g21, _f16s,_lts0lo 0x19, %r30
	  qpaddw,3	%g23, %r17, %g23
	  qplog_0x96,4	%r6, %r39, %r32, %r6
	}
	{
	  qplog_0xca,0	%g21, %r10, %g27, %g27
	  qpsrcw,1	%g21, 0x6, %r17
	  qpaddw,3	%r13, %r62, %r13
	  qpsrcw,4	%g25, 0x7, %r32
	}
	{
	  qpaddw,0	%g21, %r25, %r25
	  qplog_0x96,1	%r17, %r38, %r30, %r17
	  qpaddw,3	%g18, %g23, %g18
	  qpsrlw,4	%r13, 0xa, %g23
	}
	{
	  qpaddw,0	%r17, %g27, %g27
	  qpsrcw,3	%g18, 0xd, %r30
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r17
	}
	{
	  qpaddw,0	%r24, %g27, %g27
	  qplog_0xe8,3	%g18, %g22, %g31, %r38
	  qpsrcw,4	%g18, 0x2, %r24
	}
	{
	  qpaddw,0	%g26, %g27, %g26
	  qpsrcw,1	%r13, _f16s,_lts0lo 0x13, %r28
	  qpaddw,3	%r13, %r28, %r24
	  qplog_0x96,4	%r24, %r30, %r17, %r17
	}
	{
	  qpsrcw,0	%g26, 0xb, %r39
	  qpsrcw,1	%g26, _f16s,_lts0lo 0x19, %r30
	  qpaddw,3	%r17, %r38, %r17
	  qpsrcw,4	%r13, _f16s,_lts0hi 0x11, %r38
	}
	{
	  qplog_0xca,0	%g26, %g21, %r10, %r10
	  qpsrcw,1	%g26, 0x6, %r40
	  qpaddw,3	%r6, %r11, %r6
	  qplog_0x96,4	%r32, %r21, %r34, %r21
	}
	{
	  qpaddw,0	%g26, %r29, %r29
	  qplog_0x96,1	%r40, %r39, %r30, %r30
	  qpaddw,3	%g27, %r17, %g27
	  qpsrlw,4	%r13, 0x3, %r17
	}
	{
	  qpaddw,0	%r30, %r10, %r10
	  qpsrcw,1	%r13, _f16s,_lts0hi 0x12, %r34
	  qpsrcw,3	%g27, 0xd, %r32
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x16, %r30
	}
	{
	  qpaddw,0	%r1, %r10, %r1
	  qplog_0x96,1	%r38, %r28, %g23, %g23
	  qplog_0xe8,3	%g27, %g18, %g22, %r39
	  qpsrcw,4	%g27, 0x2, %r10
	}
	{
	  qpaddw,0	%g31, %r1, %g31
	  qpsrcw,1	%r13, 0x7, %r28
	  qpaddw,3	%r6, %b[24], %r6
	  qplog_0x96,4	%r10, %r32, %r30, %r10
	}
	{
	  qpsrcw,0	%g31, 0xb, %r32
	  qpsrcw,1	%g31, _f16s,_lts0lo 0x19, %r30
	  qpaddw,3	%r10, %r39, %r10
	  qpsrlw,4	%r6, 0xa, %r38
	}
	{
	  qplog_0xca,0	%g31, %g26, %g21, %g21
	  qpsrcw,1	%g31, 0x6, %r39
	  qpaddw,3	%r6, %r37, %r37
	  qpsrcw,4	%r6, _f16s,_lts0lo 0x13, %r40
	}
	{
	  qpaddw,0	%g31, %r16, %r16
	  qplog_0x96,1	%r39, %r32, %r30, %r30
	  qpaddw,3	%r1, %r10, %r1
	  qpsrcw,4	%r6, _f16s,_lts0lo 0x11, %r10
	}
	{
	  qpaddw,0	%r30, %g21, %g21
	  qplog_0x96,1	%r28, %r34, %r17, %r17
	  qpsrcw,3	%r1, 0xd, %r32
	  qpsrcw,4	%r1, _f16s,_lts0lo 0x16, %r30
	}
	{
	  qpaddw,0	%r20, %g21, %g21
	  qpsrlw,1	%r6, 0x3, %r34
	  qplog_0xe8,3	%r1, %g27, %g18, %r28
	  qpsrcw,4	%r1, 0x2, %r20
	}
	{
	  qpaddw,0	%g22, %g21, %g22
	  qpsrcw,1	%r6, _f16s,_lts0lo 0x12, %r30
	  qpaddw,3	%g23, %g20, %g23
	  qplog_0x96,4	%r20, %r32, %r30, %r20
	}
	{
	  qpsrcw,0	%g22, 0xb, %r39
	  qpsrcw,1	%g22, _f16s,_lts0lo 0x19, %r32
	  qpaddw,3	%r20, %r28, %r20
	  qplog_0x96,4	%r10, %r40, %r38, %r10
	}
	{
	  qplog_0xca,0	%g22, %g31, %g26, %g26
	  qpsrcw,1	%g22, 0x6, %r28
	  qpaddw,3	%g23, %r31, %g23
	  qpsrcw,4	%r6, 0x7, %r31
	}
	{
	  qpaddw,0	%g22, %r19, %r19
	  qplog_0x96,1	%r28, %r39, %r32, %r28
	  qpaddw,3	%g21, %r20, %g21
	  qpsrlw,4	%g23, 0xa, %r20
	}
	{
	  qpaddw,0	%r28, %g26, %g26
	  qpsrcw,3	%g21, 0xd, %r32
	  qpsrcw,4	%g21, _f16s,_lts0lo 0x16, %r28
	}
	{
	  qpaddw,0	%r25, %g26, %g26
	  qplog_0xe8,3	%g21, %r1, %g27, %r38
	  qpsrcw,4	%g21, 0x2, %r25
	}
	{
	  qpaddw,0	%g18, %g26, %g18
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x13, %r32
	  qpaddw,3	%g23, %r43, %r28
	  qplog_0x96,4	%r25, %r32, %r28, %r25
	}
	{
	  qpsrcw,0	%g18, 0xb, %r40
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %r39
	  qpaddw,3	%r25, %r38, %r25
	  qpsrcw,4	%g23, _f16s,_lts0hi 0x11, %r38
	}
	{
	  qplog_0xca,0	%g18, %g22, %g31, %g31
	  qpsrcw,1	%g18, 0x6, %r42
	  qpaddw,3	%r10, %g19, %r10
	  qplog_0x96,4	%r31, %r30, %r34, %r30
	}
	{
	  qpaddw,0	%g18, %g24, %g24
	  qplog_0x96,1	%r42, %r40, %r39, %r31
	  qpaddw,3	%g26, %r25, %g26
	  qpsrlw,4	%g23, 0x3, %r25
	}
	{
	  qpaddw,0	%r31, %g31, %g31
	  qpsrcw,1	%g23, _f16s,_lts0hi 0x12, %r39
	  qpsrcw,3	%g26, 0xd, %r34
	  qpsrcw,4	%g26, _f16s,_lts0lo 0x16, %r31
	}
	{
	  qpaddw,0	%r29, %g31, %g31
	  qplog_0x96,1	%r38, %r32, %r20, %r20
	  qplog_0xe8,3	%g26, %g21, %r1, %r40
	  qpsrcw,4	%g26, 0x2, %r29
	}
	{
	  qpaddw,0	%g27, %g31, %g27
	  qpsrcw,1	%g23, 0x7, %r31
	  qpaddw,3	%r10, %b[16], %r10
	  qplog_0x96,4	%r29, %r34, %r31, %r29
	}
	{
	  qpsrcw,0	%g27, 0xb, %r34
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x19, %r32
	  qpaddw,3	%r29, %r40, %r29
	  qpsrlw,4	%r10, 0xa, %r38
	}
	{
	  qplog_0xca,0	%g27, %g18, %g22, %g22
	  qpsrcw,1	%g27, 0x6, %r40
	  qpaddw,3	%r10, %r7, %r7
	  qpsrcw,4	%r10, _f16s,_lts0lo 0x13, %r42
	}
	{
	  qpaddw,0	%g27, %r27, %r27
	  qplog_0x96,1	%r40, %r34, %r32, %r32
	  qpaddw,3	%g31, %r29, %g31
	  qpsrcw,4	%r10, _f16s,_lts0lo 0x11, %r29
	}
	{
	  qpaddw,0	%r32, %g22, %g22
	  qplog_0x96,1	%r31, %r39, %r25, %r25
	  qpsrcw,3	%g31, 0xd, %r34
	  qpsrcw,4	%g31, _f16s,_lts0lo 0x16, %r32
	}
	{
	  qpaddw,0	%r16, %g22, %g22
	  qpsrlw,1	%r10, 0x3, %r39
	  qplog_0xe8,3	%g31, %g26, %g21, %r31
	  qpsrcw,4	%g31, 0x2, %r16
	}
	{
	  qpaddw,0	%r1, %g22, %r1
	  qpsrcw,1	%r10, _f16s,_lts0lo 0x12, %r32
	  qpaddw,3	%r20, %g30, %r20
	  qplog_0x96,4	%r16, %r34, %r32, %r16
	}
	{
	  qpsrcw,0	%r1, 0xb, %r40
	  qpsrcw,1	%r1, _f16s,_lts0lo 0x19, %r34
	  qpaddw,3	%r16, %r31, %r16
	  qplog_0x96,4	%r29, %r42, %r38, %r29
	}
	{
	  qplog_0xca,0	%r1, %g27, %g18, %g18
	  qpsrcw,1	%r1, 0x6, %r31
	  qpaddw,3	%r20, %r36, %r20
	  qpsrcw,4	%r10, 0x7, %r36
	}
	{
	  qpaddw,0	%r1, %r35, %r34
	  qplog_0x96,1	%r31, %r40, %r34, %r31
	  qpaddw,3	%g22, %r16, %g22
	  qpsrlw,4	%r20, 0xa, %r16
	}
	{
	  qpaddw,0	%r31, %g18, %g18
	  qpsrcw,3	%g22, 0xd, %r35
	  qpsrcw,4	%g22, _f16s,_lts0lo 0x16, %r31
	}
	{
	  qpaddw,0	%r19, %g18, %g18
	  qplog_0xe8,3	%g22, %g31, %g26, %r38
	  qpsrcw,4	%g22, 0x2, %r19
	}
	{
	  qpaddw,0	%g21, %g18, %g21
	  qpsrcw,1	%r20, _f16s,_lts0lo 0x13, %r35
	  qpaddw,3	%r20, %r46, %r31
	  qplog_0x96,4	%r19, %r35, %r31, %r19
	}
	{
	  qpsrcw,0	%g21, 0xb, %r42
	  qpsrcw,1	%g21, _f16s,_lts0lo 0x19, %r40
	  qpaddw,3	%r19, %r38, %r19
	  qpsrcw,4	%r20, _f16s,_lts0hi 0x11, %r38
	}
	{
	  qplog_0xca,0	%g21, %r1, %g27, %g27
	  qpsrcw,1	%g21, 0x6, %r43
	  qpaddw,3	%r29, %g28, %r29
	  qplog_0x96,4	%r36, %r32, %r39, %r32
	}
	{
	  qpaddw,0	%g21, %r24, %r24
	  qplog_0x96,1	%r43, %r42, %r40, %r36
	  qpaddw,3	%g18, %r19, %g18
	  qpsrlw,4	%r20, 0x3, %r19
	}
	{
	  qpaddw,0	%r36, %g27, %g27
	  qpsrcw,1	%r20, _f16s,_lts0hi 0x12, %r40
	  qpsrcw,3	%g18, 0xd, %r39
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r36
	}
	{
	  qpaddw,0	%g24, %g27, %g24
	  qplog_0x96,1	%r38, %r35, %r16, %r16
	  qplog_0xe8,3	%g18, %g22, %g31, %r42
	  qpsrcw,4	%g18, 0x2, %g27
	}
	{
	  qpaddw,0	%g26, %g24, %g26
	  qpsrcw,1	%r20, 0x7, %r35
	  qpaddw,3	%r29, %r63, %r29
	  qplog_0x96,4	%g27, %r39, %r36, %g27
	}
	{
	  qpsrcw,0	%g26, 0xb, %r38
	  qpsrcw,1	%g26, _f16s,_lts0lo 0x19, %r36
	  qpaddw,3	%g27, %r42, %g27
	  qpsrlw,4	%r29, 0xa, %r39
	}
	{
	  qplog_0xca,0	%g26, %g21, %r1, %r1
	  qpsrcw,1	%g26, 0x6, %r42
	  qpaddw,3	%r29, %r48, %r43
	  qpsrcw,4	%r29, _f16s,_lts0lo 0x13, %r45
	}
	{
	  qpaddw,0	%g26, %r37, %r37
	  qplog_0x96,1	%r42, %r38, %r36, %r36
	  qpaddw,3	%g24, %g27, %g24
	  qpsrcw,4	%r29, _f16s,_lts0lo 0x11, %g27
	}
	{
	  qpaddw,0	%r36, %r1, %r1
	  qplog_0x96,1	%r35, %r40, %r19, %r19
	  qpsrcw,3	%g24, 0xd, %r38
	  qpsrcw,4	%g24, _f16s,_lts0lo 0x16, %r36
	}
	{
	  qpaddw,0	%r27, %r1, %r1
	  qpsrlw,1	%r29, 0x3, %r40
	  qplog_0xe8,3	%g24, %g18, %g22, %r35
	  qpsrcw,4	%g24, 0x2, %r27
	}
	{
	  qpaddw,0	%g31, %r1, %g31
	  qpsrcw,1	%r29, _f16s,_lts0lo 0x12, %r23
	  qpaddw,3	%r12, %r23, %r12
	  qplog_0x96,4	%r27, %r38, %r36, %r27
	}
	{
	  qpsrcw,0	%g31, 0xb, %r38
	  qpsrcw,1	%g31, _f16s,_lts0lo 0x19, %r36
	  qpaddw,3	%r27, %r35, %r27
	  qplog_0x96,4	%g27, %r45, %r39, %g27
	}
	{
	  qplog_0xca,0	%g31, %g26, %g21, %g21
	  qpsrcw,1	%g31, 0x6, %r35
	  qpaddw,3	%r16, %g25, %r16
	  qpsrcw,4	%r29, 0x7, %r39
	}
	{
	  qpaddw,0	%g31, %r28, %r28
	  qplog_0x96,1	%r35, %r38, %r36, %r35
	  qpaddw,3	%r1, %r27, %r1
	}
	{
	  qpaddw,0	%r35, %g21, %g21
	  qpsrcw,3	%r1, 0xd, %r35
	  qpsrcw,4	%r1, _f16s,_lts0lo 0x16, %r27
	}
	{
	  qpaddw,0	%r34, %g21, %g21
	  qplog_0xe8,3	%r1, %g24, %g18, %r36
	  qpsrcw,4	%r1, 0x2, %r34
	}
	{
	  qpaddw,0	%g22, %g21, %g22
	  qplog_0x96,1	%r39, %r23, %r40, %r16
	  qpaddw,3	%r16, %r12, %r12
	  qplog_0x96,4	%r34, %r35, %r27, %r27
	}
	{
	  qpsrcw,0	%g22, 0xb, %r34
	  qpsrcw,1	%g22, _f16s,_lts0lo 0x19, %r23
	  qpaddw,3	%r27, %r36, %r27
	  qpsrlw,4	%r12, 0xa, %r35
	}
	{
	  qplog_0xca,0	%g22, %g31, %g26, %g26
	  qpsrcw,1	%g22, 0x6, %r36
	  qpaddw,3	%r12, %r44, %r38
	  qpsrcw,4	%r12, _f16s,_lts0lo 0x13, %r39
	}
	{
	  qpaddw,0	%g22, %r7, %r7
	  qplog_0x96,1	%r36, %r34, %r23, %r23
	  qpaddw,3	%g21, %r27, %g21
	  qpsrcw,4	%r12, _f16s,_lts0lo 0x11, %r27
	}
	{
	  qpaddw,0	%r23, %g26, %g26
	  qpsrlw,1	%r12, 0x3, %r36
	  qpsrcw,3	%g21, 0xd, %r34
	  qpsrcw,4	%g21, _f16s,_lts0lo 0x16, %r23
	}
	{
	  qpaddw,0	%r24, %g26, %g26
	  qpsrcw,1	%r12, _f16s,_lts0lo 0x12, %r42
	  qplog_0xe8,3	%g21, %r1, %g24, %r40
	  qpsrcw,4	%g21, 0x2, %r24
	}
	{
	  qpaddw,0	%g18, %g26, %g18
	  qpsrcw,1	%r12, 0x7, %r24
	  qpaddw,3	%g16, %r13, %g16
	  qplog_0x96,4	%r24, %r34, %r23, %r23
	}
	{
	  qpsrcw,0	%g18, 0xb, %r44
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %r34
	  qpaddw,3	%r23, %r40, %r23
	  qplog_0x96,4	%r27, %r39, %r35, %r27
	}
	{
	  qplog_0xca,0	%g18, %g22, %g31, %g31
	  qpsrcw,1	%g18, 0x6, %r35
	  qpaddw,3	%g29, %g27, %g27
	}
	{
	  qpaddw,0	%g18, %r31, %r31
	  qplog_0x96,1	%r35, %r44, %r34, %g29
	  qpaddw,3	%g26, %r23, %g26
	}
	{
	  qpaddw,0	%g29, %g31, %g29
	  qplog_0x96,1	%r24, %r42, %r36, %r24
	  qpsrcw,3	%g26, 0xd, %r23
	  qpsrcw,4	%g26, _f16s,_lts0lo 0x16, %g31
	}
	{
	  qpaddw,0	%r37, %g29, %g29
	  qplog_0xe8,3	%g26, %g21, %r1, %r35
	  qpsrcw,4	%g26, 0x2, %r34
	}
	{
	  qpaddw,0	%g24, %g29, %g24
	  qpaddw,3	%g16, %g27, %g16
	  qplog_0x96,4	%r34, %r23, %g31, %g31
	}
	{
	  qpsrcw,0	%g24, 0xb, %r23
	  qpsrcw,1	%g24, _f16s,_lts0lo 0x19, %g27
	  qpaddw,3	%g31, %r35, %g31
	  qpsrlw,4	%g16, 0xa, %r34
	}
	{
	  qplog_0xca,0	%g24, %g18, %g22, %g22
	  qpsrcw,1	%g24, 0x6, %r35
	  qpaddw,3	%g16, %r51, %r36
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x13, %r37
	}
	{
	  qpaddw,0	%g24, %r43, %r23
	  qplog_0x96,1	%r35, %r23, %g27, %g27
	  qpaddw,3	%g29, %g31, %g29
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x11, %g31
	}
	{
	  qpaddw,0	%g27, %g22, %g22
	  qpsrlw,1	%g16, 0x3, %r39
	  qpsrcw,3	%g29, 0xd, %r35
	  qpsrcw,4	%g29, _f16s,_lts0lo 0x16, %g27
	}
	{
	  qpaddw,0	%r28, %g22, %g22
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x12, %r42
	  qplog_0xe8,3	%g29, %g26, %g21, %r40
	  qpsrcw,4	%g29, 0x2, %r28
	}
	{
	  qpaddw,0	%r1, %g22, %r1
	  qpsrcw,1	%g16, 0x7, %r28
	  qpaddw,3	%g17, %r6, %g17
	  qplog_0x96,4	%r28, %r35, %g27, %g27
	}
	{
	  qpsrcw,0	%r1, 0xb, %r43
	  qpsrcw,1	%r1, _f16s,_lts0lo 0x19, %r35
	  qpaddw,3	%g27, %r40, %g27
	  qplog_0x96,4	%g31, %r37, %r34, %g31
	}
	{
	  qplog_0xca,0	%r1, %g24, %g18, %g18
	  qpsrcw,1	%r1, 0x6, %r34
	  qpaddw,3	%r3, %r27, %r3
	}
	{
	  qpaddw,0	%r1, %r38, %r34
	  qplog_0x96,1	%r34, %r43, %r35, %r27
	  qpaddw,3	%g22, %g27, %g22
	}
	{
	  qpaddw,0	%r27, %g18, %g18
	  qplog_0x96,1	%r28, %r42, %r39, %r28
	  qpsrcw,3	%g22, 0xd, %r27
	  qpsrcw,4	%g22, _f16s,_lts0lo 0x16, %g27
	}
	{
	  qpaddw,0	%r7, %g18, %g18
	  qplog_0xe8,3	%g22, %g29, %g26, %r35
	  qpsrcw,4	%g22, 0x2, %r7
	}
	{
	  qpaddw,0	%g21, %g18, %g21
	  qpaddw,3	%g17, %r3, %g17
	  qplog_0x96,4	%r7, %r27, %g27, %g27
	}
	{
	  qpsrcw,0	%g21, 0xb, %r7
	  qpsrcw,1	%g21, _f16s,_lts0lo 0x19, %r3
	  qpaddw,3	%g27, %r35, %g27
	  qpsrlw,4	%g17, 0xa, %r27
	}
	{
	  qplog_0xca,0	%g21, %r1, %g24, %g24
	  qpsrcw,1	%g21, 0x6, %r35
	  qpaddw,3	%g17, %r47, %r37
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x13, %r38
	}
	{
	  qpaddw,0	%g21, %r36, %r7
	  qplog_0x96,1	%r35, %r7, %r3, %r3
	  qpaddw,3	%g18, %g27, %g18
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x11, %g27
	}
	{
	  qpaddw,0	%r3, %g24, %g24
	  qpsrlw,1	%g17, 0x3, %r36
	  qpsrcw,3	%g18, 0xd, %r35
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r3
	}
	{
	  qpaddw,0	%r31, %g24, %g24
	  qpsrcw,1	%g17, _f16s,_lts0lo 0x12, %r40
	  qplog_0xe8,3	%g18, %g22, %g29, %r39
	  qpsrcw,4	%g18, 0x2, %r31
	}
	{
	  qpaddw,0	%g26, %g24, %g26
	  qpsrcw,1	%g17, 0x7, %r31
	  qpaddw,3	%r9, %g23, %r9
	  qplog_0x96,4	%r31, %r35, %r3, %r3
	}
	{
	  qpsrcw,0	%g26, 0xb, %r42
	  qpsrcw,1	%g26, _f16s,_lts0lo 0x19, %r35
	  qpaddw,3	%r3, %r39, %r3
	  qplog_0x96,4	%g27, %r38, %r27, %g27
	}
	{
	  qplog_0xca,0	%g26, %g21, %r1, %r1
	  qpsrcw,1	%g26, 0x6, %r27
	  qpaddw,3	%r26, %g31, %g31
	}
	{
	  qpaddw,0	%g26, %r37, %r27
	  qplog_0x96,1	%r27, %r42, %r35, %r26
	  qpaddw,3	%g24, %r3, %g24
	}
	{
	  qpaddw,0	%r26, %r1, %r1
	  qplog_0x96,1	%r31, %r40, %r36, %r9
	  qpaddw,3	%r9, %g31, %g31
	  qpsrcw,4	%g24, _f16s,_lts0lo 0x16, %r3
	}
	{
	  qpaddw,0	%r23, %r1, %r1
	  qpsrcw,3	%g24, 0x2, %r26
	  qpsrcw,4	%g24, 0xd, %r23
	}
	{
	  qpaddw,0	%g29, %r1, %g29
	  qpaddw,3	%g31, %r49, %r31
	  qplog_0xe8,4	%g24, %g18, %g22, %r35
	}
	{
	  qpsrcw,0	%g29, 0xb, %r37
	  qpsrcw,1	%g29, _f16s,_lts0lo 0x19, %r36
	  qpaddw,3	%r11, %r10, %r11
	  qplog_0x96,4	%r26, %r23, %r3, %r3
	}
	{
	  qplog_0xca,0	%g29, %g26, %g21, %g21
	  qpsrcw,1	%g29, 0x6, %r23
	  qpaddw,3	%r3, %r35, %r3
	  qpsrlw,4	%g31, 0xa, %r26
	}
	{
	  qpaddw,0	%r18, %g27, %g27
	  qplog_0x96,1	%r23, %r37, %r36, %r23
	  qpaddw,3	%r1, %r3, %r1
	  qpsrcw,4	%g31, _f16s,_lts0lo 0x13, %r3
	}
	{
	  qpaddw,0	%r23, %g21, %g21
	  qpsrcw,1	%g31, _f16s,_lts0hi 0x11, %r31
	  qpaddw,3	%g29, %r31, %r18
	  qpsrcw,4	%r1, _f16s,_lts0lo 0x16, %r23
	}
	{
	  qpaddw,0	%r34, %g21, %g21
	  qpsrlw,1	%g31, 0x3, %r36
	  qpsrcw,3	%r1, 0x2, %r35
	  qpsrcw,4	%r1, 0xd, %r34
	}
	{
	  qpaddw,0	%g22, %g21, %g22
	  qpsrcw,1	%g31, _f16s,_lts0lo 0x12, %r34
	  qplog_0x96,3	%r35, %r34, %r23, %r23
	  qplog_0xe8,4	%r1, %g24, %g18, %r37
	}
	{
	  qpsrcw,0	%g22, 0xb, %r38
	  qpsrcw,1	%g22, _f16s,_lts0lo 0x19, %r35
	  qpaddw,3	%r11, %g27, %g27
	  qpsrcw,4	%g31, 0x7, %r11
	}
	{
	  qplog_0xca,0	%g22, %g29, %g26, %g26
	  qpsrcw,1	%g22, 0x6, %r39
	  qpaddw,3	%g27, %r58, %r40
	  qplog_0x96,4	%r31, %r3, %r26, %r3
	}
	{
	  qpaddw,0	%g20, %r20, %g20
	  qplog_0x96,1	%r39, %r38, %r35, %r26
	  qpaddw,3	%r23, %r37, %r23
	  qpsrlw,4	%g27, 0xa, %r31
	}
	{
	  qpaddw,0	%r26, %g26, %g26
	  qpaddw,3	%g22, %r40, %r26
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x13, %r35
	}
	{
	  qpaddw,0	%r7, %g26, %g26
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x11, %r7
	  qpaddw,3	%g21, %r23, %g21
	  qplog_0x96,4	%r11, %r34, %r36, %r11
	}
	{
	  qpaddw,0	%g18, %g26, %g18
	  qpsrlw,1	%g27, 0x3, %r23
	  qpaddw,3	%r15, %r3, %r3
	  qpsrcw,4	%g21, _f16s,_lts0lo 0x16, %r15
	}
	{
	  qpsrcw,0	%g18, 0xb, %r36
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x19, %r34
	  qpaddw,3	%g20, %r3, %g20
	  qpsrcw,4	%g21, 0xd, %r3
	}
	{
	  qplog_0xca,0	%g18, %g22, %g29, %g29
	  qpsrcw,1	%g18, 0x6, %r37
	  qpaddw,3	%g20, %r57, %r39
	  qpsrcw,4	%g21, 0x2, %r38
	}
	{
	  qplog_0xe8,0	%g21, %r1, %g24, %r36
	  qplog_0x96,1	%r37, %r36, %r34, %r34
	  qplog_0x96,3	%r7, %r35, %r31, %r7
	  qplog_0x96,4	%r38, %r3, %r15, %r3
	}
	{
	  qpaddw,0	%r34, %g29, %g29
	  qpsrcw,1	%g27, _f16s,_lts0lo 0x12, %r34
	  qpaddw,3	%g18, %r39, %r15
	  qpsrlw,4	%g20, 0xa, %r31
	}
	{
	  qpaddw,0	%r27, %g29, %g29
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x13, %r27
	  qpaddw,3	%g19, %r29, %g19
	  qpsrcw,4	%g20, _f16s,_lts0hi 0x11, %r35
	}
	{
	  qpaddw,0	%g24, %g29, %g24
	  qpsrcw,1	%g27, 0x7, %r7
	  qpaddw,3	%r2, %r7, %r2
	  qpsrlw,4	%g20, 0x3, %r37
	}
	{
	  qpsrcw,0	%g24, 0xb, %r39
	  qpsrcw,1	%g24, _f16s,_lts0lo 0x19, %r38
	  qpaddw,3	%r3, %r36, %r3
	  qpsrcw,4	%g20, _f16s,_lts0hi 0x12, %r36
	}
	{
	  qplog_0xca,0	%g24, %g18, %g22, %g22
	  qpsrcw,1	%g24, 0x6, %r40
	  qpaddw,3	%g26, %r3, %g26
	  qpsrcw,4	%g20, 0x7, %r3
	}
	{
	  qplog_0x96,0	%r35, %r27, %r31, %r27
	  qplog_0x96,1	%r40, %r39, %r38, %r38
	  qpaddw,3	%g19, %r2, %g19
	  qpsrcw,4	%g26, _f16s,_lts0lo 0x16, %r2
	}
	{
	  qpaddw,0	%r38, %g22, %g22
	  qplog_0x96,1	%r7, %r34, %r23, %r7
	  qpsrcw,3	%g26, 0x2, %r35
	  qpsrcw,4	%g26, 0xd, %r31
	}
	{
	  qpaddw,0	%r18, %g22, %g22
	  qpaddw,3	%g19, %r53, %r18
	  qplog_0xe8,4	%g26, %g21, %r1, %r23
	}
	{
	  qpaddw,0	%r1, %g22, %r1
	  qplog_0x96,1	%r3, %r36, %r37, %r3
	  qpaddw,3	%g24, %r18, %r18
	  qplog_0x96,4	%r35, %r31, %r2, %r2
	}
	{
	  qpsrcw,0	%r1, 0xb, %r34
	  qpsrcw,1	%r1, _f16s,_lts0lo 0x19, %r31
	  qpaddw,3	%r2, %r23, %r2
	  qpsrlw,4	%g19, 0xa, %r23
	}
	{
	  qplog_0xca,0	%r1, %g24, %g18, %g18
	  qpsrcw,1	%r1, 0x6, %r35
	  qpaddw,3	%g29, %r2, %g29
	  qpsrcw,4	%g19, _f16s,_lts0lo 0x13, %r2
	}
	{
	  qpaddw,0	%g30, %r12, %g30
	  qplog_0x96,1	%r35, %r34, %r31, %r31
	  qpaddw,3	%r14, %r27, %r14
	  qpsrcw,4	%g29, _f16s,_lts0lo 0x16, %r27
	}
	{
	  qpaddw,0	%r31, %g18, %g18
	  qpsrcw,1	%g19, _f16s,_lts0lo 0x11, %r35
	  qpsrcw,3	%g29, 0x2, %r34
	  qpsrcw,4	%g29, 0xd, %r31
	}
	{
	  qpaddw,0	%r26, %g18, %g18
	  qpsrlw,1	%g19, 0x3, %r31
	  qplog_0x96,3	%r34, %r31, %r27, %r27
	  qplog_0xe8,4	%g29, %g26, %g21, %r26
	}
	{
	  qpaddw,0	%g21, %g18, %g21
	  qplog_0x96,1	%r35, %r2, %r23, %r2
	  qpaddw,3	%r27, %r26, %r26
	  qpsrcw,4	%g19, _f16s,_lts0lo 0x12, %r23
	}
	{
	  qpsrcw,0	%g21, 0xb, %r34
	  qpsrcw,1	%g21, _f16s,_lts0lo 0x19, %r27
	  qpaddw,3	%g30, %r14, %g30
	  qpsrcw,4	%g19, 0x7, %r14
	}
	{
	  qplog_0xca,0	%g21, %r1, %g24, %g24
	  qpsrcw,1	%g21, 0x6, %r35
	  qpaddw,3	%g30, %r50, %r36
	  qpsrlw,4	%g30, 0xa, %r37
	}
	{
	  qpaddw,0	%g28, %g16, %g28
	  qplog_0x96,1	%r35, %r34, %r27, %r27
	  qpaddw,3	%r1, %r36, %r34
	  qpsrcw,4	%g30, _f16s,_lts0lo 0x13, %r35
	}
	{
	  qpaddw,0	%r27, %g24, %g24
	  qpaddw,3	%g22, %r26, %g22
	  qpsrcw,4	%g30, _f16s,_lts0lo 0x11, %r26
	}
	{
	  qpaddw,0	%r15, %g24, %g24
	  qplog_0x96,1	%r14, %r23, %r31, %r14
	  qpaddw,3	%r21, %r2, %r2
	  qpsrcw,4	%g22, _f16s,_lts0lo 0x16, %r15
	}
	{
	  qpaddw,0	%g26, %g24, %r21
	  qpsrlw,1	%g30, 0x3, %r31
	  qpsrcw,3	%g22, 0x2, %r27
	  qpsrcw,4	%g22, 0xd, %r23
	}
	{
	  qpsrcw,0	%r21, 0xb, %r38
	  qpsrcw,1	%r21, _f16s,_lts0lo 0x19, %r36
	  qpaddw,3	%g28, %r2, %g28
	  qplog_0xe8,4	%g22, %g29, %g26, %g26
	}
	{
	  qplog_0xca,0	%r21, %g21, %r1, %r1
	  qpsrcw,1	%r21, 0x6, %r2
	  qpaddw,3	%g28, %r56, %r39
	  qplog_0x96,4	%r27, %r23, %r15, %r15
	}
	{
	  qplog_0x96,0	%r26, %r35, %r37, %r26
	  qplog_0x96,1	%r2, %r38, %r36, %r2
	  qpaddw,3	%g21, %r39, %r23
	  qpsrlw,4	%g28, 0xa, %r27
	}
	{
	  qpaddw,0	%r2, %r1, %r1
	  qpsrcw,1	%g30, _f16s,_lts0hi 0x12, %r15
	  qpaddw,3	%r15, %g26, %g26
	  qpsrcw,4	%g28, _f16s,_lts0lo 0x13, %r2
	}
	{
	  qpaddw,0	%r18, %r1, %r1
	  qpsrcw,1	%g28, _f16s,_lts0lo 0x11, %g26
	  qpaddw,3	%g18, %g26, %g18
	  qpsrcw,4	%g30, 0x7, %r18
	}
	{
	  qpaddw,0	%g29, %r1, %r35
	  qpsrlw,1	%g28, 0x3, %r37
	  qpaddw,3	%g25, %g17, %g25
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r36
	}
	{
	  qpsrcw,0	%r35, 0xb, %r39
	  qpsrcw,1	%r35, _f16s,_lts0lo 0x19, %r38
	  qpaddw,3	%r17, %r26, %r17
	  qpsrcw,4	%g18, 0xd, %r26
	}
	{
	  qplog_0xca,0	%r35, %r21, %g21, %g21
	  qpsrcw,1	%r35, 0x6, %r40
	  qpaddw,3	%g25, %r17, %g25
	  qpsrcw,4	%g18, 0x2, %r17
	}
	{
	  qplog_0xe8,0	%g18, %g22, %g29, %g29
	  qplog_0x96,1	%r40, %r39, %r38, %r38
	  qpaddw,3	%g25, %r55, %r39
	  qplog_0x96,4	%r17, %r26, %r36, %r17
	}
	{
	  qpaddw,0	%r38, %g21, %g21
	  qplog_0x96,1	%g26, %r2, %r27, %g26
	  qpaddw,3	%r21, %r39, %r26
	  qpsrlw,4	%g25, 0xa, %r2
	}
	{
	  qpaddw,0	%r34, %g21, %g21
	  qplog_0x96,1	%r18, %r15, %r31, %r15
	  qpaddw,3	%r13, %g31, %r13
	  qpsrcw,4	%g25, _f16s,_lts0lo 0x13, %r27
	}
	{
	  qpaddw,0	%g22, %g21, %r18
	  qpsrcw,1	%g25, _f16s,_lts0lo 0x11, %r31
	  qpaddw,3	%r6, %g27, %r6
	  qpsrcw,4	%g28, _f16s,_lts0hi 0x12, %r34
	}
	{
	  qpsrcw,0	%r18, 0xb, %r38
	  qpsrcw,1	%r18, _f16s,_lts0lo 0x19, %r36
	  qpaddw,3	%r17, %g29, %g29
	  qpsrcw,4	%g28, 0x7, %r17
	}
	{
	  qplog_0xca,0	%r18, %r35, %r21, %r21
	  qpsrcw,1	%r18, 0x6, %r39
	  qpaddw,3	%g24, %g29, %g24
	  qplog_0x96,4	%r17, %r34, %r37, %g29
	}
	{
	  qpaddw,0	%r30, %g26, %g26
	  qplog_0x96,1	%r39, %r38, %r36, %r17
	  qpsrcw,3	%g24, 0xd, %r34
	  qpsrcw,4	%g24, _f16s,_lts0lo 0x16, %r30
	}
	{
	  qpaddw,0	%r17, %r21, %r17
	  qplog_0x96,1	%r31, %r27, %r2, %r2
	  qplog_0xe8,3	%g24, %g18, %g22, %g22
	  qpsrcw,4	%g24, 0x2, %r21
	}
	{
	  qpaddw,0	%r23, %r17, %r17
	  qpsrlw,1	%g25, 0x3, %r23
	  qpaddw,3	%g23, %g20, %g23
	  qplog_0x96,4	%r21, %r34, %r30, %r21
	}
	{
	  qpaddw,0	%g18, %r17, %r27
	  qpsrcw,1	%g25, 0x7, %r30
	  qpaddw,3	%r21, %g22, %g22
	  qpsrcw,4	%g25, _f16s,_lts0lo 0x12, %r21
	}
	{
	  qpsrcw,0	%r27, 0xb, %r34
	  qpsrcw,1	%r27, _f16s,_lts0lo 0x19, %r31
	  qpaddw,3	%r13, %g26, %g26
	}
	{
	  qplog_0xca,0	%r27, %r18, %r35, %r36
	  qpsrcw,1	%r27, 0x6, %r13
	  qpaddw,3	%g26, %r33, %r33
	  qpsrlw,4	%g26, 0xa, %r37
	}
	{
	  qpaddw,0	%r25, %r2, %r2
	  qplog_0x96,1	%r13, %r34, %r31, %r13
	  qpaddw,3	%r35, %r33, %r31
	  qpsrcw,4	%g26, _f16s,_lts0lo 0x13, %r25
	}
	{
	  qpaddw,0	%r13, %r36, %r13
	  qplog_0x96,1	%r30, %r21, %r23, %r21
	  qpaddw,3	%r1, %g22, %g22
	  qpsrcw,4	%g26, _f16s,_lts0lo 0x11, %r1
	}
	{
	  qpaddw,0	%r26, %r13, %r13
	  qpsrlw,1	%g26, 0x3, %r30
	  qpsrcw,3	%g22, 0xd, %r26
	  qpsrcw,4	%g22, _f16s,_lts0lo 0x16, %r23
	}
	{
	  qpaddw,0	%g24, %r13, %r33
	  qpsrcw,1	%g26, _f16s,_lts0lo 0x12, %r35
	  qplog_0xe8,3	%g22, %g24, %g18, %g18
	  qpsrcw,4	%g22, 0x2, %r34
	}
	{
	  qpsrcw,0	%r33, 0xb, %r38
	  qpsrcw,1	%r33, _f16s,_lts0lo 0x19, %r36
	  qpaddw,3	%r6, %r2, %r2
	  qplog_0x96,4	%r34, %r26, %r23, %r6
	}
	{
	  qplog_0xca,0	%r33, %r27, %r18, %r26
	  qpsrcw,1	%r33, 0x6, %r23
	  qpaddw,3	%r2, %b[5], %r34
	  qplog_0x96,4	%r1, %r25, %r37, %r1
	}
	{
	  qpaddw,0	%r10, %g19, %r10
	  qplog_0x96,1	%r23, %r38, %r36, %r23
	  qpaddw,3	%r6, %g18, %g18
	  qpsrlw,4	%r2, 0xa, %r6
	}
	{
	  qpaddw,0	%r23, %r26, %r23
	  qpsrcw,1	%g26, 0x7, %r26
	  qpaddw,3	%r18, %r34, %r18
	  qpsrcw,4	%r2, _f16s,_lts0lo 0x13, %r25
	}
	{
	  qpaddw,0	%r31, %r23, %r23
	  qplog_0x96,1	%r26, %r35, %r30, %r26
	  qpaddw,3	%g21, %g18, %g18
	  qpsrcw,4	%r2, _f16s,_lts0lo 0x11, %g21
	}
	{
	  qpaddw,0	%g22, %r23, %r30
	  qpsrlw,1	%r2, 0x3, %r32
	  qpaddw,3	%r32, %r1, %r1
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r31
	}
	{
	  qpsrcw,0	%r30, 0xb, %r35
	  qpsrcw,1	%r30, _f16s,_lts0lo 0x19, %r34
	  qpaddw,3	%g23, %r1, %g23
	  qpsrcw,4	%g18, 0xd, %r1
	}
	{
	  qplog_0xca,0	%r30, %r33, %r27, %r37
	  qpsrcw,1	%r30, 0x6, %r36
	  qpaddw,3	%g23, %b[0], %r39
	  qpsrcw,4	%g18, 0x2, %r38
	}
	{
	  qplog_0xe8,0	%g18, %g22, %g24, %g24
	  qplog_0x96,1	%r36, %r35, %r34, %r34
	  qpaddw,3	%r27, %r39, %r27
	  qplog_0x96,4	%r38, %r1, %r31, %r1
	}
	{
	  qpaddw,0	%r34, %r37, %r31
	  qplog_0x96,1	%g21, %r25, %r6, %g21
	  qpsrcw,3	%g23, _f16s,_lts0lo 0x13, %r25
	  qpsrlw,4	%g23, 0xa, %r6
	}
	{
	  qpaddw,0	%r18, %r31, %r18
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x11, %r31
	  qpaddw,3	%r20, %g30, %r20
	  qpsrcw,4	%r2, _f16s,_lts0hi 0x12, %r34
	}
	{
	  qpaddw,0	%g18, %r18, %r35
	  qpsrlw,1	%g23, 0x3, %r37
	  qpaddw,3	%r29, %g28, %r29
	  qpsrcw,4	%r2, 0x7, %r36
	}
	{
	  qpsrcw,0	%r35, 0xb, %r39
	  qpsrcw,1	%r35, _f16s,_lts0lo 0x19, %r38
	  qpaddw,3	%r1, %g24, %g24
	  qplog_0x96,4	%r36, %r34, %r32, %r1
	}
	{
	  qplog_0xca,0	%r35, %r30, %r33, %r34
	  qpsrcw,1	%r35, 0x6, %r32
	  qpaddw,3	%r17, %g24, %g24
	  qpsrcw,4	%g23, _f16s,_lts0lo 0x12, %r17
	}
	{
	  qpaddw,0	%r19, %g21, %g21
	  qplog_0x96,1	%r32, %r39, %r38, %r32
	  qpsrcw,3	%g24, 0xd, %r36
	  qpsrcw,4	%g24, _f16s,_lts0lo 0x16, %r19
	}
	{
	  qpaddw,0	%r32, %r34, %r32
	  qplog_0x96,1	%r31, %r25, %r6, %r6
	  qplog_0xe8,3	%g24, %g18, %g22, %g22
	  qpsrcw,4	%g24, 0x2, %r34
	}
	{
	  qpaddw,0	%r27, %r32, %r25
	  qpsrcw,1	%g23, 0x7, %r27
	  qpaddw,3	%r12, %g25, %r12
	  qplog_0x96,4	%r34, %r36, %r19, %r19
	}
	{
	  qpaddw,0	%g24, %r25, %r31
	  qplog_0x96,1	%r27, %r17, %r37, %r17
	  qpaddw,3	%r19, %g22, %g22
	}
	{
	  qpaddw,0	%r10, %g21, %g21
	  qpsrcw,1	%r31, _f16s,_lts0lo 0x19, %r10
	  qpaddw,3	%r13, %g22, %g22
	}
	{
	  qpsrcw,0	%r31, 0x6, %r19
	  qpsrcw,1	%r31, 0xb, %r13
	  qpaddw,3	%r16, %r6, %r6
	  qpsrcw,4	%g22, _f16s,_lts0lo 0x16, %r16
	}
	{
	  qpaddw,0	%g21, %r60, %r27
	  qplog_0xca,1	%r31, %r35, %r30, %r32
	  qpaddw,3	%r20, %r6, %r6
	  qpsrcw,4	%g22, 0xd, %r20
	}
	{
	  qpaddw,0	%r33, %r27, %r13
	  qplog_0x96,1	%r19, %r13, %r10, %r10
	  qpaddw,3	%r6, %b[11], %r27
	  qpsrcw,4	%g22, 0x2, %r19
	}
	{
	  qpaddw,0	%r10, %r32, %r10
	  qplog_0xe8,1	%g22, %g24, %g18, %g18
	  qpaddw,3	%r30, %r27, %r19
	  qplog_0x96,4	%r19, %r20, %r16, %r16
	}
	{
	  qpaddw,0	%r13, %r10, %r10
	  qpsrlw,1	%g21, 0xa, %r13
	  qpsrcw,3	%g21, _f16s,_lts0hi 0x11, %r27
	  qpsrcw,4	%g21, _f16s,_lts0lo 0x13, %r20
	}
	{
	  qpaddw,0	%g22, %r10, %r30
	  qpsrlw,1	%r6, 0xa, %r32
	  qpsrcw,3	%r6, _f16s,_lts0hi 0x11, %r34
	  qpsrcw,4	%r6, _f16s,_lts0lo 0x13, %r33
	}
	{
	  qpsrcw,0	%r30, 0xb, %r37
	  qpsrcw,1	%r30, _f16s,_lts0lo 0x19, %r36
	  qpaddw,3	%g16, %g26, %g16
	  qpsrlw,4	%g21, 0x3, %r38
	}
	{
	  qplog_0xca,0	%r30, %r31, %r35, %r40
	  qpsrcw,1	%r30, 0x6, %r39
	  qpaddw,3	%r16, %g18, %g18
	  qpsrcw,4	%g21, _f16s,_lts0lo 0x12, %r16
	}
	{
	  qpaddw,0	%g17, %r2, %g17
	  qplog_0x96,1	%r39, %r37, %r36, %r36
	  qpaddw,3	%r23, %g18, %g18
	  qplog_0x96,4	%r27, %r20, %r13, %r13
	}
	{
	  qpaddw,0	%r36, %r40, %r20
	  qplog_0x96,1	%r34, %r33, %r32, %r24
	  qpaddw,3	%r24, %r13, %r13
	  qpsrcw,4	%g18, _f16s,_lts0lo 0x16, %r23
	}
	{
	  qpaddw,0	%r19, %r20, %r19
	  qpsrcw,1	%g21, 0x7, %r27
	  qpaddw,3	%r29, %r13, %r13
	  qpsrcw,4	%g18, 0xd, %r20
	}
	{
	  qpaddw,0	%r28, %r24, %r24
	  qplog_0x96,1	%r27, %r16, %r38, %r16
	  qpaddw,3	%r13, %b[7], %r32
	  qpsrcw,4	%g18, 0x2, %r29
	}
	{
	  qpaddw,0	%g18, %r19, %r27
	  qplog_0xe8,1	%g18, %g22, %g24, %g24
	  qpaddw,3	%r35, %r32, %r23
	  qplog_0x96,4	%r29, %r20, %r23, %r20
	}
	{
	  qpsrcw,0	%r27, 0xb, %r29
	  qpsrcw,1	%r27, _f16s,_lts0lo 0x19, %r28
	  qpsrcw,3	%r13, _f16s,_lts0hi 0x13, %r33
	  qpsrlw,4	%r13, 0xa, %r32
	}
	{
	  qplog_0xca,0	%r27, %r30, %r31, %r35
	  qpsrcw,1	%r27, 0x6, %r34
	  qpaddw,3	%g31, %g23, %g31
	  qpsrcw,4	%r13, _f16s,_lts0lo 0x11, %r36
	}
	{
	  qpaddw,0	%r12, %r24, %r12
	  qplog_0x96,1	%r34, %r29, %r28, %r28
	  qpaddw,3	%g27, %g21, %g27
	  qplog_0x96,4	%r36, %r33, %r32, %r24
	}
	{
	  qpaddw,0	%r20, %g24, %g24
	  qpsrlw,1	%r12, 0xa, %r20
	  qpaddw,3	%r9, %r24, %r9
	  qpsrlw,4	%r6, 0x3, %r24
	}
	{
	  qpaddw,0	%r28, %r35, %r28
	  qpsrcw,1	%r12, _f16s,_lts0lo 0x13, %r9
	  qpaddw,3	%g16, %r9, %g16
	  qpsrcw,4	%r6, _f16s,_lts0hi 0x12, %r29
	}
	{
	  qpaddw,0	%r18, %g24, %g24
	  qpsrcw,1	%r12, _f16s,_lts0lo 0x11, %r32
	  qpaddw,3	%g16, %b[14], %r18
	  qpsrlw,4	%g16, 0xa, %r33
	}
	{
	  qpaddw,0	%r23, %r28, %r23
	  qpsrcw,1	%g24, _f16s,_lts0lo 0x16, %r28
	  qpaddw,3	%r12, %b[17], %r34
	  qpsrcw,4	%g16, _f16s,_lts0hi 0x13, %r35
	}
	{
	  qpaddw,0	%g24, %r23, %r36
	  qpsrcw,1	%g24, 0xd, %r37
	  qpaddw,3	%r31, %r34, %r31
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x11, %r34
	}
	{
	  qpsrcw,0	%g24, 0x2, %r38
	  qpsrcw,1	%r36, _f16s,_lts0lo 0x19, %r39
	  qpaddw,3	%r30, %r18, %r18
	  qplog_0x96,4	%r34, %r35, %r33, %r33
	}
	{
	  qpsrcw,0	%r36, 0xb, %r34
	  qpsrcw,1	%r36, 0x6, %r35
	  qplog_0x96,3	%r32, %r9, %r20, %r9
	  qplog_0xe8,4	%g24, %g18, %g22, %g22
	}
	{
	  qplog_0xca,0	%r36, %r27, %r30, %r28
	  qplog_0x96,1	%r38, %r37, %r28, %r20
	  qpaddw,3	%r11, %r9, %r9
	  qpsrcw,4	%r6, 0x7, %r11
	}
	{
	  qpaddw,0	%g20, %r6, %g20
	  qplog_0x96,1	%r35, %r34, %r39, %r30
	  qpaddw,3	%g17, %r9, %g17
	  qplog_0x96,4	%r11, %r29, %r24, %r6
	}
	{
	  qpaddw,0	%r30, %r28, %r9
	  qpaddw,3	%g17, %b[18], %r11
	  qpsrlw,4	%g17, 0xa, %r24
	}
	{
	  qpaddw,0	%r20, %g22, %g22
	  qpaddw,3	%r27, %r11, %r11
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x13, %r20
	}
	{
	  qpaddw,0	%r31, %r9, %r9
	  qpaddw,3	%r7, %r33, %r7
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x11, %r28
	}
	{
	  qpaddw,0	%r25, %g22, %g22
	  qpaddw,3	%g31, %r7, %g31
	  qplog_0x96,4	%r28, %r20, %r24, %r7
	}
	{
	  qpaddw,0	%g22, %r9, %r20
	  qpsrcw,1	%g22, _f16s,_lts0lo 0x16, %r24
	  qpaddw,3	%g31, %b[8], %r25
	  qpsrlw,4	%g31, 0xa, %r28
	}
	{
	  qpsrcw,0	%g22, 0xd, %r29
	  qpsrcw,1	%g22, 0x2, %r30
	  qpaddw,3	%r36, %r25, %r25
	  qpsrcw,4	%g31, _f16s,_lts0lo 0x13, %r31
	}
	{
	  qpsrcw,0	%r20, _f16s,_lts0lo 0x19, %r32
	  qpsrcw,1	%r20, 0xb, %r33
	  qpaddw,3	%r3, %r7, %r3
	  qpsrcw,4	%g31, _f16s,_lts0hi 0x11, %r7
	}
	{
	  qplog_0xe8,0	%g22, %g24, %g18, %g18
	  qpsrcw,1	%r20, 0x6, %r34
	  qpaddw,3	%g27, %r3, %g27
	  qplog_0x96,4	%r7, %r31, %r28, %r3
	}
	{
	  qplog_0xca,0	%r20, %r36, %r27, %r24
	  qplog_0x96,1	%r30, %r29, %r24, %r7
	  qpaddw,3	%g27, %b[10], %r27
	  qpsrlw,4	%g27, 0xa, %r28
	}
	{
	  qpaddw,0	%r7, %g18, %g18
	  qplog_0x96,1	%r34, %r33, %r32, %r29
	  qpaddw,3	%r20, %r27, %r7
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x13, %r27
	}
	{
	  qpaddw,0	%r29, %r24, %r24
	  qpaddw,3	%r14, %r3, %r3
	  qpsrcw,4	%g27, _f16s,_lts0lo 0x11, %r14
	}
	{
	  qpaddw,0	%r10, %g18, %g18
	  qpaddw,3	%g20, %r3, %g20
	  qplog_0x96,4	%r14, %r27, %r28, %r3
	}
	{
	  qpaddw,0	%r18, %r24, %r10
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x16, %r14
	  qpaddw,3	%g20, %b[13], %r18
	  qpsrlw,4	%g20, 0xa, %r24
	}
	{
	  qpaddw,0	%g18, %r10, %r27
	  qpsrcw,1	%g18, 0xd, %r28
	  qpaddw,3	%g19, %r13, %g19
	  qpsrcw,4	%g20, _f16s,_lts0lo 0x13, %r13
	}
	{
	  qpsrcw,0	%g18, 0x2, %r29
	  qpsrcw,1	%r27, _f16s,_lts0lo 0x19, %r30
	  qpaddw,3	%r15, %r3, %r3
	  qpsrcw,4	%g20, _f16s,_lts0hi 0x11, %r15
	}
	{
	  qpsrcw,0	%r27, 0x6, %r32
	  qpsrcw,1	%r27, 0xb, %r31
	  qpaddw,3	%g19, %r3, %g19
	  qplog_0xe8,4	%g18, %g22, %g24, %g24
	}
	{
	  qplog_0xca,0	%r27, %r20, %r36, %r14
	  qplog_0x96,1	%r29, %r28, %r14, %r3
	  qpaddw,3	%g19, %b[27], %r28
	  qplog_0x96,4	%r15, %r13, %r24, %r13
	}
	{
	  qpaddw,0	%r27, %r18, %r18
	  qplog_0x96,1	%r32, %r31, %r30, %r15
	  qpaddw,3	%g30, %r12, %g30
	  qpsrlw,4	%g19, 0xa, %r12
	}
	{
	  qpaddw,0	%r15, %r14, %r14
	  qpaddw,3	%g29, %r13, %g29
	  qpsrcw,4	%g19, _f16s,_lts0lo 0x13, %r13
	}
	{
	  qpaddw,0	%r3, %g24, %g24
	  qpsrcw,1	%g19, _f16s,_lts0lo 0x11, %g30
	  qpaddw,3	%g30, %g29, %g29
	}
	{
	  qpaddw,0	%r11, %r14, %r3
	  qpaddw,3	%g29, %b[19], %r11
	  qpsrlw,4	%g29, 0xa, %r14
	}
	{
	  qpaddw,0	%r19, %g24, %g24
	  qpaddw,3	%g28, %g16, %g16
	  qpsrcw,4	%g29, _f16s,_lts0lo 0x13, %g28
	}
	{
	  qpaddw,0	%g24, %r3, %r15
	  qpsrcw,1	%g24, _f16s,_lts0lo 0x16, %r19
	  qpaddw,3	%g25, %g17, %g17
	  qpsrcw,4	%g29, _f16s,_lts0hi 0x11, %g29
	}
	{
	  qpsrcw,0	%g24, 0xd, %g25
	  qpsrcw,1	%g24, 0x2, %r24
	  qplog_0x96,3	%g29, %g28, %r14, %g28
	  qplog_0x96,4	%g30, %r13, %r12, %g30
	}
	{
	  qpsrcw,0	%r15, _f16s,_lts0lo 0x19, %g29
	  qpsrcw,1	%r15, 0xb, %r12
	  qpaddw,3	%r21, %g30, %g30
	}
	{
	  qplog_0xe8,0	%g24, %g18, %g22, %g22
	  qpsrcw,1	%r15, 0x6, %r13
	  qpaddw,3	%g16, %g30, %g16
	}
	{
	  qplog_0xca,0	%r15, %r27, %r20, %g30
	  qplog_0x96,1	%r24, %g25, %r19, %g25
	  qpaddw,3	%r15, %r28, %r14
	  qpsrlw,4	%g16, 0xa, %r19
	}
	{
	  qpaddw,0	%g25, %g22, %g22
	  qplog_0x96,1	%r13, %r12, %g29, %g29
	  qpaddw,3	%g16, %b[3], %g25
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x13, %r12
	}
	{
	  qpaddw,0	%g29, %g30, %g29
	  qpaddw,3	%r26, %g28, %g28
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x11, %g16
	}
	{
	  qpaddw,0	%r23, %g22, %g22
	  qpaddw,3	%g17, %g28, %g17
	  qplog_0x96,4	%g16, %r12, %r19, %g16
	}
	{
	  qpaddw,0	%r25, %g29, %g28
	  qpsrcw,1	%g22, _f16s,_lts0lo 0x16, %g29
	  qpaddw,3	%g17, %b[21], %g30
	  qpsrlw,4	%g17, 0xa, %r12
	}
	{
	  qpaddw,0	%g22, %g28, %r13
	  qpsrcw,1	%g22, 0xd, %r19
	  qpaddw,3	%g26, %g31, %g26
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x13, %g31
	}
	{
	  qpsrcw,0	%g22, 0x2, %r20
	  qpsrcw,1	%r13, _f16s,_lts0lo 0x19, %r21
	  qpaddw,3	%r1, %g16, %g16
	  qpsrcw,4	%g17, _f16s,_lts0hi 0x11, %g17
	}
	{
	  qpsrcw,0	%r13, 0x6, %r23
	  qpsrcw,1	%r13, 0xb, %r1
	  qpaddw,3	%g26, %g16, %g16
	  qplog_0xe8,4	%g22, %g24, %g18, %g18
	}
	{
	  qplog_0xca,0	%r13, %r15, %r27, %g29
	  qplog_0x96,1	%r20, %r19, %g29, %g26
	  qpaddw,3	%g16, %b[2], %r19
	  qplog_0x96,4	%g17, %g31, %r12, %g17
	}
	{
	  qpaddw,0	%r13, %r11, %r1
	  qplog_0x96,1	%r23, %r1, %r21, %g31
	  qpaddw,3	%r2, %g27, %g27
	  qpsrlw,4	%g16, 0xa, %r2
	}
	{
	  qpaddw,0	%g31, %g29, %g29
	  qpaddw,3	%r17, %g17, %g17
	  qpsrcw,4	%g16, _f16s,_lts0lo 0x13, %g31
	}
	{
	  qpaddw,0	%g26, %g18, %g18
	  qpsrcw,1	%g16, _f16s,_lts0lo 0x11, %g16
	  qpaddw,3	%g27, %g17, %g17
	}
	{
	  qpaddw,0	%r7, %g29, %g26
	  qpaddw,3	%g17, %r41, %g27
	  qpsrlw,4	%g17, 0xa, %g29
	}
	{
	  qpaddw,0	%r9, %g18, %g18
	  qpaddw,3	%g23, %g20, %g20
	  qpsrcw,4	%g17, _f16s,_lts0lo 0x13, %g23
	}
	{
	  qpaddw,0	%g18, %g26, %r7
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x16, %r9
	  qpaddw,3	%g21, %g19, %g19
	  qpsrcw,4	%g17, _f16s,_lts0hi 0x11, %g17
	}
	{
	  qpsrcw,0	%g18, 0xd, %g21
	  qpsrcw,1	%g18, 0x2, %r11
	  qplog_0x96,3	%g16, %g31, %r2, %g16
	  qplog_0x96,4	%g17, %g23, %g29, %g17
	}
	{
	  qpsrcw,0	%r7, _f16s,_lts0lo 0x19, %g23
	  qpsrcw,1	%r7, 0xb, %g29
	  qpaddw,3	%r16, %g16, %g16
	}
	{
	  qplog_0xe8,0	%g18, %g22, %g24, %g24
	  qpsrcw,1	%r7, 0x6, %g31
	  qpaddw,3	%g20, %g16, %g16
	}
	{
	  qplog_0xca,0	%r7, %r13, %r15, %g21
	  qplog_0x96,1	%r11, %g21, %r9, %g20
	  qpaddw,3	%r7, %g25, %g25
	}
	{
	  qpaddw,0	%g20, %g24, %g20
	  qplog_0x96,1	%g31, %g29, %g23, %g23
	  qpaddw,3	%g16, %r22, %g16
	}
	{
	  qpaddw,0	%g23, %g21, %g21
	  qpaddw,3	%r6, %g17, %g17
	}
	{
	  qpaddw,0	%r10, %g20, %g20
	  qpaddw,3	%g19, %g17, %g17
	}
	{
	  qpaddw,0	%r18, %g21, %g19
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x16, %g21
	  qpaddw,3	%g17, %b[23], %g17
	}
	{
	  qpaddw,0	%g20, %g19, %g23
	  qpsrcw,1	%g20, 0xd, %g24
	}
	{
	  qpsrcw,0	%g20, 0x2, %g29
	  qpsrcw,1	%g23, _f16s,_lts0lo 0x19, %g31
	}
	{
	  qpsrcw,0	%g23, 0x6, %r6
	  qpsrcw,1	%g23, 0xb, %r2
	  qplog_0xe8,4	%g20, %g18, %g22, %g22
	}
	{
	  qplog_0xca,0	%g23, %r7, %r13, %g24
	  qplog_0x96,1	%g29, %g24, %g21, %g21
	}
	{
	  qpaddw,0	%g23, %g30, %g30
	  qplog_0x96,1	%r6, %r2, %g31, %g29
	}
	{
	  qpaddw,0	%g29, %g24, %g24
	}
	{
	  qpaddw,0	%g21, %g22, %g21
	}
	{
	  qpaddw,0	%r14, %g24, %g22
	}
	{
	  qpaddw,0	%r3, %g21, %g21
	}
	{
	  qpaddw,0	%g21, %g22, %g24
	  qpsrcw,1	%g21, _f16s,_lts0lo 0x16, %g29
	}
	{
	  qpsrcw,0	%g21, 0xd, %g31
	  qpsrcw,1	%g21, 0x2, %r2
	  stqp,2	%r0, _f16s,_lts0lo 0x60, %g24
	}
	{
	  qpsrcw,0	%g24, _f16s,_lts0lo 0x19, %r3
	  qpsrcw,1	%g24, 0xb, %r6
	}
	{
	  qpsrcw,0	%g24, 0x6, %r9
	  qplog_0xe8,1	%g21, %g20, %g18, %g18
	}
	{
	  qplog_0x96,0	%r2, %g31, %g29, %g29
	  qplog_0xca,1	%g24, %g23, %r7, %g31
	}
	{
	  qpaddw,0	%g29, %g18, %g18
	  qplog_0x96,1	%r9, %r6, %r3, %r2
	}
	{
	  qpaddw,0	%r2, %g31, %g29
	}
	{
	  qpaddw,0	%g28, %g18, %g18
	}
	{
	  qpaddw,0	%r1, %g29, %g28
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x16, %g29
	}
	{
	  qpaddw,0	%g18, %g28, %g31
	  qpsrcw,1	%g18, 0xd, %r1
	}
	{
	  qpsrcw,0	%g18, 0x2, %r2
	  qpsrcw,1	%g31, _f16s,_lts0lo 0x19, %r3
	  stqp,2	%r0, _f16s,_lts0hi 0x50, %g31
	}
	{
	  qpsrcw,0	%g31, 0xb, %r6
	  qpsrcw,1	%g31, 0x6, %r7
	  qplog_0xe8,3	%g18, %g21, %g20, %g20
	}
	{
	  qplog_0x96,0	%r2, %r1, %g29, %g29
	  qplog_0xca,1	%g31, %g24, %g23, %g23
	}
	{
	  qplog_0x96,0	%r7, %r6, %r3, %r1
	}
	{
	  qpaddw,0	%r1, %g23, %g23
	}
	{
	  qpaddw,0	%g29, %g20, %g20
	}
	{
	  qpaddw,0	%g25, %g23, %g23
	}
	{
	  qpaddw,0	%g26, %g20, %g20
	}
	{
	  qpaddw,0	%g20, %g23, %g25
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x16, %g26
	}
	{
	  qpsrcw,0	%g20, 0xd, %g29
	  qpsrcw,1	%g20, 0x2, %r1
	  stqp,2	%r0, _f16s,_lts0lo 0x40, %g25
	}
	{
	  qplog_0xe8,0	%g20, %g18, %g21, %g21
	  qplog_0x96,1	%r1, %g29, %g26, %g26
	}
	{
	  qpsrcw,0	%g25, 0xb, %r1
	  qpsrcw,1	%g25, _f16s,_lts0lo 0x19, %g29
	}
	{
	  qpaddw,0	%g26, %g21, %g21
	  qpsrcw,1	%g25, 0x6, %r2
	  qplog_0xca,3	%g25, %g31, %g24, %g26
	}
	{
	  qpaddw,0	%g19, %g21, %g19
	  qplog_0x96,1	%r2, %r1, %g29, %g29
	}
	{
	  qpsrcw,0	%g19, _f16s,_lts0lo 0x16, %g21
	  qpsrcw,1	%g19, 0xd, %r1
	}
	{
	  qpsrcw,0	%g19, 0x2, %r2
	  qplog_0xe8,1	%g19, %g20, %g18, %g18
	}
	{
	  qpaddw,0	%g29, %g26, %g26
	  qplog_0x96,1	%r2, %r1, %g21, %g21
	}
	{
	  qpaddw,0	%g30, %g26, %g26
	}
	{
	  qpaddw,0	%g19, %g26, %g29
	}
	{
	  qpaddw,0	%g21, %g18, %g18
	  qpsrcw,1	%g29, _f16s,_lts0lo 0x19, %g21
	  stqp,2	%r0, _f16s,_lts0hi 0x30, %g29
	}
	{
	  qpsrcw,0	%g29, 0x6, %r1
	  qpsrcw,1	%g29, 0xb, %g30
	}
	{
	  qpaddw,0	%g22, %g18, %g18
	  qplog_0xca,1	%g29, %g25, %g31, %g22
	}
	{
	  qpaddw,0	%g18, %g24, %g24
	  qplog_0x96,1	%r1, %g30, %g21, %g21
	}
	{
	  qpaddw,0	%g21, %g22, %g21
	  qpsrcw,1	%g18, _f16s,_lts0lo 0x16, %g22
	}
	{
	  qpaddw,0	%g24, %g21, %g21
	  qpsrcw,1	%g18, 0xd, %g24
	}
	{
	  qpaddw,0	%g21, %r19, %g21
	  qpsrcw,1	%g18, 0x2, %g30
	  qplog_0xe8,3	%g18, %g19, %g20, %g20
	}
	{
	  qplog_0x96,0	%g30, %g24, %g22, %g22
	  qpsrcw,1	%g21, _f16s,_lts0lo 0x19, %g24
	  stqp,2	%r0, _f16s,_lts0hi 0x20, %g21
	}
	{
	  qpsrcw,0	%g21, 0xb, %g30
	  qpsrcw,1	%g21, 0x6, %r1
	}
	{
	  qplog_0xca,0	%g21, %g29, %g25, %r2
	  qplog_0x96,1	%r1, %g30, %g24, %g24
	}
	{
	  qpaddw,0	%g22, %g20, %g20
	}
	{
	  qpaddw,0	%g28, %g20, %g20
	}
	{
	  qpaddw,0	%g24, %r2, %g22
	  qpsrcw,1	%g20, _f16s,_lts0lo 0x16, %g24
	}
	{
	  qpaddw,0	%g20, %g31, %g28
	  qpsrcw,1	%g20, 0xd, %g30
	}
	{
	  qpaddw,0	%g28, %g22, %g22
	  qpsrcw,1	%g20, 0x2, %g28
	}
	{
	  qpaddw,0	%g22, %g27, %g22
	  qplog_0xe8,1	%g20, %g18, %g19, %g19
	}
	{
	  qplog_0x96,0	%g28, %g30, %g24, %g24
	  qpsrcw,1	%g22, _f16s,_lts0lo 0x19, %g27
	  stqp,2	0x10, %r0, %g22
	}
	{
	  qpaddw,0	%g24, %g19, %g19
	  qpsrcw,1	%g22, 0xb, %g24
	}
	{
	  qpaddw,0	%g23, %g19, %g19
	  qpsrcw,1	%g22, 0x6, %g28
	}
	{
	  qplog_0x96,0	%g28, %g24, %g27, %g24
	  qplog_0xca,1	%g22, %g21, %g29, %g23
	}
	{
	  qpaddw,0	%g19, %g25, %g25
	  qpsrcw,1	%g19, _f16s,_lts0lo 0x16, %g27
	}
	{
	  qpaddw,0	%g24, %g23, %g23
	  qpsrcw,1	%g19, 0xd, %g24
	}
	{
	  qpaddw,0	%g25, %g23, %g23
	  qpsrcw,1	%g19, 0x2, %g25
	  qplog_0xe8,3	%g19, %g20, %g18, %g18
	}
	{
	  qpaddw,0	%g23, %g16, %g16
	  qplog_0x96,1	%g25, %g24, %g27, %g19
	}
	{
	  qpsrcw,0	%g16, _f16s,_lts0lo 0x19, %g20
	  qpsrcw,1	%g16, 0xb, %g23
	  stqp,2	%r0, 0x0, %g16
	}
	{
	  qpsrcw,0	%g16, 0x6, %g24
	  qplog_0xca,1	%g16, %g22, %g21, %g16
	}
	{
	  qpaddw,0	%g19, %g18, %g18
	  qplog_0x96,1	%g24, %g23, %g20, %g19
	}
	{
	  qpaddw,0	%g26, %g18, %g18
	}
	{
	  qpaddw,0	%g19, %g16, %g16
	}
	{
	  qpaddw,0	%g18, %g29, %g18
	}
	{
	  qpaddw,0	%g18, %g16, %g16
	}
	{
	  qpaddw,0	%g16, %g17, %g16
	}
	{
	  ct	%ctpr3
	  stqp,2	%r0, _f16s,_lts0lo 0x70, %g16
	}
	.size	sha256d_ms_4way, .- sha256d_ms_4way
	.section .rodata
	.local	sha256_k_as_words
	.type	sha256_k_as_words, #object
	.size	sha256_k_as_words, 0x400
	.align	16
sha256_k_as_words:
	.uadword	0x428a2f98428a2f98
	.uadword	0x428a2f98428a2f98
	.uadword	0x7137449171374491
	.uadword	0x7137449171374491
	.uadword	0xb5c0fbcfb5c0fbcf
	.uadword	0xb5c0fbcfb5c0fbcf
	.uadword	0xe9b5dba5e9b5dba5
	.uadword	0xe9b5dba5e9b5dba5
	.uadword	0x3956c25b3956c25b
	.uadword	0x3956c25b3956c25b
	.uadword	0x59f111f159f111f1
	.uadword	0x59f111f159f111f1
	.uadword	0x923f82a4923f82a4
	.uadword	0x923f82a4923f82a4
	.uadword	0xab1c5ed5ab1c5ed5
	.uadword	0xab1c5ed5ab1c5ed5

	.uadword	0xd807aa98d807aa98
	.uadword	0xd807aa98d807aa98
	.uadword	0x12835b0112835b01
	.uadword	0x12835b0112835b01
	.uadword	0x243185be243185be
	.uadword	0x243185be243185be
	.uadword	0x550c7dc3550c7dc3
	.uadword	0x550c7dc3550c7dc3
	.uadword	0x72be5d7472be5d74
	.uadword	0x72be5d7472be5d74
	.uadword	0x80deb1fe80deb1fe
	.uadword	0x80deb1fe80deb1fe
	.uadword	0x9bdc06a79bdc06a7
	.uadword	0x9bdc06a79bdc06a7
	.uadword	0xc19bf174c19bf174
	.uadword	0xc19bf174c19bf174

	.uadword	0xe49b69c1e49b69c1
	.uadword	0xe49b69c1e49b69c1
	.uadword	0xefbe4786efbe4786
	.uadword	0xefbe4786efbe4786
	.uadword	0xfc19dc60fc19dc6
	.uadword	0xfc19dc60fc19dc6
	.uadword	0x240ca1cc240ca1cc
	.uadword	0x240ca1cc240ca1cc
	.uadword	0x2de92c6f2de92c6f
	.uadword	0x2de92c6f2de92c6f
	.uadword	0x4a7484aa4a7484aa
	.uadword	0x4a7484aa4a7484aa
	.uadword	0x5cb0a9dc5cb0a9dc
	.uadword	0x5cb0a9dc5cb0a9dc
	.uadword	0x76f988da76f988da
	.uadword	0x76f988da76f988da

	.uadword	0x983e5152983e5152
	.uadword	0x983e5152983e5152
	.uadword	0xa831c66da831c66d
	.uadword	0xa831c66da831c66d
	.uadword	0xb00327c8b00327c8
	.uadword	0xb00327c8b00327c8
	.uadword	0xbf597fc7bf597fc7
	.uadword	0xbf597fc7bf597fc7
	.uadword	0xc6e00bf3c6e00bf3
	.uadword	0xc6e00bf3c6e00bf3
	.uadword	0xd5a79147d5a79147
	.uadword	0xd5a79147d5a79147
	.uadword	0x6ca635106ca6351
	.uadword	0x6ca635106ca6351
	.uadword	0x1429296714292967
	.uadword	0x1429296714292967

	.uadword	0x27b70a8527b70a85
	.uadword	0x27b70a8527b70a85
	.uadword	0x2e1b21382e1b2138
	.uadword	0x2e1b21382e1b2138
	.uadword	0x4d2c6dfc4d2c6dfc
	.uadword	0x4d2c6dfc4d2c6dfc
	.uadword	0x53380d1353380d13
	.uadword	0x53380d1353380d13
	.uadword	0x650a7354650a7354
	.uadword	0x650a7354650a7354
	.uadword	0x766a0abb766a0abb
	.uadword	0x766a0abb766a0abb
	.uadword	0x81c2c92e81c2c92e
	.uadword	0x81c2c92e81c2c92e
	.uadword	0x92722c8592722c85
	.uadword	0x92722c8592722c85

	.uadword	0xa2bfe8a1a2bfe8a1
	.uadword	0xa2bfe8a1a2bfe8a1
	.uadword	0xa81a664ba81a664b
	.uadword	0xa81a664ba81a664b
	.uadword	0xc24b8b70c24b8b70
	.uadword	0xc24b8b70c24b8b70
	.uadword	0xc76c51a3c76c51a3
	.uadword	0xc76c51a3c76c51a3
	.uadword	0xd192e819d192e819
	.uadword	0xd192e819d192e819
	.uadword	0xd6990624d6990624
	.uadword	0xd6990624d6990624
	.uadword	0xf40e3585f40e3585
	.uadword	0xf40e3585f40e3585
	.uadword	0x106aa070106aa070
	.uadword	0x106aa070106aa070

	.uadword	0x19a4c11619a4c116
	.uadword	0x19a4c11619a4c116
	.uadword	0x1e376c081e376c08
	.uadword	0x1e376c081e376c08
	.uadword	0x2748774c2748774c
	.uadword	0x2748774c2748774c
	.uadword	0x34b0bcb534b0bcb5
	.uadword	0x34b0bcb534b0bcb5
	.uadword	0x391c0cb3391c0cb3
	.uadword	0x391c0cb3391c0cb3
	.uadword	0x4ed8aa4a4ed8aa4a
	.uadword	0x4ed8aa4a4ed8aa4a
	.uadword	0x5b9cca4f5b9cca4f
	.uadword	0x5b9cca4f5b9cca4f
	.uadword	0x682e6ff3682e6ff3
	.uadword	0x682e6ff3682e6ff3

	.uadword	0x748f82ee748f82ee
	.uadword	0x748f82ee748f82ee
	.uadword	0x78a5636f78a5636f
	.uadword	0x78a5636f78a5636f
	.uadword	0x84c8781484c87814
	.uadword	0x84c8781484c87814
	.uadword	0x8cc702088cc70208
	.uadword	0x8cc702088cc70208
	.uadword	0x90befffa90befffa
	.uadword	0x90befffa90befffa
	.uadword	0xa4506ceba4506ceb
	.uadword	0xa4506ceba4506ceb
	.uadword	0xbef9a3f7bef9a3f7
	.uadword	0xbef9a3f7bef9a3f7
	.uadword	0xc67178f2c67178f2
	.uadword	0xc67178f2c67178f2

	.local	sha256d_hash1_as_words
	.type	sha256d_hash1_as_words, #object
	.size	sha256d_hash1_as_words, 0x100
	.align	16
sha256d_hash1_as_words:
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0

	.uadword	0x8000000080000000
	.uadword	0x8000000080000000
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x10000000100
	.uadword	0x10000000100

	.local	sha256_h_as_words
	.type	sha256_h_as_words, #object
	.size	sha256_h_as_words, 0x80
	.align	16
sha256_h_as_words:
	.uadword	0x6a09e6676a09e667
	.uadword	0x6a09e6676a09e667
	.uadword	0xbb67ae85bb67ae85
	.uadword	0xbb67ae85bb67ae85
	.uadword	0x3c6ef3723c6ef372
	.uadword	0x3c6ef3723c6ef372
	.uadword	0xa54ff53aa54ff53a
	.uadword	0xa54ff53aa54ff53a
	.uadword	0x510e527f510e527f
	.uadword	0x510e527f510e527f
	.uadword	0x9b05688c9b05688c
	.uadword	0x9b05688c9b05688c
	.uadword	0x1f83d9ab1f83d9ab
	.uadword	0x1f83d9ab1f83d9ab
	.uadword	0x5be0cd195be0cd19
	.uadword	0x5be0cd195be0cd19

	.weak	elbrus_optimizing_compiler_v1.24.11_May_26_2020
	elbrus_optimizing_compiler_v1.24.11_May_26_2020 = 0x0
