	.file	"scrypt-e2k.c"
	.ignore	ld_st_style
	.ignore	strict_delay
	.text
	.local	HMAC_SHA256_80_init
	.type	HMAC_SHA256_80_init, #function
	.align	8
HMAC_SHA256_80_init:
	{
	  setwd	wsz = 0xe, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x3, rbs = 0xa, rcur = 0x0
	  disp	%ctpr1, sha256_transform
	  getsp,0	_f32s,_lts2 0xffffff80, %r4
	  ldw,2	%r0, _f32s,_lts3 0x44, %r7
	  ldw,3	%r0, _f16s,_lts1lo 0x4c, %r5
	  ldw,5	%r0, _f16s,_lts1hi 0x48, %r6
	}
	{
	  ldw,0	%r0, _f16s,_lts0lo 0x40, %r9
	  addd,1,sm	0x0, %r1, %b[0]
	  ldqp,2	0x0, [ _f64,_lts2 keypad ], %r10
	  addd,3,sm	0x0, 0x0, %b[2]
	  adds,4	0x0, _f32s,_lts1 0x5c5c5c5c, %r11
	}
	{
	  addd,0	%r4, _f64,_lts0 0x80, %r3
	  ldqp,2	0x0, [ _f64,_lts2 keypad +32 ], %r12
	  adds,3	0x0, %r11, %r13
	}
	{
	  addd,0	%r3, _f16s,_lts0lo 0xffa0, %r6
	  ldqp,2	0x0, [ _f64,_lts2 keypad +16 ], %r14
	  insfd,3	%r5, _f32s,_lts1 0xa820, %r6, %r5
	}
	{
	  insfd,0	%r7, _f32s,_lts0 0xa820, %r9, %r7
	  addd,1,sm	0x0, %r6, %b[1]
	  adds,2	0x0, _f32s,_lts1 0x36363636, %r9
	  addd,3	0x0, _f64,_lts2 0x3636363636363636, %r15
	}
	{
	  qppackdl,0	%r5, %r7, %r5
	  stqp,2	%r3, _f16s,_lts0lo 0xffb0, %r10
	}
	{
	  stqp,2	%r3, _f16s,_lts0lo 0xffd0, %r12
	}
	{
	  stqp,2	%r3, _f16s,_lts0lo 0xffa0, %r5
	  stqp,5	%r3, _f16s,_lts0hi 0xffc0, %r14
	}
.LCS.1:
	{
	  call	%ctpr1, wbs = 0xa
	}
	{
	  disp	%ctpr1, sha256_init
	  ldw,0	%r1, _f16s,_lts0lo 0x1c, %r5
	  addd,1,sm	0x0, %r2, %b[0]
	  ldw,2	%r1, _f16s,_lts0hi 0x18, %r7
	  ldw,3	%r1, _f16s,_lts1lo 0x14, %r10
	  ldw,5	0x10, %r1, %r12
	}
	{
	  nop 1
	  ldw,0	%r1, 0xc, %r14
	  ldw,2	%r1, 0x8, %r16
	  ldw,3	%r1, 0x4, %r17
	  ldw,5	%r1, 0x0, %r18
	}
	{
	  insfd,0	%r5, _f32s,_lts0 0xa820, %r7, %r5
	  insfd,3	%r10, _lit32_ref,_lts0 0xa820, %r12, %r7
	}
	{
	  insfd,0	%r14, _f32s,_lts0 0xa820, %r16, %r10
	  insfd,3	%r17, _lit32_ref,_lts0 0xa820, %r18, %r12
	}
	{
	  qppackdl,0	%r5, %r7, %r5
	}
	{
	  qppackdl,0	%r10, %r12, %r7
	  stqp,2	%r3, _f16s,_lts0lo 0xfff0, %r5
	}
	{
	  stqp,2	%r3, _f16s,_lts0lo 0xffe0, %r7
	}
	{
	  call	%ctpr1, wbs = 0xa
	}
	{
	  disp	%ctpr1, sha256_transform
	  ldw,0	%r3, _f16s,_lts0lo 0xfffc, %r5
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldw,2	%r3, _f16s,_lts0hi 0xfff8, %r7
	  ldw,3	%r3, _f16s,_lts1lo 0xfff4, %r10
	  addd,4,sm	0x0, %r6, %b[1]
	  ldw,5	%r3, _f16s,_lts1hi 0xfff0, %r12
	}
	{
	  ldw,0	%r3, _f16s,_lts0lo 0xffec, %r14
	  addd,1,sm	0x0, %r2, %b[0]
	  ldw,2	%r3, _f16s,_lts0hi 0xffe4, %r17
	  ldw,3	%r3, _f16s,_lts1lo 0xffe8, %r16
	  ldw,5	%r3, _f16s,_lts1hi 0xffe0, %r18
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffdc, %r13
	  stw,5	%r3, _f16s,_lts0hi 0xffd8, %r13
	}
	{
	  xors,0	%r5, %r11, %r5
	  xors,1	%r7, %r11, %r7
	  stw,2	%r3, _f16s,_lts0lo 0xffd4, %r13
	  xors,3	%r10, %r11, %r10
	  xors,4	%r12, %r11, %r12
	  stw,5	%r3, _f16s,_lts0hi 0xffd0, %r13
	}
	{
	  xors,0	%r14, %r11, %r14
	  xors,1	%r17, %r11, %r17
	  stw,2	%r3, _f16s,_lts0lo 0xffcc, %r13
	  xors,3	%r16, %r11, %r16
	  xors,4	%r18, %r11, %r11
	  stw,5	%r3, _f16s,_lts0hi 0xffc8, %r13
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffc4, %r13
	  stw,5	%r3, _f16s,_lts0hi 0xffc0, %r13
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffbc, %r5
	  stw,5	%r3, _f16s,_lts0hi 0xffb8, %r7
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffb4, %r10
	  stw,5	%r3, _f16s,_lts0hi 0xffb0, %r12
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffac, %r14
	  stw,5	%r3, _f16s,_lts0hi 0xffa8, %r16
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffa4, %r17
	  stw,5	%r3, _f16s,_lts0hi 0xffa0, %r11
	}
	{
	  call	%ctpr1, wbs = 0xa
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_init
	  addd,0,sm	0x0, %r1, %b[0]
	}
	{
	  call	%ctpr1, wbs = 0xa
	}
	{
	  disp	%ctpr1, sha256_transform
	  ldw,0	%r3, _f16s,_lts0lo 0xfffc, %g16
	  addd,1,sm	0x0, %r1, %r0
	  ldw,2	%r3, _f16s,_lts0hi 0xfff8, %g17
	  ldw,3	%r3, _f16s,_lts1lo 0xfff4, %g18
	  addd,4,sm	0x0, 0x0, %r2
	  ldw,5	%r3, _f16s,_lts1hi 0xfff0, %g19
	}
	{
	  ldw,0	%r3, _f16s,_lts0lo 0xffec, %g20
	  addd,1,sm	0x0, %r6, %r1
	  ldw,2	%r3, _f16s,_lts0hi 0xffe4, %g22
	  ldw,3	%r3, _f16s,_lts1lo 0xffe8, %g21
	  ldw,5	%r3, _f16s,_lts1hi 0xffe0, %g23
	}
	{
	  std,2	%r3, _f16s,_lts0lo 0xffd8, %r15
	  std,5	%r3, _f16s,_lts0hi 0xffd0, %r15
	}
	{
	  xors,0	%g16, %r9, %g16
	  xors,1	%g17, %r9, %g17
	  std,2	%r3, _f16s,_lts0lo 0xffc8, %r15
	  xors,3	%g18, %r9, %g18
	  xors,4	%g19, %r9, %g19
	  std,5	%r3, _f16s,_lts0hi 0xffc0, %r15
	}
	{
	  xors,0	%g20, %r9, %g20
	  xors,1	%g22, %r9, %g22
	  stw,2	%r3, _f16s,_lts0lo 0xffbc, %g16
	  xors,3	%g21, %r9, %g21
	  xors,4	%g23, %r9, %g23
	  stw,5	%r3, _f16s,_lts0hi 0xffb8, %g17
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffb4, %g18
	  stw,5	%r3, _f16s,_lts0hi 0xffb0, %g19
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffac, %g20
	  stw,5	%r3, _f16s,_lts0hi 0xffa8, %g21
	}
	{
	  stw,2	%r3, _f16s,_lts0lo 0xffa4, %g22
	  stw,5	%r3, _f16s,_lts0hi 0xffa0, %g23
	}
	{
	  ct	%ctpr1
	}
.LCS.2:
	.size	HMAC_SHA256_80_init, .- HMAC_SHA256_80_init
	.local	PBKDF2_SHA256_80_128
	.type	PBKDF2_SHA256_80_128, #function
	.align	8
PBKDF2_SHA256_80_128:
	{
	  setwd	wsz = 0xe, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x3, rbs = 0xa, rcur = 0x0
	  disp	%ctpr2, sha256_transform
	  getsp,0	_f32s,_lts1 0xffffff20, %r5
	  addd,1	0x0, [ _f64,_lts2 innerpad +44 ], %r14
	  ldw,2	%r0, 0x8, %r13
	  ldw,3	%r0, 0x0, %r11
	  ldw,5	%r0, 0x4, %r12
	}
	{
	  ldw,0	%r0, 0xc, %r15
	  addd,1,sm	0x0, %r2, %b[1]
	  ldw,2	0x10, %r0, %r16
	  ldw,3	%r0, _f16s,_lts0lo 0x14, %r17
	  addd,4,sm	0x0, 0x0, %b[2]
	  ldw,5	%r0, _f16s,_lts0hi 0x18, %r18
	}
	{
	  addd,0	%r5, _f64,_lts1 0xe0, %r4
	  addd,1,sm	0x0, 0x0, %r0
	  ldw,2	%r0, _f16s,_lts0lo 0x1c, %r5
	}
	{
	  addd,0	%r4, _f16s,_lts0lo 0xffe0, %b[0]
	  addd,1	0x0, [ _f64,_lts2 outerpad +32 ], %r12
	  addd,2	%r4, _f16s,_lts0hi 0xff60, %r19
	  insfd,3	%r12, _f32s,_lts1 0xa820, %r11, %r11
	}
	{
	  insfd,0	%r15, _f32s,_lts2 0xa820, %r13, %r13
	  cmpledb,1	%r12, %r19, %pred0
	  addd,2	%r4, _f16s,_lts0lo 0xffc0, %r10
	  addd,3	%r4, _f16s,_lts1lo 0xff80, %r9
	  addd,5	%r4, _f16s,_lts0hi 0xff94, %r15
	}
	{
	  insfd,0	%r17, _f32s,_lts0 0xa820, %r16, %r16
	  insfd,1	%r5, _lit32_ref,_lts0 0xa820, %r18, %r5
	  cmpledb,3	%r14, %r19, %pred1
	  cmpledb,4	%r9, [ _f64,_lts1 innerpad ], %pred2
	}
	{
	  qppackdl,0	%r13, %r11, %r11
	  qppackdl,1	%r5, %r16, %r5
	  cmpledb,3	%r10, %r19, %pred3
	  cmpledb,4	%r9, %r15, %pred4
	  pass	%pred1, @p0
	  pass	%pred2, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred1
	}
	{
	  cmpledb,0	%r10, [ _f64,_lts1 outerpad ], %pred2
	  cmpledb,1	%r12, %r15, %pred5
	  stqp,2	%r4, _f16s,_lts0lo 0xffe0, %r11
	  cmpledb,3	%r9, _lit64_ref,_lts1 0x0, %pred6
	  cmpledb,4	%r14, %r15, %pred4
	  pass	%pred3, @p0
	  pass	%pred4, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred3
	}
	{
	  cmpledb,0	%r10, [ _f64,_lts1 innerpad ], %pred5
	  stqp,2	%r4, _f16s,_lts0lo 0xfff0, %r5
	  pass	%pred2, @p0
	  pass	%pred5, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred2
	  pass	%pred1, @p2
	  landp	~@p4, ~@p2, @p5
	  pass	@p5, %pred1
	}
.LCS.3:
	{
	  call	%ctpr2, wbs = 0xa
	  pass	%pred0, @p0
	  pass	%pred6, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred0
	  pass	%pred3, @p2
	  landp	~@p4, ~@p2, @p5
	  pass	@p5, %pred2
	}
	{
	  disp	%ctpr1, .L2031
	  ldw,0	%r2, _f16s,_lts0lo 0x40, %g16
	  ldw,2	%r2, _f16s,_lts0hi 0x44, %g17
	  ldw,3	%r2, _f16s,_lts1lo 0x48, %g18
	  ldw,5	%r2, _f16s,_lts1hi 0x4c, %g19
	  pass	%pred2, @p0
	  pass	%pred1, @p1
	  landp	@p0, @p1, @p4
	  pass	@p4, %pred0
	  pass	%pred4, @p2
	  pass	%pred5, @p3
	  landp	~@p2, ~@p3, @p5
	  pass	@p5, %pred1
	  landp	@p4, ~@p5, @p6
	  pass	@p6, %pred2
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldqp,0,sm	0x0, [ _f64,_lts0 innerpad ], %g20
	  ldqp,2,sm	0x0, [ _f64,_lts2 innerpad +16 ], %g21
	}
	{
	  ldw,0,sm	0x0, [ _f64,_lts0 innerpad +32 ], %g22
	  adds,1	0x0, 0x0, %r6 ? %pred2
	  ldw,2,sm	0x0, [ _f64,_lts2 innerpad +36 ], %g23
	}
	{
	  ldb,0,sm	0x0, [ _f64,_lts2 innerpad +40 ], %g18
	  insfd,1	%g17, _f32s,_lts1 0xa820, %g16, %g16
	  addd,2,sm	%r4, _f16s,_lts0lo 0xff40, %r7 ? %pred2
	  insfd,4	%g19, _lit32_ref,_lts1 0xa820, %g18, %g17
	}
	{
	  qpswitchd,0,sm	%g21, %g24
	  qpswitchd,1,sm	%g20, %g19
	  ldb,2,sm	0x0, [ _f64,_lts0 innerpad +41 ], %g25
	  ldb,3,sm	0x0, [ _f64,_lts2 innerpad +42 ], %g26
	}
	{
	  ldqp,0,sm	0x0, [ _f64,_lts0 outerpad ], %g17
	  qppackdl,1	%g17, %g16, %g16
	  ldb,3,sm	0x0, [ _f64,_lts2 innerpad +43 ], %g27
	}
	{
	  ct	%ctpr1 ? ~%pred2
	  ldqp,0,sm	0x0, [ _f64,_lts1 outerpad +16 ], %g28
	  getfd,1,sm	%g20, _f16s,_lts0lo 0x820, %g16
	  stqp,2	%r4, _f16s,_lts0hi 0xff80, %g16
	  getfd,3,sm	%g21, _lit16_ref,_lts0lo 0x820, %g29
	}
	{
	  stw,2	%r4, _f16s,_lts0lo 0xff94, %g20 ? %pred2
	  stw,5	%r4, _f16s,_lts0hi 0xff98, %g16 ? %pred2
	}
	{
	  getfd,0,sm	%g19, _f16s,_lts0lo 0x820, %g16
	  getfd,1,sm	%g24, _lit16_ref,_lts0lo 0x820, %g20
	  stw,2	%r4, _f16s,_lts0hi 0xff9c, %g19 ? %pred2
	  stw,5	%r4, _f16s,_lts1lo 0xffa4, %g21 ? %pred2
	}
	{
	  stqp,2	%r4, _f16s,_lts0lo 0xff60, %g17 ? %pred2
	  stw,5	%r4, _f16s,_lts0hi 0xffa0, %g16 ? %pred2
	}
	{
	  stqp,2	%r4, _f16s,_lts0lo 0xff70, %g28 ? %pred2
	  stw,5	%r4, _f16s,_lts0hi 0xffa8, %g29 ? %pred2
	}
	{
	  stw,2	%r4, _f16s,_lts0lo 0xffac, %g24 ? %pred2
	  stw,5	%r4, _f16s,_lts0hi 0xffb0, %g20 ? %pred2
	}
	{
	  stw,2	%r4, _f16s,_lts0lo 0xffb4, %g22 ? %pred2
	  stw,5	%r4, _f16s,_lts0hi 0xffb8, %g23 ? %pred2
	}
	{
	  stb,2	%r4, _f16s,_lts0lo 0xffbc, %g18 ? %pred2
	  stb,5	%r4, _f16s,_lts0hi 0xffbd, %g25 ? %pred2
	}
	{
	  stb,2	%r4, _f16s,_lts0lo 0xffbe, %g26 ? %pred2
	  stb,5	%r4, _f16s,_lts0hi 0xffbf, %g27 ? %pred2
	}
.L846:
	{
	  ldqp,0	%r4, _f16s,_lts0lo 0xffe0, %r2
	  adds,1	%r6, 0x1, %r11
	  ldqp,2	%r4, _f16s,_lts0hi 0xfff0, %r5
	  addd,3,sm	0x0, 0x0, %b[2]
	  addd,4,sm	0x0, %r9, %b[1]
	  addd,5,sm	0x0, %r7, %b[0]
	}
	{
	  nop 2
	  cmplsb,0	%r11, 0x4, %pred0
	  addd,1,sm	%r3, %r0, %r11
	  stw,2	%r4, _f16s,_lts0lo 0xff90, %r11
	}
	{
	  stqp,2	%r4, _f16s,_lts0lo 0xff40, %r2
	  stqp,5	%r4, _f16s,_lts0hi 0xff50, %r5
	}
	{
	  call	%ctpr2, wbs = 0xa
	}
	{
	  disp	%ctpr1, sha256_transform
	  ldw,0	%r1, 0x0, %r2
	  addd,1,sm	0x0, %r7, %b[1]
	  ldw,2	%r1, 0x4, %r5
	  ldw,3	%r1, 0x8, %r12
	  addd,4,sm	0x0, %r10, %b[0]
	  ldw,5	%r1, 0xc, %r13
	}
	{
	  nop 1
	  ldw,0	0x10, %r1, %r14
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldw,2	%r1, _f16s,_lts0lo 0x14, %r15
	  ldw,3	%r1, _f16s,_lts0hi 0x18, %r16
	  ldw,5	%r1, _f16s,_lts1lo 0x1c, %r17
	}
	{
	  insfd,0	%r5, _f32s,_lts0 0xa820, %r2, %r2
	  insfd,3	%r13, _lit32_ref,_lts0 0xa820, %r12, %r5
	}
	{
	  insfd,0	%r15, _f32s,_lts0 0xa820, %r14, %r12
	  insfd,3	%r17, _lit32_ref,_lts0 0xa820, %r16, %r13
	}
	{
	  qppackdl,0	%r5, %r2, %r2
	}
	{
	  qppackdl,0	%r13, %r12, %r5
	  stqp,2	%r4, _f16s,_lts0lo 0xffc0, %r2
	}
	{
	  stqp,2	%r4, _f16s,_lts0lo 0xffd0, %r5
	}
	{
	  call	%ctpr1, wbs = 0xa
	}
	{
	  disp	%ctpr1, .L846
	  ldd,0	%r4, _f16s,_lts0lo 0xffc0, %g16
	  adds,1	%r6, 0x1, %r6
	  ldd,2	%r4, _f16s,_lts0hi 0xffc8, %g17
	  ldd,3	%r4, _f16s,_lts1lo 0xffd0, %g18
	  ldd,5	%r4, _f16s,_lts1hi 0xffd8, %g19
	}
	{
	  disp	%ctpr2, sha256_transform
	}
	{
	  return	%ctpr3
	}
	{
	  getfd,0	%g16, _f16s,_lts0lo 0x820, %g20
	  getfd,1	%g17, _lit16_ref,_lts0lo 0x820, %g21
	  getfd,3	%g18, _lit16_ref,_lts0lo 0x820, %g22
	  getfd,4	%g19, _lit16_ref,_lts0lo 0x820, %g23
	}
	{
	  addd,0,sm	%r0, _f16s,_lts0lo 0x20, %r0
	  stw,2	%r3, %r0, %g16, mas=0x8
	  stw,5	%r11, 0x4, %g20, mas=0x8
	}
	{
	  stw,2	%r11, 0x8, %g17, mas=0x8
	  stw,5	%r11, 0xc, %g21, mas=0x8
	}
	{
	  stw,2	%r11, _f16s,_lts0lo 0x10, %g18, mas=0x8
	  stw,5	%r11, _f16s,_lts0hi 0x14, %g22, mas=0x8
	}
	{
	  ct	%ctpr1 ? %pred0
	  stw,2	%r11, _f16s,_lts0lo 0x18, %g19, mas=0x8
	  stw,5	%r11, _f16s,_lts0hi 0x1c, %g23, mas=0x8
	}
	{
	  ct	%ctpr3 ? ~%pred0
	}
.L2031:
	{
	  disp	%ctpr1, .L846
	  ldqp,0	0x0, [ _f64,_lts0 innerpad ], %g16
	  adds,1	0x0, 0x0, %r6
	  ldqp,2	0x0, [ _f64,_lts2 innerpad +16 ], %g17
	  addd,3,sm	0x0, 0x0, %r0
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldqp,0	0x0, [ _f64,_lts0 outerpad ], %g18
	  ldqp,2	0x0, [ _f64,_lts2 outerpad +16 ], %g19
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 innerpad +42 ], %g20
	  ldb,2	0x0, [ _f64,_lts2 innerpad +40 ], %g21
	}
	{
	  qpswitchd,0	%g17, %g23
	  qpswitchd,1	%g16, %g22
	  ldb,2	0x0, [ _f64,_lts0 innerpad +43 ], %g24
	  ldw,3	0x0, [ _f64,_lts2 innerpad +32 ], %g25
	}
	{
	  getfd,0	%g16, _f16s,_lts0lo 0x820, %g26
	  getfd,1	%g17, _lit16_ref,_lts0lo 0x820, %g27
	  stw,2	%r4, _f16s,_lts0hi 0xff94, %g16
	  addd,3,sm	%r4, _f16s,_lts1hi 0xff40, %r7
	  stw,5	%r4, _f16s,_lts1lo 0xffa4, %g17
	}
	{
	  stw,2	%r4, _f16s,_lts0lo 0xff98, %g26
	  stw,5	%r4, _f16s,_lts0hi 0xffa8, %g27
	}
	{
	  stw,2	%r4, _f16s,_lts0lo 0xff9c, %g22
	  stw,5	%r4, _f16s,_lts0hi 0xffac, %g23
	}
	{
	  ldb,0	0x0, [ _f64,_lts1 innerpad +41 ], %g22
	  getfd,1	%g22, _f16s,_lts0lo 0x820, %g16
	  stqp,2	%r4, _f16s,_lts0hi 0xff60, %g18
	  getfd,4	%g23, _lit16_ref,_lts0lo 0x820, %g17
	}
	{
	  stw,2	%r4, _f16s,_lts0lo 0xffa0, %g16
	  stw,5	%r4, _f16s,_lts0hi 0xffb0, %g17
	}
	{
	  ldw,0	0x0, [ _f64,_lts1 innerpad +36 ], %g16
	  stqp,2	%r4, _f16s,_lts0lo 0xff70, %g19
	}
	{
	  stb,2	%r4, _f16s,_lts0lo 0xffbe, %g20
	  stb,5	%r4, _f16s,_lts0hi 0xffbc, %g21
	}
	{
	  stb,2	%r4, _f16s,_lts0lo 0xffbf, %g24
	  stw,5	%r4, _f16s,_lts0hi 0xffb4, %g25
	}
	{
	  stb,2	%r4, _f16s,_lts0lo 0xffbd, %g22
	}
	{
	  ct	%ctpr1
	  stw,2	%r4, _f16s,_lts0lo 0xffb8, %g16
	}
.LCS.4:
	.size	PBKDF2_SHA256_80_128, .- PBKDF2_SHA256_80_128
	.local	scrypt_1024_core_1_cycle_elway
	.type	scrypt_1024_core_1_cycle_elway, #function
	.align	8
scrypt_1024_core_1_cycle_elway:
	{
	  setwd	wsz = 0x37, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x16, rbs = 0x20, rcur = 0x0
	  addd,1,sm	0x0, 0x0, %r5
	  addd,2	0x0, 0x0, %r6
	  addd,3	0x0, _f64,_lts2 0x1f1e1d1c17161514, %g16
	  scld,4	0x1, 0x7, %r20
	  addd,5	0x0, 0x0, %r9
	}
	{
	  addd,1	0x13, 0x0, %r21
	  addd,2	%r2, %r5, %r7
	  qppackdl,3	%g16, _f64,_lts2 0xf0e0d0c07060504, %r18
	  addd,4	0x17, 0x0, %r22
	  addd,5	0x0, _f64,_lts0 0x1b1a191813121110, %g17
	}
	{
	  getfd,0	%r7, _f16s,_lts0lo 0x43, %g16
	  addd,1	0x19, 0x0, %r23
	  addd,3,sm	%r2, _f16s,_lts0hi 0x10, %r24
	  adds,4	0x2, 0x0, %r26
	  addd,5	0x2, 0x0, %r25
	}
	{
	  nop 1
	  cmpandedb,0	%g16, 0x1, %pred1
	  qppackdl,1	%g17, _f64,_lts0 0xb0a090803020100, %r19
	  addd,2,sm	%r0, 0x8, %r27
	  adds,3	0x4, 0x0, %r28
	}
	{
	  addd,0	0x1, 0x0, %r6 ? ~%pred1
	}
	{
	  cmpldb,0,sm	%r6, _f16s,_lts0lo 0x80, %pred0
	}
.L2043:
	{
	  disp	%ctpr3, .L81970
	  subd,0,sm	%r20, %r6, %g18
	  shld,1	%r6, 0x3, %r10
	  ldd,2,sm	%r0, 0x0, %g16
	  cmpesb,3	0x0, 0x0, %pred2
	  subd,5,sm	%r20, %r6, %g17
	}
	{
	  merged,0,sm	0x1, %g18, %r13, %pred0
	  addd,1	%r0, %r10, %g17
	  merged,3,sm	0x1, %g17, %r17, %pred0
	}
	{
	  cmpandedb,0	%g17, 0xf, %pred0
	  shrd,2,sm	%r13, 0x1, %r12
	  shrd,5,sm	%r17, 0x1, %r16
	}
	{
	  cmpldb,0,sm	0x0, %r12, %pred4
	  cmpldb,3,sm	0x0, %r16, %pred3
	}
	{
	  ibranch	.L2073 ? ~%pred2
	  std,2	%r2, %r5, %g16 ? ~%pred1
	}
	{
	  merged,0,sm	0x1, %r16, %r15, %pred3
	  merged,1,sm	0x1, %r12, %r11, %pred4
	}
	{
	  ct	%ctpr3 ? ~%pred0
	  shrd,0,sm	%r15, 0x1, %r14
	  shrd,1,sm	%r11, 0x1, %r4
	}
	{
	  setwd	wsz = 0x37, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x4, rbs = 0x20, rcur = 0x0
	  ldisp	%ctpr2, .L82120
	  cmpldb,0	0x0, %r4, %pred0
	  addd,1	0x0, _f64,_lts1 0x80f92000000000, %g16
	  addd,2,sm	0x1, 0x0, %g17
	  addd,3,sm	%r0, %r10, %g18
	  addd,4	%r24, %r5, %g19
	  addd,5,sm	0x0, 0x0, %g21
	}
	{
	  disp	%ctpr1, .L2054
	  ldqp,0,sm	%r0, %r10, %b[8]
	  addd,1	0x0, 0x0, %g22
	  aaurw,2	%r26, %aaincr1
	  addd,3,sm	0x0, %g18, %g20
	  addd,4	%r7, %r10, %g23
	  addd,5	%g19, %r10, %g19
	}
	{
	  insfd,0,sm	%g16, _f32s,_lts1 0x8800, %r4, %g24 ? %pred0
	  insfd,1,sm	%g16, _lit32_ref,_lts1 0x8800, %g17, %g24 ? ~%pred0
	  aaurwd,2	%r25, %aaincr2
	  addd,3,sm	%g20, _f16s,_lts0lo 0x80, %g20
	  aaurwd,5	%g23, %aad2
	}
	{
	  rwd,0	%g24, %lsr
	  andd,1	%g24, _f64,_lts0 0xffffffff, %g16
	  aaurwd,2	%g22, %aasti2
	  aaurwd,5	%g22, %aasti1
	}
	{
	  shld,1	%g16, 0x2, %g16
	  aaurwd,2	%g19, %aad1
	  ldqp,5,sm	%g18, _f16s,_lts0lo 0x10, %b[9]
	}
	{
	  addd,0	%r6, %g16, %r6
	  aaurwq,2	%g20, %aad0
	}
	{
	  ldqp,0,sm	%g18, _f16s,_lts0lo 0x20, %b[6]
	  ldqp,2,sm	%g18, _f16s,_lts0hi 0x30, %b[7]
	  ldqp,3,sm	%g18, _f16s,_lts1lo 0x40, %b[4]
	  ldqp,5,sm	%g18, _f16s,_lts1hi 0x50, %b[5]
	}
	{
	  nop 7
	  bap
	  ldqp,0,sm	%g18, _f16s,_lts0lo 0x60, %b[2]
	  ldqp,2,sm	%g18, _f16s,_lts0hi 0x70, %b[3]
	}
	{
	  nop 7
	}
.L2054:
	{
	  loop_mode
	  alc	alcf=1, alct=1
	  abn	abnf=1, abnt=1
	  ct	%ctpr1 ? %NOT_LOOP_END
	  staaqp,2	%b[8], %aad2[ %aasti2 ]
	  incr,2	%aaincr2
	  staaqp,5	%b[9], %aad1[ %aasti1 ]
	  incr,5	%aaincr2
	  movaqp,0	area=0, ind=0, am=0, be=0, %b[0]
	  movaqp,1	area=0, ind=16, am=1, be=0, %b[1]
	}
	{
	  setwd	wsz = 0x37, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x16, rbs = 0x20, rcur = 0x0
	  disp	%ctpr3, .L2073
	  shld,0,sm	%r6, 0x3, %g16
	  shld,1	%r4, 0x1, %g17
	  shld,2	%r12, 0x1, %g18
	  adds,3	0x0, 0x0, %g19
	}
	{
	  cmpedb,0	%g17, %r11, %pred0
	  cmpedb,1	%g18, %r13, %pred1
	  ldqp,2,sm	%r0, %g16, %g20
	}
	{
	  disp	%ctpr2, disp=0x0
	  aaurw,2	%g19, %aabf0
	}
	{
	  addd,0	%r6, 0x2, %r6 ? ~%pred0
	}
	{
	  shld,0,sm	%r6, 0x3, %g17
	}
	{
	  ct	%ctpr3 ? %pred1
	  ldd,0,sm	%r0, %g17, %g16
	  stqp,2	%r7, %g16, %g20 ? ~%pred0
	}
	{
	  nop 2
	}
	{
	  std,2	%r7, %g17, %g16 ? ~%pred1
	}
.L2073:
	{
	  disp	%ctpr1, .L2043
	  ldqp,0	%r1, _f16s,_lts0lo 0x200, %g16
	  addd,1,sm	%r5, _f32s,_lts2 0x400, %r5
	  ldqp,2	%r1, _f16s,_lts0hi 0x300, %g17
	  ldqp,3	%r1, _f16s,_lts1lo 0x210, %g18
	  addd,4	%r9, 0x1, %r9
	  ldqp,5	%r1, _f16s,_lts1hi 0x310, %g19
	}
	{
	  return	%ctpr3
	  ldqp,0	%r1, _f16s,_lts0lo 0x250, %g20
	  addd,1,sm	%r2, %r5, %r7
	  ldqp,2	%r1, _f16s,_lts0hi 0x350, %g21
	  ldqp,3	%r1, _f16s,_lts1lo 0x260, %g22
	  cmpldb,4	%r9, _f32s,_lts2 0x400, %pred2
	  ldqp,5	%r1, _f16s,_lts1hi 0x360, %g23
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0x2a0, %g24
	  getfd,1,sm	%r7, _f32s,_lts2 0x43, %g28
	  ldqp,2	%r1, _f16s,_lts0hi 0x3a0, %g25
	  ldqp,3	%r1, _f16s,_lts1lo 0x2b0, %g26
	  addd,4,sm	0x0, 0x0, %r6
	  ldqp,5	%r1, _f16s,_lts1hi 0x3b0, %g27
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0x2c0, %g29
	  qpxor,1	%g16, %g17, %g16
	  ldqp,2	%r1, _f16s,_lts0hi 0x3c0, %g30
	  ldqp,3	%r1, _f16s,_lts1lo 0x2f0, %g31
	  qpxor,4	%g18, %g19, %g18
	  ldqp,5	%r1, _f16s,_lts1hi 0x3f0, %r4
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0x3e0, %r10
	  qpxor,1	%g20, %g21, %g20
	  ldqp,2	%r1, _f16s,_lts0hi 0x2e0, %r11
	  ldqp,3	%r1, _f16s,_lts1lo 0x390, %r12
	  qpxor,4	%g22, %g23, %g22
	  ldqp,5	%r1, _f16s,_lts1hi 0x290, %r13
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0x240, %r15
	  qpxor,1	%g24, %g25, %g24
	  ldqp,2	%r1, _f16s,_lts0hi 0x340, %r14
	  ldqp,3	%r1, _f16s,_lts1hi 0x230, %r17
	  qpxor,4	%g26, %g27, %g26
	  ldqp,5	%r1, _f16s,_lts1lo 0x330, %r16
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0x3d0, %r29
	  qpxor,1	%g29, %g30, %g29
	  ldqp,2	%r1, _f16s,_lts0hi 0x2d0, %r30
	  ldqp,3	%r1, _f16s,_lts1lo 0x380, %r31
	  qpxor,4	%g31, %r4, %g31
	  ldqp,5	%r1, _f16s,_lts1hi 0x280, %r32
	}
	{
	  qpaddw,0	%g20, %g18, %r33
	  qpxor,1	%r11, %r10, %r11
	  ldqp,2	%r1, _f16s,_lts0lo 0x370, %r35
	  qpaddw,3	%g31, %g26, %r34
	  qpxor,4	%r13, %r12, %r13
	  ldqp,5	%r1, _f16s,_lts0hi 0x270, %r36
	}
	{
	  qpaddw,0	%g16, %g29, %r37
	  qpxor,1	%r15, %r14, %r15
	  ldqp,2	%r1, _f16s,_lts0lo 0x320, %r38
	  qpsrcw,3	%r34, %r23, %r34
	  qpxor,4	%r17, %r16, %r17
	  ldqp,5	%r1, _f16s,_lts0hi 0x220, %r39
	}
	{
	  qpaddw,0	%g24, %g22, %r40
	  qpsrcw,1	%r33, %r23, %r33
	  ldqp,2	%r1, 0x0, %r41
	  qpxor,3	%r32, %r31, %r32
	  qpxor,4	%r17, %r34, %r34
	  ldqp,5	%r1, _f16s,_lts0lo 0x100, %r42
	}
	{
	  qpsrcw,0	%r40, %r23, %r40
	  qpsrcw,1	%r37, %r23, %r37
	  ldqp,2	0x10, %r1, %r44
	  qpaddw,3	%r34, %g31, %r43
	  qpxor,4	%r30, %r29, %r30
	  ldqp,5	%r1, _f16s,_lts0lo 0x110, %r45
	}
	{
	  qpxor,0	%r15, %r37, %r37
	  qpxor,1	%r13, %r33, %r33
	  ldqp,2	%r1, _f16s,_lts0lo 0x50, %r46
	  qpsrcw,3	%r43, %r22, %r43
	  qpxor,4	%r36, %r35, %r36
	  ldqp,5	%r1, _f16s,_lts0hi 0x150, %r47
	}
	{
	  qpaddw,0	%r33, %g20, %r48
	  qpxor,1	%r11, %r40, %r40
	  ldqp,2	%r1, _f16s,_lts0lo 0x60, %r49
	  qpxor,3	%r36, %r43, %r43
	  qpxor,4	%r39, %r38, %r39
	  ldqp,5	%r1, _f16s,_lts0hi 0x160, %r50
	}
	{
	  qpaddw,0	%r37, %g16, %r51
	  qpsrcw,1	%r48, %r22, %r48
	  ldqp,2	%r1, _f16s,_lts0lo 0xa0, %r53
	  qpaddw,3	%r43, %r34, %r52
	  qpxor,4	%r41, %r42, %r41
	  ldqp,5	%r1, _f16s,_lts0hi 0x1a0, %r54
	}
	{
	  qpaddw,0	%r40, %g24, %r55
	  qpsrcw,1	%r51, %r22, %r51
	  ldqp,2	%r1, _f16s,_lts0lo 0xb0, %r56
	  ldqp,3	%r1, _f16s,_lts0hi 0x1b0, %r57
	  qpsrcw,4	%r52, %r21, %r52
	  ldqp,5	%r1, _f16s,_lts1lo 0xc0, %r58
	}
	{
	  qpxor,0	%r30, %r48, %r48
	  qpsrcw,1	%r55, %r22, %r55
	  ldqp,2	%r1, _f16s,_lts0lo 0x1c0, %r59
	  ldqp,3	%r1, _f16s,_lts0hi 0xf0, %r60
	  qpxor,4	%g26, %r52, %r52
	  ldqp,5	%r1, _f16s,_lts1lo 0x1f0, %r61
	}
	{
	  qpxor,0	%r39, %r55, %r55
	  qpxor,1	%r32, %r51, %r51
	  ldqp,2	%r1, _f16s,_lts0lo 0x1e0, %r63
	  qpaddw,3	%r52, %r43, %r62
	  qpxor,4	%r44, %r45, %r44
	  ldqp,5	%r1, _f16s,_lts0hi 0xe0, %b[0]
	}
	{
	  qpaddw,0	%r48, %r33, %b[1]
	  qpxor,1	%r46, %r47, %r46
	  ldqp,2	%r1, _f16s,_lts0lo 0x190, %b[2]
	  ldqp,3	%r1, _f16s,_lts0hi 0x90, %b[3]
	  qpsrcw,4	%r62, 0xe, %r62
	  ldqp,5	%r1, _f16s,_lts1lo 0x140, %b[4]
	}
	{
	  qpaddw,0	%r51, %r37, %b[5]
	  qpsrcw,1	%b[1], %r21, %b[1]
	  ldqp,2	%r1, _f16s,_lts0lo 0x40, %b[6]
	  ldqp,3	%r1, _f16s,_lts1lo 0x30, %b[8]
	  qpxor,4	%g31, %r62, %r62
	  ldqp,5	%r1, _f16s,_lts0hi 0x130, %b[7]
	}
	{
	  qpaddw,0	%r55, %r40, %b[9]
	  qpsrcw,1	%b[5], %r21, %b[5]
	  ldqp,2	%r1, _f16s,_lts0hi 0xd0, %b[12]
	  qpaddw,3	%r62, %r40, %b[10]
	  qpxor,4	%r49, %r50, %r49
	  ldqp,5	%r1, _f16s,_lts0lo 0x1d0, %b[11]
	}
	{
	  qpsrcw,0	%b[9], %r21, %b[9]
	  qpxor,1	%g18, %b[1], %b[1]
	  ldqp,2	%r1, _f16s,_lts0hi 0x80, %b[14]
	  qpxor,3	%r53, %r54, %r53
	  qpsrcw,4	%b[10], %r23, %b[10]
	  ldqp,5	%r1, _f16s,_lts0lo 0x180, %b[13]
	}
	{
	  qpxor,0	%g22, %b[9], %b[9]
	  qpxor,1	%g29, %b[5], %b[5]
	  ldqp,2	%r1, _f16s,_lts0hi 0x70, %b[16]
	  qpxor,3	%r60, %r61, %r60
	  qpxor,4	%r56, %r57, %r56
	  ldqp,5	%r1, _f16s,_lts0lo 0x170, %b[15]
	}
	{
	  qpaddw,0	%b[1], %r48, %b[17]
	  qpxor,1	%r58, %r59, %r58
	  ldqp,2	%r1, _f16s,_lts0lo 0x120, %b[19]
	  qpaddw,3	%r46, %r44, %b[18]
	  qpxor,4	%b[0], %r63, %b[0]
	  ldqp,5	%r1, _f16s,_lts0hi 0x20, %b[20]
	}
	{
	  qpaddw,0	%b[5], %r51, %b[21]
	  qpsrcw,1	%b[17], 0xe, %b[17]
	  qpaddw,3	%r53, %r49, %b[22]
	  qpxor,4	%b[3], %b[2], %b[3]
	}
	{
	  qpaddw,0	%b[9], %r55, %b[23]
	  qpsrcw,1	%b[21], 0xe, %b[21]
	  qpaddw,3	%r60, %r56, %b[24]
	  qpsrcw,4	%b[18], %r23, %b[18]
	}
	{
	  qpxor,0	%g20, %b[17], %b[17]
	  qpsrcw,1	%b[23], 0xe, %b[23]
	  qpxor,3	%b[6], %b[4], %b[6]
	  qpxor,4	%b[5], %b[10], %b[5]
	}
	{
	  qpxor,0	%g24, %b[23], %b[21]
	  qpxor,1	%g16, %b[21], %b[10]
	  qpaddw,3	%b[5], %r62, %b[23]
	  qpxor,4	%b[8], %b[7], %b[8]
	}
	{
	  qpaddw,0	%b[17], %r37, %b[25]
	  qpsrcw,1	%b[22], %r23, %b[22]
	  qpaddw,3	%r41, %r58, %b[26]
	  qpsrcw,4	%b[23], %r22, %b[23]
	}
	{
	  qpaddw,0	%b[10], %r34, %b[27]
	  qpsrcw,1	%b[25], %r23, %b[25]
	  qpxor,3	%r48, %b[23], %r48
	  qpsrcw,4	%b[24], %r23, %b[23]
	}
	{
	  qpaddw,0	%b[21], %r33, %b[24]
	  qpsrcw,1	%b[27], %r23, %b[27]
	  qpaddw,3	%r48, %b[5], %b[28]
	  qpsrcw,4	%b[26], %r23, %b[26]
	}
	{
	  qpsrcw,0	%b[24], %r23, %b[24]
	  qpxor,1	%b[9], %b[25], %b[9]
	  qpsrcw,3	%b[28], %r21, %b[25]
	  qpxor,4	%b[3], %b[18], %b[18]
	}
	{
	  qpxor,0	%r52, %b[24], %r52
	  qpxor,1	%b[1], %b[27], %b[1]
	  qpxor,3	%b[0], %b[22], %b[22]
	  qpxor,4	%r40, %b[25], %r40
	}
	{
	  qpaddw,0	%b[9], %b[17], %b[24]
	  qpxor,1	%b[8], %b[23], %b[23]
	  qpaddw,3	%r40, %r48, %b[25]
	  qpxor,4	%b[6], %b[26], %b[26]
	}
	{
	  qpaddw,0	%b[1], %b[10], %b[27]
	  qpsrcw,1	%b[24], %r22, %b[24]
	  qpaddw,3	%b[18], %r46, %b[28]
	  qpsrcw,4	%b[25], 0xe, %b[25]
	}
	{
	  qpaddw,0	%r52, %b[21], %b[29]
	  qpsrcw,1	%b[27], %r22, %b[27]
	  qpaddw,3	%b[22], %r53, %b[25]
	  qpxor,4	%r62, %b[25], %r62
	}
	{
	  qpxor,0	%r43, %b[24], %r43
	  qpsrcw,1	%b[29], %r22, %b[29]
	  qpaddw,3	%r62, %r52, %b[24]
	  qpxor,4	%b[12], %b[11], %b[12]
	}
	{
	  qpxor,0	%r51, %b[29], %r51
	  qpxor,1	%r55, %b[27], %r55
	  qpaddw,3	%b[23], %r60, %b[27]
	  qpsrcw,4	%b[24], %r23, %b[24]
	}
	{
	  qpaddw,0	%r43, %b[9], %b[29]
	  qpxor,1	%b[14], %b[13], %b[14]
	  qpaddw,3	%b[26], %r41, %b[30]
	  qpsrcw,4	%b[28], %r22, %b[28]
	}
	{
	  qpaddw,0	%r55, %b[1], %b[31]
	  qpsrcw,1	%b[29], %r21, %b[29]
	  qpxor,3	%b[16], %b[15], %b[16]
	  qpsrcw,4	%b[27], %r22, %b[27]
	}
	{
	  qpaddw,0	%r51, %r52, %b[32]
	  qpsrcw,1	%b[31], %r21, %b[31]
	  qpxor,3	%b[20], %b[19], %b[20]
	  qpsrcw,4	%b[25], %r22, %b[25]
	}
	{
	  qpsrcw,0	%b[32], %r21, %b[32]
	  qpxor,1	%r37, %b[29], %r37
	  qpsrcw,3	%b[30], %r22, %b[29]
	  qpxor,4	%b[12], %b[28], %b[28]
	}
	{
	  qpxor,0	%r33, %b[32], %r33
	  qpxor,1	%r34, %b[31], %r34
	  qpxor,3	%b[20], %b[25], %b[25]
	  qpxor,4	%b[16], %b[27], %b[27]
	}
	{
	  qpaddw,0	%r37, %r43, %b[30]
	  qpxor,1	%r34, %b[24], %b[24]
	  qpaddw,3	%b[28], %b[18], %b[31]
	  qpxor,4	%b[14], %b[29], %b[29]
	}
	{
	  qpaddw,0	%r34, %r55, %r34
	  qpsrcw,1	%b[30], 0xe, %b[30]
	  qpaddw,3	%b[27], %b[23], %b[32]
	  qpsrcw,4	%b[31], %r21, %b[31]
	}
	{
	  qpaddw,0	%r33, %r51, %b[33]
	  qpsrcw,1	%r34, 0xe, %r34
	  qpaddw,3	%b[25], %b[22], %b[34]
	  qpsrcw,4	%b[32], %r21, %b[32]
	}
	{
	  qpxor,0	%b[17], %b[30], %b[17]
	  qpsrcw,1	%b[33], 0xe, %b[33]
	  qpaddw,3	%b[29], %b[26], %b[30]
	  qpsrcw,4	%b[34], %r21, %b[34]
	}
	{
	  qpxor,0	%b[21], %b[33], %b[10]
	  qpxor,1	%b[10], %r34, %r34
	  qpaddw,3	%b[24], %r62, %b[21]
	  qpsrcw,4	%b[30], %r21, %b[30]
	}
	{
	  qpaddw,0	%b[17], %b[1], %b[33]
	  qpxor,1	%r44, %b[31], %b[31]
	  qpsrcw,3	%b[21], %r22, %b[21]
	  qpxor,4	%r56, %b[32], %b[32]
	}
	{
	  qpaddw,0	%r34, %b[5], %b[35]
	  qpsrcw,1	%b[33], %r23, %b[33]
	  qpxor,3	%r49, %b[34], %b[21]
	  qpxor,4	%r43, %b[21], %r43
	}
	{
	  qpaddw,0	%b[10], %b[9], %b[34]
	  qpsrcw,1	%b[35], %r23, %b[35]
	  qpaddw,3	%r43, %b[24], %b[36]
	  qpxor,4	%r58, %b[30], %b[30]
	}
	{
	  qpxor,0	%r33, %b[33], %r33
	  qpsrcw,1	%b[34], %r23, %b[34]
	  qpaddw,3	%b[32], %b[27], %b[36]
	  qpsrcw,4	%b[36], %r21, %b[33]
	}
	{
	  qpxor,0	%r40, %b[34], %r40
	  qpxor,1	%r37, %b[35], %r37
	  qpaddw,3	%b[31], %b[28], %b[33]
	  qpxor,4	%r52, %b[33], %r52
	}
	{
	  qpaddw,0	%r33, %b[17], %b[34]
	  cmpandedb,1,sm	%g28, 0x1, %pred1
	  qpaddw,3	%r52, %r43, %b[35]
	  qpsrcw,4	%b[36], 0xe, %b[36]
	}
	{
	  qpaddw,0	%r37, %r34, %g28
	  qpsrcw,1	%b[34], %r22, %b[34]
	  qpaddw,3	%b[21], %b[25], %b[37]
	  qpsrcw,4	%b[35], 0xe, %b[35]
	  pass	%pred2, @p0
	  pass	%pred1, @p1
	  landp	@p0, ~@p1, @p4
	  pass	@p4, %pred3
	}
	{
	  qpaddw,0	%r40, %b[10], %b[38]
	  qpsrcw,1	%g28, %r22, %g28
	  qpaddw,3	%b[30], %b[29], %b[35]
	  qpxor,4	%r62, %b[35], %r62
	}
	{
	  qpxor,0	%r48, %b[34], %r48
	  qpsrcw,1	%b[38], %r22, %b[38]
	  qpaddw,3	%r62, %r40, %b[34]
	  qpsrcw,4	%b[33], 0xe, %b[33]
	  addd,5	0x1, 0x0, %r6 ? %pred3
	}
	{
	  qpxor,0	%r55, %b[38], %r51
	  qpxor,1	%r51, %g28, %g28
	  qpsrcw,3	%b[34], %r23, %r55
	  qpsrcw,4	%b[37], 0xe, %b[34]
	}
	{
	  qpaddw,0	%r48, %r33, %b[37]
	  cmpldb,1,sm	%r6, _f16s,_lts0lo 0x80, %pred0
	  qpsrcw,3	%b[35], 0xe, %b[35]
	  qpxor,4	%r60, %b[36], %b[36]
	}
	{
	  qpaddw,0	%g28, %r37, %b[38]
	  qpsrcw,1	%b[37], %r21, %b[37]
	  qpxor,3	%r53, %b[34], %b[34]
	  qpxor,4	%r46, %b[33], %b[33]
	}
	{
	  qpaddw,0	%r51, %r40, %b[39]
	  qpsrcw,1	%b[38], %r21, %b[38]
	  qpaddw,3	%b[36], %b[22], %b[40]
	  qpxor,4	%r41, %b[35], %b[35]
	}
	{
	  qpxor,0	%b[1], %b[37], %b[1]
	  qpsrcw,1	%b[39], %r21, %b[39]
	  qpaddw,3	%b[33], %b[26], %b[37]
	  qpsrcw,4	%b[40], %r23, %b[40]
	}
	{
	  qpxor,0	%b[9], %b[39], %b[9]
	  qpxor,1	%b[5], %b[38], %b[5]
	  qpaddw,3	%b[34], %b[18], %b[38]
	  qpsrcw,4	%b[37], %r23, %b[37]
	}
	{
	  qpaddw,0	%b[1], %r48, %b[39]
	  qpxor,1	%b[5], %r55, %r55
	  qpaddw,3	%b[35], %b[23], %b[41]
	  qpsrcw,4	%b[38], %r23, %b[38]
	}
	{
	  qpaddw,0	%b[5], %g28, %b[5]
	  qpsrcw,1	%b[39], 0xe, %b[39]
	  qpsrcw,3	%b[41], %r23, %b[41]
	  qpxor,4	%b[30], %b[40], %b[30]
	}
	{
	  qpaddw,0	%b[9], %r51, %b[40]
	  qpsrcw,1	%b[5], 0xe, %b[5]
	  qpxor,3	%b[32], %b[38], %b[32]
	  qpxor,4	%b[21], %b[37], %b[21]
	}
	{
	  qpxor,0	%b[17], %b[39], %b[17]
	  qpsrcw,1	%b[40], 0xe, %b[37]
	  qpaddw,3	%b[30], %b[36], %b[38]
	  qpxor,4	%b[31], %b[41], %b[31]
	}
	{
	  qpxor,0	%b[10], %b[37], %b[5]
	  qpxor,1	%r34, %b[5], %r34
	  qpaddw,3	%r55, %r62, %b[10]
	  qpsrcw,4	%b[38], %r22, %b[37]
	}
	{
	  qpaddw,0	%b[17], %r37, %b[38]
	  qpaddw,3	%b[21], %b[33], %b[39]
	  qpsrcw,4	%b[10], %r22, %b[10]
	}
	{
	  qpaddw,0	%r34, %b[24], %b[40]
	  qpsrcw,1	%b[38], %r23, %b[38]
	  qpaddw,3	%b[32], %b[34], %b[10]
	  qpxor,4	%r48, %b[10], %r48
	}
	{
	  qpaddw,0	%b[5], %r33, %b[41]
	  qpsrcw,1	%b[40], %r23, %b[40]
	  qpaddw,3	%r48, %r55, %b[42]
	  qpsrcw,4	%b[39], %r22, %b[39]
	}
	{
	  qpxor,0	%b[9], %b[38], %b[9]
	  qpsrcw,1	%b[41], %r23, %b[41]
	  qpaddw,3	%b[31], %b[35], %b[42]
	  qpsrcw,4	%b[42], %r21, %b[38]
	}
	{
	  qpxor,0	%r52, %b[41], %r52
	  qpxor,1	%b[1], %b[40], %b[1]
	  qpxor,3	%r40, %b[38], %r40
	  qpsrcw,4	%b[10], %r22, %b[10]
	}
	{
	  qpaddw,0	%b[9], %b[17], %b[38]
	  qpxor,1	%b[28], %b[37], %b[28]
	  qpaddw,3	%r40, %r48, %b[40]
	  qpsrcw,4	%b[42], %r22, %b[41]
	}
	{
	  qpaddw,0	%b[1], %r34, %b[37]
	  qpsrcw,1	%b[38], %r22, %b[38]
	  qpxor,3	%b[27], %b[39], %b[27]
	  qpsrcw,4	%b[40], 0xe, %b[40]
	}
	{
	  qpaddw,0	%r52, %b[5], %b[39]
	  qpsrcw,1	%b[37], %r22, %b[37]
	  qpxor,3	%b[29], %b[10], %b[10]
	  qpxor,4	%r62, %b[40], %r62
	}
	{
	  qpxor,0	%r43, %b[38], %r43
	  qpsrcw,1	%b[39], %r22, %b[29]
	  qpaddw,3	%r62, %r52, %b[38]
	  qpxor,4	%b[25], %b[41], %b[25]
	}
	{
	  qpxor,0	%g28, %b[29], %g28
	  qpxor,1	%r51, %b[37], %r51
	  qpaddw,3	%b[28], %b[30], %b[37]
	  qpsrcw,4	%b[38], %r23, %b[29]
	}
	{
	  qpaddw,0	%r43, %b[9], %b[38]
	  qpaddw,3	%b[27], %b[21], %b[39]
	  qpsrcw,4	%b[37], %r21, %b[37]
	}
	{
	  qpaddw,0	%r51, %b[1], %b[40]
	  qpsrcw,1	%b[38], %r21, %b[38]
	  qpaddw,3	%b[10], %b[32], %b[41]
	  qpsrcw,4	%b[39], %r21, %b[39]
	}
	{
	  qpaddw,0	%g28, %r52, %b[42]
	  qpsrcw,1	%b[40], %r21, %b[40]
	  qpaddw,3	%b[25], %b[31], %b[43]
	  qpsrcw,4	%b[41], %r21, %b[41]
	}
	{
	  qpsrcw,0	%b[42], %r21, %b[42]
	  qpxor,1	%r37, %b[38], %r37
	  qpsrcw,3	%b[43], %r21, %b[38]
	  qpxor,4	%b[22], %b[37], %b[22]
	}
	{
	  qpxor,0	%r33, %b[42], %r33
	  qpxor,1	%b[24], %b[40], %b[24]
	  qpxor,3	%b[18], %b[41], %b[18]
	  qpxor,4	%b[26], %b[39], %b[26]
	}
	{
	  qpaddw,0	%r37, %r43, %b[37]
	  qpxor,1	%b[24], %b[29], %b[29]
	  qpaddw,3	%b[22], %b[28], %b[38]
	  qpxor,4	%b[23], %b[38], %b[23]
	}
	{
	  qpaddw,0	%b[24], %r51, %b[24]
	  qpsrcw,1	%b[37], 0xe, %b[37]
	  qpaddw,3	%b[26], %b[27], %b[39]
	  qpsrcw,4	%b[38], 0xe, %b[38]
	}
	{
	  qpaddw,0	%r33, %g28, %b[40]
	  qpsrcw,1	%b[24], 0xe, %b[24]
	  qpaddw,3	%b[18], %b[10], %b[41]
	  qpsrcw,4	%b[39], 0xe, %b[39]
	}
	{
	  qpxor,0	%b[17], %b[37], %b[17]
	  qpsrcw,1	%b[40], 0xe, %b[40]
	  qpaddw,3	%b[23], %b[25], %b[37]
	  qpsrcw,4	%b[41], 0xe, %b[41]
	}
	{
	  qpxor,0	%b[5], %b[40], %b[5]
	  qpxor,1	%r34, %b[24], %r34
	  qpaddw,3	%b[29], %r62, %b[24]
	  qpsrcw,4	%b[37], 0xe, %b[37]
	}
	{
	  qpaddw,0	%b[17], %b[1], %b[40]
	  qpxor,1	%b[36], %b[38], %b[36]
	  qpsrcw,3	%b[24], %r22, %b[24]
	  qpxor,4	%b[33], %b[39], %b[33]
	}
	{
	  qpaddw,0	%r34, %r55, %b[38]
	  qpsrcw,1	%b[40], %r23, %b[39]
	  qpxor,3	%b[34], %b[41], %b[24]
	  qpxor,4	%r43, %b[24], %r43
	}
	{
	  qpaddw,0	%b[5], %b[9], %b[34]
	  qpsrcw,1	%b[38], %r23, %b[38]
	  qpaddw,3	%r43, %b[29], %b[40]
	  qpxor,4	%b[35], %b[37], %b[35]
	}
	{
	  qpxor,0	%r33, %b[39], %r33
	  qpsrcw,1	%b[34], %r23, %b[34]
	  qpaddw,3	%b[33], %b[31], %b[39]
	  qpsrcw,4	%b[40], %r21, %b[37]
	}
	{
	  qpxor,0	%r40, %b[34], %r40
	  qpxor,1	%r37, %b[38], %r37
	  qpaddw,3	%b[36], %b[32], %b[34]
	  qpxor,4	%r52, %b[37], %r52
	}
	{
	  qpaddw,0	%r33, %b[17], %b[37]
	  qpaddw,3	%r52, %r43, %b[38]
	  qpsrcw,4	%b[39], %r23, %b[39]
	}
	{
	  qpaddw,0	%r37, %r34, %b[40]
	  qpsrcw,1	%b[37], %r22, %b[37]
	  qpaddw,3	%b[24], %b[21], %b[41]
	  qpsrcw,4	%b[38], 0xe, %b[38]
	}
	{
	  qpaddw,0	%r40, %b[5], %b[42]
	  qpsrcw,1	%b[40], %r22, %b[40]
	  qpaddw,3	%b[35], %b[30], %b[38]
	  qpxor,4	%r62, %b[38], %r62
	}
	{
	  qpxor,0	%r48, %b[37], %r48
	  qpsrcw,1	%b[42], %r22, %b[42]
	  qpaddw,3	%r62, %r40, %b[37]
	  qpsrcw,4	%b[34], %r23, %b[34]
	}
	{
	  qpxor,0	%r51, %b[42], %r51
	  qpxor,1	%g28, %b[40], %g28
	  qpsrcw,3	%b[37], %r23, %b[37]
	  qpsrcw,4	%b[41], %r23, %b[40]
	}
	{
	  qpaddw,0	%r48, %r33, %b[41]
	  qpsrcw,3	%b[38], %r23, %b[38]
	  qpxor,4	%b[18], %b[39], %b[18]
	}
	{
	  qpaddw,0	%g28, %r37, %b[39]
	  qpsrcw,1	%b[41], %r21, %b[41]
	  qpxor,3	%b[22], %b[40], %b[22]
	  qpxor,4	%b[23], %b[34], %b[23]
	}
	{
	  qpaddw,0	%r51, %r40, %b[34]
	  qpsrcw,1	%b[39], %r21, %b[39]
	  qpaddw,3	%b[18], %b[33], %b[38]
	  qpxor,4	%b[26], %b[38], %b[26]
	}
	{
	  qpxor,0	%b[1], %b[41], %b[1]
	  qpsrcw,1	%b[34], %r21, %b[34]
	  qpaddw,3	%b[23], %b[36], %b[40]
	  qpsrcw,4	%b[38], %r22, %b[38]
	}
	{
	  qpxor,0	%b[9], %b[34], %b[9]
	  qpxor,1	%r55, %b[39], %r55
	  qpaddw,3	%b[22], %b[24], %b[34]
	  qpsrcw,4	%b[40], %r22, %b[39]
	}
	{
	  qpaddw,0	%b[1], %r48, %b[40]
	  qpxor,1	%r55, %b[37], %b[37]
	  qpaddw,3	%b[26], %b[35], %b[41]
	  qpsrcw,4	%b[34], %r22, %b[34]
	}
	{
	  qpaddw,0	%r55, %g28, %r55
	  qpsrcw,1	%b[40], 0xe, %b[40]
	  qpsrcw,3	%b[41], %r22, %b[41]
	  qpxor,4	%b[28], %b[38], %b[28]
	}
	{
	  qpaddw,0	%b[9], %r51, %b[38]
	  qpsrcw,1	%r55, 0xe, %r55
	  qpxor,3	%b[25], %b[34], %b[25]
	  qpxor,4	%b[27], %b[39], %b[27]
	}
	{
	  qpxor,0	%b[17], %b[40], %b[17]
	  qpsrcw,1	%b[38], 0xe, %b[34]
	  qpaddw,3	%b[28], %b[18], %b[38]
	  qpxor,4	%b[10], %b[41], %b[10]
	}
	{
	  qpxor,0	%b[5], %b[34], %r55
	  qpxor,1	%r34, %r55, %r34
	  qpaddw,3	%b[37], %r62, %b[5]
	  qpsrcw,4	%b[38], %r21, %b[34]
	}
	{
	  qpaddw,0	%b[17], %r37, %b[38]
	  qpaddw,3	%b[27], %b[23], %b[39]
	  qpsrcw,4	%b[5], %r22, %b[5]
	}
	{
	  qpaddw,0	%r34, %b[29], %b[40]
	  qpsrcw,1	%b[38], %r23, %b[38]
	  qpaddw,3	%b[25], %b[22], %b[5]
	  qpxor,4	%r48, %b[5], %r48
	}
	{
	  qpaddw,0	%r55, %r33, %b[41]
	  qpsrcw,1	%b[40], %r23, %b[40]
	  qpaddw,3	%r48, %b[37], %b[42]
	  qpsrcw,4	%b[39], %r21, %b[39]
	}
	{
	  qpxor,0	%b[9], %b[38], %b[9]
	  qpsrcw,1	%b[41], %r23, %b[41]
	  qpaddw,3	%b[10], %b[26], %b[42]
	  qpsrcw,4	%b[42], %r21, %b[38]
	}
	{
	  qpxor,0	%r52, %b[41], %r52
	  qpxor,1	%b[1], %b[40], %b[1]
	  qpxor,3	%r40, %b[38], %r40
	  qpsrcw,4	%b[5], %r21, %b[5]
	}
	{
	  qpaddw,0	%b[9], %b[17], %b[38]
	  qpxor,1	%b[31], %b[34], %b[31]
	  qpaddw,3	%r40, %r48, %b[40]
	  qpsrcw,4	%b[42], %r21, %b[41]
	}
	{
	  qpaddw,0	%b[1], %r34, %b[34]
	  qpsrcw,1	%b[38], %r22, %b[38]
	  qpxor,3	%b[32], %b[39], %b[32]
	  qpsrcw,4	%b[40], 0xe, %b[40]
	}
	{
	  qpaddw,0	%r52, %r55, %b[39]
	  qpsrcw,1	%b[34], %r22, %b[34]
	  qpxor,3	%b[21], %b[5], %b[5]
	  qpxor,4	%r62, %b[40], %r62
	}
	{
	  qpxor,0	%r43, %b[38], %r43
	  qpsrcw,1	%b[39], %r22, %b[21]
	  qpaddw,3	%r62, %r52, %b[38]
	  qpxor,4	%b[30], %b[41], %b[30]
	}
	{
	  qpxor,0	%g28, %b[21], %g28
	  qpxor,1	%r51, %b[34], %r51
	  qpaddw,3	%b[31], %b[28], %b[34]
	  qpsrcw,4	%b[38], %r23, %b[21]
	}
	{
	  qpaddw,0	%r43, %b[9], %b[38]
	  qpaddw,3	%b[32], %b[27], %b[39]
	  qpsrcw,4	%b[34], 0xe, %b[34]
	}
	{
	  qpaddw,0	%r51, %b[1], %b[40]
	  qpsrcw,1	%b[38], %r21, %b[38]
	  qpaddw,3	%b[5], %b[25], %b[41]
	  qpsrcw,4	%b[39], 0xe, %b[39]
	}
	{
	  qpaddw,0	%g28, %r52, %b[42]
	  qpsrcw,1	%b[40], %r21, %b[40]
	  qpaddw,3	%b[30], %b[10], %b[43]
	  qpsrcw,4	%b[41], 0xe, %b[41]
	}
	{
	  qpsrcw,0	%b[42], %r21, %b[42]
	  qpxor,1	%r37, %b[38], %r37
	  qpsrcw,3	%b[43], 0xe, %b[38]
	  qpxor,4	%b[33], %b[34], %b[33]
	}
	{
	  qpxor,0	%r33, %b[42], %r33
	  qpxor,1	%b[29], %b[40], %b[29]
	  qpxor,3	%b[24], %b[41], %b[24]
	  qpxor,4	%b[36], %b[39], %b[34]
	}
	{
	  qpaddw,0	%r37, %r43, %b[36]
	  qpxor,1	%b[29], %b[21], %b[21]
	  qpaddw,3	%b[33], %b[26], %b[38]
	  qpxor,4	%b[35], %b[38], %b[35]
	}
	{
	  qpaddw,0	%b[29], %r51, %b[29]
	  qpsrcw,1	%b[36], 0xe, %b[36]
	  qpaddw,3	%b[34], %b[22], %b[39]
	  qpsrcw,4	%b[38], %r23, %b[38]
	}
	{
	  qpaddw,0	%r33, %g28, %b[40]
	  qpsrcw,1	%b[29], 0xe, %b[29]
	  qpaddw,3	%b[24], %b[18], %b[41]
	  qpsrcw,4	%b[39], %r23, %b[39]
	}
	{
	  qpxor,0	%b[17], %b[36], %b[17]
	  qpsrcw,1	%b[40], 0xe, %b[40]
	  qpaddw,3	%b[35], %b[23], %b[36]
	  qpsrcw,4	%b[41], %r23, %b[41]
	}
	{
	  qpxor,0	%r55, %b[40], %r55
	  qpxor,1	%r34, %b[29], %r34
	  qpaddw,3	%b[21], %r62, %b[29]
	  qpsrcw,4	%b[36], %r23, %b[36]
	}
	{
	  qpaddw,0	%b[17], %b[1], %b[40]
	  qpxor,1	%b[5], %b[38], %b[5]
	  qpsrcw,3	%b[29], %r22, %b[29]
	  qpxor,4	%b[30], %b[39], %b[30]
	}
	{
	  qpaddw,0	%r34, %b[37], %b[38]
	  qpsrcw,1	%b[40], %r23, %b[39]
	  qpxor,3	%b[32], %b[41], %b[29]
	  qpxor,4	%r43, %b[29], %r43
	}
	{
	  qpaddw,0	%r55, %b[9], %b[32]
	  qpsrcw,1	%b[38], %r23, %b[38]
	  qpaddw,3	%r43, %b[21], %b[40]
	  qpxor,4	%b[31], %b[36], %b[31]
	}
	{
	  qpxor,0	%r33, %b[39], %r33
	  qpsrcw,1	%b[32], %r23, %b[32]
	  qpaddw,3	%b[30], %b[34], %b[39]
	  qpsrcw,4	%b[40], %r21, %b[36]
	}
	{
	  qpxor,0	%r40, %b[32], %r40
	  qpxor,1	%r37, %b[38], %r37
	  qpaddw,3	%b[5], %b[33], %b[32]
	  qpxor,4	%r52, %b[36], %r52
	}
	{
	  qpaddw,0	%r33, %b[17], %b[36]
	  qpaddw,3	%r52, %r43, %b[38]
	  qpsrcw,4	%b[39], %r22, %b[39]
	}
	{
	  qpaddw,0	%r37, %r34, %b[40]
	  qpsrcw,1	%b[36], %r22, %b[36]
	  qpaddw,3	%b[29], %b[24], %b[41]
	  qpsrcw,4	%b[38], 0xe, %b[38]
	}
	{
	  qpaddw,0	%r40, %r55, %b[42]
	  qpsrcw,1	%b[40], %r22, %b[40]
	  qpaddw,3	%b[31], %b[35], %b[38]
	  qpxor,4	%r62, %b[38], %r62
	}
	{
	  qpxor,0	%r48, %b[36], %r48
	  qpsrcw,1	%b[42], %r22, %b[42]
	  qpaddw,3	%r62, %r40, %b[36]
	  qpsrcw,4	%b[32], %r22, %b[32]
	}
	{
	  qpxor,0	%r51, %b[42], %r51
	  qpxor,1	%g28, %b[40], %g28
	  qpsrcw,3	%b[36], %r23, %b[36]
	  qpsrcw,4	%b[41], %r22, %b[40]
	}
	{
	  qpaddw,0	%r48, %r33, %b[41]
	  qpsrcw,3	%b[38], %r22, %b[38]
	  qpxor,4	%b[28], %b[39], %b[28]
	}
	{
	  qpaddw,0	%g28, %r37, %b[39]
	  qpsrcw,1	%b[41], %r21, %b[41]
	  qpxor,3	%b[10], %b[40], %b[10]
	  qpxor,4	%b[27], %b[32], %b[27]
	}
	{
	  qpaddw,0	%r51, %r40, %b[32]
	  qpsrcw,1	%b[39], %r21, %b[39]
	  qpaddw,3	%b[28], %b[30], %b[38]
	  qpxor,4	%b[25], %b[38], %b[25]
	}
	{
	  qpxor,0	%b[1], %b[41], %b[1]
	  qpsrcw,1	%b[32], %r21, %b[32]
	  qpaddw,3	%b[27], %b[5], %b[40]
	  qpsrcw,4	%b[38], %r21, %b[38]
	}
	{
	  qpxor,0	%b[9], %b[32], %b[9]
	  qpxor,1	%b[37], %b[39], %b[37]
	  qpaddw,3	%b[10], %b[29], %b[32]
	  qpsrcw,4	%b[40], %r21, %b[39]
	}
	{
	  qpaddw,0	%b[1], %r48, %b[40]
	  qpxor,1	%b[37], %b[36], %b[36]
	  qpaddw,3	%b[25], %b[31], %b[41]
	  qpsrcw,4	%b[32], %r21, %b[32]
	}
	{
	  qpaddw,0	%b[37], %g28, %b[37]
	  qpsrcw,1	%b[40], 0xe, %b[40]
	  qpsrcw,3	%b[41], %r21, %b[41]
	  qpxor,4	%b[22], %b[38], %b[22]
	}
	{
	  qpaddw,0	%b[9], %r51, %b[38]
	  qpsrcw,1	%b[37], 0xe, %b[37]
	  qpxor,3	%b[18], %b[32], %b[18]
	  qpxor,4	%b[26], %b[39], %b[26]
	}
	{
	  qpxor,0	%b[17], %b[40], %b[17]
	  qpsrcw,1	%b[38], 0xe, %b[32]
	  qpaddw,3	%b[22], %b[28], %b[38]
	  qpxor,4	%b[23], %b[41], %b[23]
	}
	{
	  qpxor,0	%r55, %b[32], %r55
	  qpxor,1	%r34, %b[37], %r34
	  qpaddw,3	%b[36], %r62, %b[32]
	  qpsrcw,4	%b[38], 0xe, %b[37]
	}
	{
	  qpaddw,0	%b[17], %r37, %b[38]
	  qpaddw,3	%g29, %b[36], %g29
	  qpsrcw,4	%b[32], %r22, %b[32]
	}
	{
	  qpaddw,0	%r34, %b[21], %b[39]
	  qpsrcw,1	%b[38], %r23, %b[38]
	  qpxor,3	%g30, %g29, %g30
	  qpxor,4	%r48, %b[32], %r48
	  stqp,5	%r1, _f16s,_lts0lo 0x2c0, %g29
	}
	{
	  qpaddw,0	%r55, %r33, %b[32]
	  qpsrcw,1	%b[39], %r23, %b[39]
	  qpaddw,3	%r48, %b[36], %b[36]
	  qpxor,4	%b[34], %b[37], %b[34]
	}
	{
	  qpxor,0	%b[9], %b[38], %b[9]
	  qpsrcw,1	%b[32], %r23, %b[32]
	  qpaddw,3	%r30, %r48, %r30
	  qpsrcw,4	%b[36], %r21, %b[36]
	}
	{
	  qpxor,0	%r52, %b[32], %r52
	  qpxor,1	%b[1], %b[39], %b[1]
	  qpaddw,3	%b[26], %b[27], %b[32]
	  qpxor,4	%r40, %b[36], %r40
	  stqp,5	%r1, _f16s,_lts0lo 0x2d0, %r30
	}
	{
	  qpaddw,0	%b[9], %b[17], %b[36]
	  qpaddw,3	%r40, %r48, %r48
	  qpxor,4	%r29, %r30, %r29
	}
	{
	  qpaddw,0	%b[1], %r34, %b[37]
	  qpsrcw,1	%b[36], %r22, %b[36]
	  qpaddw,3	%r11, %r40, %r11
	  qpsrcw,4	%r48, 0xe, %r48
	}
	{
	  qpaddw,0	%r52, %r55, %r40
	  qpsrcw,1	%b[37], %r22, %b[37]
	  qpaddw,3	%g22, %b[9], %g22
	  qpxor,4	%r62, %r48, %r48
	  stqp,5	%r1, _f16s,_lts0lo 0x2e0, %r11
	}
	{
	  qpxor,0	%r43, %b[36], %r43
	  qpsrcw,1	%r40, %r22, %r40
	  qpaddw,3	%g18, %b[1], %g18
	  qpxor,4	%g23, %g22, %g23
	  stqp,5	%r1, _f16s,_lts0lo 0x260, %g22
	}
	{
	  qpxor,0	%g28, %r40, %g28
	  qpxor,1	%r51, %b[37], %r51
	  qpaddw,3	%g26, %r52, %g26
	  qpxor,4	%g19, %g18, %g19
	  stqp,5	%r1, _f16s,_lts0lo 0x210, %g18
	}
	{
	  qpaddw,0	%r43, %b[9], %r40
	  qpxor,1	%r10, %r11, %r10
	  qpaddw,3	%g31, %r48, %g31
	  qpxor,4	%g27, %g26, %g27
	  stqp,5	%r1, _f16s,_lts0lo 0x2b0, %g26
	}
	{
	  qpaddw,0	%r51, %b[1], %r48
	  qpsrcw,1	%r40, %r21, %r40
	  qpaddw,3	%b[18], %b[10], %r62
	  qpxor,4	%r4, %g31, %r4
	  stqp,5	%r1, _f16s,_lts0lo 0x2f0, %g31
	}
	{
	  qpaddw,0	%g28, %r52, %r52
	  qpsrcw,1	%r48, %r21, %r48
	  qpaddw,3	%r4, %g27, %b[1]
	  qpsrcw,4	%b[32], 0xe, %b[9]
	}
	{
	  qpxor,0	%r37, %r40, %r37
	  qpsrcw,1	%r52, %r21, %r52
	  qpaddw,3	%r36, %r43, %r36
	  qpsrcw,4	%b[1], %r23, %r40
	}
	{
	  qpxor,0	%r33, %r52, %r33
	  qpxor,1	%b[21], %r48, %r48
	  qpaddw,3	%r39, %r51, %r39
	  qpxor,4	%r35, %r36, %r35
	  stqp,5	%r1, _f16s,_lts0lo 0x270, %r36
	}
	{
	  qpaddw,0	%r37, %r43, %r43
	  qpsrcw,1	%r62, 0xe, %r52
	  qpaddw,3	%r32, %g28, %r32
	  qpxor,4	%r38, %r39, %r38
	  stqp,5	%r1, _f16s,_lts0lo 0x220, %r39
	}
	{
	  qpaddw,0	%r48, %r51, %r51
	  qpsrcw,1	%r43, 0xe, %r43
	  qpaddw,3	%b[23], %b[25], %r62
	  qpxor,4	%r31, %r32, %r31
	  stqp,5	%r1, _f16s,_lts0lo 0x280, %r32
	}
	{
	  qpaddw,0	%r33, %g28, %g28
	  qpsrcw,1	%r51, 0xe, %r51
	  qpaddw,3	%r15, %r37, %r15
	  qpsrcw,4	%r62, 0xe, %r37
	}
	{
	  qpxor,0	%b[17], %r43, %r43
	  qpsrcw,1	%g28, 0xe, %g28
	  qpaddw,3	%r17, %r48, %r17
	  qpxor,4	%r14, %r15, %r14
	  stqp,5	%r1, _f16s,_lts0lo 0x240, %r15
	}
	{
	  qpxor,0	%r55, %g28, %g28
	  qpxor,1	%r34, %r51, %r34
	  qpaddw,3	%r13, %r33, %r13
	  qpxor,4	%r16, %r17, %r16
	  stqp,5	%r1, _f16s,_lts0lo 0x230, %r17
	}
	{
	  qpaddw,0	%g20, %r43, %g20
	  qpxor,1	%b[33], %b[9], %r40
	  qpxor,3	%r16, %r40, %r33
	  qpxor,4	%r12, %r13, %r12
	  stqp,5	%r1, _f16s,_lts0lo 0x290, %r13
	}
	{
	  qpaddw,0	%g16, %r34, %g16
	  qpxor,1	%g21, %g20, %g21
	  stqp,2	%r1, _f16s,_lts0lo 0x250, %g20
	  qpaddw,3	%r33, %r4, %r34
	  qpxor,4	%b[24], %r52, %r43
	}
	{
	  qpaddw,0	%g24, %g28, %g24
	  qpxor,1	%g17, %g16, %g17
	  stqp,2	%r1, _f16s,_lts0lo 0x200, %g16
	  qpxor,3	%b[35], %r37, %r34
	  qpsrcw,4	%r34, %r22, %g28
	}
	{
	  qpaddw,0	%g21, %g19, %r37
	  qpxor,1	%g25, %g24, %g25
	  stqp,2	%r1, _f16s,_lts0lo 0x2a0, %g24
	  qpaddw,3	%b[34], %b[29], %r48
	  qpxor,4	%r35, %g28, %g28
	}
	{
	  qpaddw,0	%g17, %g30, %r51
	  qpsrcw,1	%r37, %r23, %r37
	  qpaddw,3	%g28, %r33, %r52
	  qpsrcw,4	%r48, %r23, %r48
	}
	{
	  qpaddw,0	%g25, %g23, %r55
	  qpsrcw,1	%r51, %r23, %r51
	  qpaddw,3	%r40, %b[31], %r62
	  qpsrcw,4	%r52, %r21, %r52
	}
	{
	  qpxor,0	%r12, %r37, %r37
	  qpsrcw,1	%r55, %r23, %r55
	  qpaddw,3	%r43, %b[5], %b[1]
	  qpsrcw,4	%r62, %r23, %r62
	}
	{
	  qpxor,0	%r10, %r55, %r55
	  qpxor,1	%r14, %r51, %r51
	  qpaddw,3	%r34, %b[30], %b[9]
	  qpxor,4	%g27, %r52, %r52
	}
	{
	  qpaddw,0	%r37, %g21, %b[17]
	  qpxor,1	%b[23], %r48, %r48
	  qpsrcw,3	%b[9], %r23, %b[9]
	  qpsrcw,4	%b[1], %r23, %b[1]
	}
	{
	  qpaddw,0	%r51, %g17, %b[21]
	  qpsrcw,1	%b[17], %r22, %b[17]
	  qpaddw,3	%r52, %g28, %b[23]
	  qpxor,4	%b[18], %r62, %r62
	}
	{
	  qpaddw,0	%r55, %g25, %b[18]
	  qpsrcw,1	%b[21], %r22, %b[21]
	  qpxor,3	%b[26], %b[9], %b[9]
	  qpxor,4	%b[22], %b[1], %b[1]
	}
	{
	  qpxor,0	%r29, %b[17], %b[17]
	  qpsrcw,1	%b[18], %r22, %b[18]
	  qpaddw,3	%r62, %r40, %b[22]
	  qpsrcw,4	%b[23], 0xe, %b[23]
	}
	{
	  qpxor,0	%r38, %b[18], %b[18]
	  qpxor,1	%r31, %b[21], %b[21]
	  qpaddw,3	%r48, %b[34], %b[24]
	  qpsrcw,4	%b[22], %r22, %b[22]
	}
	{
	  qpaddw,0	%b[17], %r37, %b[26]
	  qppermb,1	%r30, %g29, %r18, %b[33]
	  qpaddw,3	%b[1], %r43, %b[32]
	  qpxor,4	%r4, %b[23], %b[23]
	}
	{
	  qpaddw,0	%b[21], %r51, %b[35]
	  qpsrcw,1	%b[26], %r21, %b[26]
	  qpaddw,3	%b[9], %r34, %b[36]
	  qpsrcw,4	%b[24], %r22, %b[24]
	}
	{
	  qpaddw,0	%b[18], %r55, %b[37]
	  qpsrcw,1	%b[35], %r21, %b[35]
	  qpsrcw,3	%b[36], %r22, %b[36]
	  qpsrcw,4	%b[32], %r22, %b[32]
	}
	{
	  qpxor,0	%g19, %b[26], %b[26]
	  qpsrcw,1	%b[37], %r21, %b[37]
	  qpaddw,3	%b[23], %r55, %b[38]
	  qpxor,4	%b[28], %b[22], %b[22]
	}
	{
	  qpxor,0	%g23, %b[37], %b[35]
	  qpxor,1	%g30, %b[35], %b[28]
	  qpxor,3	%b[25], %b[32], %b[25]
	  qpxor,4	%b[27], %b[24], %b[24]
	}
	{
	  qpaddw,0	%b[26], %b[17], %b[27]
	  qppermb,1	%g31, %r11, %r18, %b[36]
	  qpaddw,3	%b[24], %r48, %b[32]
	  qpxor,4	%b[10], %b[36], %b[10]
	}
	{
	  qpaddw,0	%b[28], %b[21], %b[37]
	  qpsrcw,1	%b[27], 0xe, %b[27]
	  qpaddw,3	%b[25], %b[1], %b[39]
	  qpsrcw,4	%b[38], %r23, %b[38]
	}
	{
	  qpaddw,0	%b[35], %b[18], %b[40]
	  qpsrcw,1	%b[37], 0xe, %b[37]
	  qpaddw,3	%b[10], %b[9], %b[41]
	  qpsrcw,4	%b[32], %r21, %b[32]
	}
	{
	  qpxor,0	%g21, %b[27], %b[27]
	  qpsrcw,1	%b[40], 0xe, %b[40]
	  qpaddw,3	%b[22], %r62, %b[42]
	  qpsrcw,4	%b[39], %r21, %b[39]
	}
	{
	  qpxor,0	%g25, %b[40], %b[40]
	  qpxor,1	%g17, %b[37], %b[37]
	  qpxor,3	%b[28], %b[38], %b[28]
	  qpsrcw,4	%b[41], %r21, %b[38]
	}
	{
	  qpaddw,0	%b[27], %r51, %b[41]
	  qppermb,1	%r30, %g29, %r19, %g29
	  qpaddw,3	%b[28], %b[23], %b[43]
	  qpsrcw,4	%b[42], %r21, %b[42]
	}
	{
	  qpaddw,0	%b[37], %r33, %r30
	  qpsrcw,1	%b[41], %r23, %b[41]
	  qpxor,3	%b[29], %b[32], %b[29]
	  qpxor,4	%b[5], %b[39], %b[5]
	}
	{
	  qpaddw,0	%b[40], %r37, %b[32]
	  qpsrcw,1	%r30, %r23, %r30
	  qpxor,3	%b[31], %b[42], %b[31]
	  qpxor,4	%b[30], %b[38], %b[30]
	}
	{
	  qpxor,0	%b[35], %b[41], %b[35]
	  qpsrcw,1	%b[32], %r23, %b[32]
	  qpaddw,3	%b[29], %b[24], %b[38]
	  qpsrcw,4	%b[43], %r22, %b[39]
	}
	{
	  qpxor,0	%r52, %b[32], %r52
	  qpxor,1	%b[26], %r30, %r30
	  qpaddw,3	%b[5], %b[25], %b[26]
	  qpsrcw,4	%b[38], 0xe, %b[32]
	}
	{
	  qpaddw,0	%b[35], %b[27], %b[38]
	  qppermb,1	%g31, %r11, %r19, %g31
	  qpaddw,3	%b[30], %b[10], %b[41]
	  qpxor,4	%b[17], %b[39], %b[17]
	}
	{
	  qpaddw,0	%r30, %b[37], %r11
	  qpsrcw,1	%b[38], %r22, %b[38]
	  qpaddw,3	%b[31], %b[22], %b[39]
	  qpsrcw,4	%b[26], 0xe, %b[26]
	}
	{
	  qpaddw,0	%r52, %b[40], %b[42]
	  qpsrcw,1	%r11, %r22, %r11
	  qpsrcw,3	%b[39], 0xe, %b[39]
	  qpsrcw,4	%b[41], 0xe, %b[41]
	}
	{
	  qpxor,0	%g28, %b[38], %g28
	  qpsrcw,1	%b[42], %r22, %b[42]
	  qpaddw,3	%b[17], %b[28], %b[38]
	  qpxor,4	%b[34], %b[32], %b[32]
	}
	{
	  qpxor,0	%b[21], %b[42], %b[18]
	  qpxor,1	%b[18], %r11, %r11
	  qpxor,3	%r34, %b[41], %r34
	  qpxor,4	%r43, %b[26], %r43
	}
	{
	  qpaddw,0	%g28, %b[35], %b[21]
	  qppermb,1	%r36, %g22, %r18, %b[34]
	  qpaddw,3	%b[32], %b[1], %b[26]
	  qpxor,4	%r40, %b[39], %r40
	}
	{
	  qpaddw,0	%r11, %r30, %b[39]
	  qpsrcw,1	%b[21], %r21, %b[21]
	  qpaddw,3	%r43, %r62, %b[41]
	  qpsrcw,4	%b[38], %r21, %b[38]
	}
	{
	  qpaddw,0	%b[18], %r52, %b[42]
	  qpsrcw,1	%b[39], %r21, %b[39]
	  qpaddw,3	%r34, %r48, %b[43]
	  qpsrcw,4	%b[26], %r23, %b[26]
	}
	{
	  qpsrcw,0	%b[42], %r21, %b[42]
	  qpxor,1	%r51, %b[21], %r51
	  qpaddw,3	%r40, %b[9], %b[44]
	  qpsrcw,4	%b[41], %r23, %b[41]
	}
	{
	  qpxor,0	%r37, %b[42], %r37
	  qpxor,1	%r33, %b[39], %r33
	  qpsrcw,3	%b[43], %r23, %b[21]
	  qpxor,4	%r55, %b[38], %r55
	}
	{
	  qpaddw,0	%r51, %g28, %b[39]
	  qppermb,1	%g20, %r15, %r18, %b[43]
	  qpaddw,3	%r55, %b[17], %b[42]
	  qpsrcw,4	%b[44], %r23, %b[38]
	}
	{
	  qpaddw,0	%r33, %r11, %b[44]
	  qpxor,1	%b[30], %b[26], %b[26]
	  qpxor,3	%b[29], %b[41], %b[29]
	  qpxor,4	%b[31], %b[21], %b[21]
	}
	{
	  qpaddw,0	%r37, %b[18], %b[30]
	  qpsrcw,1	%b[39], 0xe, %b[38]
	  qpaddw,3	%b[29], %r43, %b[31]
	  qpxor,4	%b[5], %b[38], %b[5]
	}
	{
	  qpaddw,0	%b[26], %b[32], %b[39]
	  qpsrcw,1	%b[44], 0xe, %b[44]
	  qpaddw,3	%b[21], %r34, %b[41]
	  qpsrcw,4	%b[42], 0xe, %b[42]
	}
	{
	  qpsrcw,0	%b[30], 0xe, %b[30]
	  qpxor,1	%b[27], %b[38], %b[27]
	  qpaddw,3	%b[5], %r40, %b[45]
	  qpsrcw,4	%b[31], %r22, %b[31]
	}
	{
	  qpsrcw,0	%b[39], %r22, %b[38]
	  qpxor,1	%b[37], %b[44], %b[37]
	  qpxor,3	%b[23], %b[42], %b[23]
	  qpsrcw,4	%b[41], %r22, %b[39]
	}
	{
	  qpaddw,0	%b[27], %r30, %b[40]
	  qpxor,1	%b[40], %b[30], %b[30]
	  qpaddw,3	%b[23], %r52, %b[42]
	  qpsrcw,4	%b[45], %r22, %b[41]
	}
	{
	  qpaddw,0	%b[37], %b[28], %b[44]
	  qpxor,1	%b[22], %b[38], %b[22]
	  qpxor,3	%b[10], %b[31], %b[10]
	  qpxor,4	%b[25], %b[39], %b[25]
	}
	{
	  qpaddw,0	%b[30], %b[35], %b[31]
	  qpsrcw,1	%b[40], %r23, %b[39]
	  qpaddw,3	%b[10], %b[29], %b[38]
	  qpxor,4	%b[24], %b[41], %b[24]
	}
	{
	  qpaddw,0	%b[22], %b[26], %b[40]
	  qpsrcw,1	%b[44], %r23, %b[44]
	  qpaddw,3	%b[25], %b[21], %b[41]
	  qpsrcw,4	%b[42], %r23, %b[42]
	}
	{
	  qpsrcw,0	%b[31], %r23, %b[31]
	  qpxor,1	%r37, %b[39], %r37
	  qpaddw,3	%b[24], %b[5], %b[45]
	  qpsrcw,4	%b[38], %r21, %b[38]
	}
	{
	  qpsrcw,0	%b[40], %r21, %b[39]
	  qpxor,1	%r51, %b[44], %r51
	  qpxor,3	%r33, %b[42], %r33
	  qpsrcw,4	%b[41], %r21, %b[40]
	}
	{
	  qpaddw,0	%r37, %b[27], %b[31]
	  qpxor,1	%r55, %b[31], %r55
	  qpaddw,3	%r33, %b[23], %b[42]
	  qpsrcw,4	%b[45], %r21, %b[41]
	}
	{
	  qpaddw,0	%r51, %b[37], %b[44]
	  qpxor,1	%b[1], %b[39], %b[1]
	  qpxor,3	%r62, %b[38], %r62
	  qpxor,4	%r48, %b[40], %r48
	}
	{
	  qpaddw,0	%r55, %b[30], %b[38]
	  qpsrcw,1	%b[31], %r22, %b[31]
	  qpaddw,3	%r62, %b[10], %b[39]
	  qpxor,4	%b[9], %b[41], %b[9]
	}
	{
	  qpaddw,0	%b[1], %b[22], %b[40]
	  qpsrcw,1	%b[44], %r22, %b[44]
	  qpaddw,3	%r48, %b[25], %b[41]
	  qpsrcw,4	%b[42], %r22, %b[42]
	}
	{
	  qpsrcw,0	%b[38], %r22, %b[38]
	  qpxor,1	%b[17], %b[31], %b[17]
	  qpaddw,3	%b[9], %b[24], %b[45]
	  qpsrcw,4	%b[39], 0xe, %b[39]
	}
	{
	  qpsrcw,0	%b[40], 0xe, %b[31]
	  qpxor,1	%b[18], %b[44], %b[18]
	  qpxor,3	%g28, %b[42], %g28
	  qpsrcw,4	%b[41], 0xe, %b[40]
	}
	{
	  qpaddw,0	%b[17], %r37, %b[38]
	  qpxor,1	%r11, %b[38], %r11
	  qpaddw,3	%g28, %r33, %b[42]
	  qpsrcw,4	%b[45], 0xe, %b[41]
	}
	{
	  qpaddw,0	%b[18], %r51, %b[44]
	  qpxor,1	%b[32], %b[31], %b[31]
	  qpxor,3	%r43, %b[39], %r43
	  qpxor,4	%r34, %b[40], %r34
	}
	{
	  qpaddw,0	%r11, %r55, %b[32]
	  qpsrcw,1	%b[38], %r21, %b[38]
	  qpaddw,3	%r43, %b[5], %b[39]
	  qpxor,4	%r40, %b[41], %r40
	}
	{
	  qpaddw,0	%b[31], %b[29], %b[40]
	  qpsrcw,1	%b[44], %r21, %b[44]
	  qpaddw,3	%r34, %b[26], %b[41]
	  qpsrcw,4	%b[42], %r21, %b[42]
	}
	{
	  qpsrcw,0	%b[32], %r21, %b[32]
	  qpxor,1	%r30, %b[38], %r30
	  qpaddw,3	%r40, %b[21], %b[45]
	  qpsrcw,4	%b[39], %r23, %b[39]
	}
	{
	  qpsrcw,0	%b[40], %r23, %b[38]
	  qpxor,1	%b[28], %b[44], %b[28]
	  qpxor,3	%r52, %b[42], %r52
	  qpsrcw,4	%b[41], %r23, %b[40]
	}
	{
	  qpaddw,0	%r30, %b[17], %b[35]
	  qpxor,1	%b[35], %b[32], %b[32]
	  qpaddw,3	%r52, %g28, %b[42]
	  qpsrcw,4	%b[45], %r23, %b[41]
	}
	{
	  qpaddw,0	%b[28], %b[18], %b[44]
	  qpxor,1	%r48, %b[38], %r48
	  qpxor,3	%b[1], %b[39], %b[1]
	  qpxor,4	%b[9], %b[40], %b[9]
	}
	{
	  qpaddw,0	%b[32], %r11, %b[38]
	  qpsrcw,1	%b[35], 0xe, %b[35]
	  qpaddw,3	%b[1], %r43, %b[39]
	  qpxor,4	%r62, %b[41], %r62
	}
	{
	  qpaddw,0	%r48, %b[31], %b[40]
	  qpsrcw,1	%b[44], 0xe, %b[44]
	  qpaddw,3	%b[9], %r34, %b[41]
	  qpsrcw,4	%b[42], 0xe, %b[42]
	}
	{
	  qpsrcw,0	%b[38], 0xe, %b[38]
	  qpxor,1	%b[27], %b[35], %b[27]
	  qpaddw,3	%r62, %r40, %b[45]
	  qpsrcw,4	%b[39], %r22, %b[39]
	}
	{
	  qpsrcw,0	%b[40], %r22, %b[35]
	  qpxor,1	%b[37], %b[44], %b[37]
	  qpxor,3	%b[23], %b[42], %b[23]
	  qpsrcw,4	%b[41], %r22, %b[40]
	}
	{
	  qpaddw,0	%b[27], %r51, %b[38]
	  qpxor,1	%b[30], %b[38], %b[30]
	  qpaddw,3	%b[23], %r55, %b[42]
	  qpsrcw,4	%b[45], %r22, %b[41]
	}
	{
	  qpaddw,0	%b[37], %r33, %b[44]
	  qpxor,1	%b[24], %b[35], %b[24]
	  qpxor,3	%b[25], %b[39], %b[25]
	  qpxor,4	%b[10], %b[40], %b[10]
	}
	{
	  qpaddw,0	%b[30], %r37, %b[35]
	  qpsrcw,1	%b[38], %r23, %b[38]
	  qpaddw,3	%b[25], %b[1], %b[39]
	  qpxor,4	%b[22], %b[41], %b[22]
	}
	{
	  qpaddw,0	%b[24], %r48, %b[40]
	  qpsrcw,1	%b[44], %r23, %b[44]
	  qpaddw,3	%b[10], %b[9], %b[41]
	  qpsrcw,4	%b[42], %r23, %b[42]
	}
	{
	  qpsrcw,0	%b[35], %r23, %b[35]
	  qpxor,1	%b[32], %b[38], %b[32]
	  qpaddw,3	%b[22], %r62, %b[45]
	  qpsrcw,4	%b[39], %r21, %b[39]
	}
	{
	  qpsrcw,0	%b[40], %r21, %b[38]
	  qpxor,1	%r30, %b[44], %r30
	  qpxor,3	%b[28], %b[42], %b[28]
	  qpsrcw,4	%b[41], %r21, %b[40]
	}
	{
	  qpaddw,0	%b[32], %b[27], %b[35]
	  qpxor,1	%r52, %b[35], %r52
	  qpaddw,3	%b[28], %b[23], %b[42]
	  qpsrcw,4	%b[45], %r21, %b[41]
	}
	{
	  qpaddw,0	%r30, %b[37], %b[44]
	  qpxor,1	%b[29], %b[38], %b[29]
	  qpxor,3	%b[5], %b[39], %b[5]
	  qpxor,4	%b[26], %b[40], %b[26]
	}
	{
	  qpaddw,0	%r52, %b[30], %b[38]
	  qpsrcw,1	%b[35], %r22, %b[35]
	  qpaddw,3	%b[5], %b[25], %b[39]
	  qpxor,4	%b[21], %b[41], %b[21]
	}
	{
	  qpaddw,0	%b[29], %b[24], %b[40]
	  qpsrcw,1	%b[44], %r22, %b[44]
	  qpaddw,3	%b[26], %b[10], %b[41]
	  qpsrcw,4	%b[42], %r22, %b[42]
	}
	{
	  qpsrcw,0	%b[38], %r22, %b[38]
	  qpxor,1	%g28, %b[35], %g28
	  qpaddw,3	%b[21], %b[22], %b[45]
	  qpsrcw,4	%b[39], 0xe, %b[39]
	}
	{
	  qpsrcw,0	%b[40], 0xe, %b[35]
	  qpxor,1	%r11, %b[44], %r11
	  qpxor,3	%b[17], %b[42], %b[17]
	  qpsrcw,4	%b[41], 0xe, %b[40]
	}
	{
	  qpaddw,0	%g28, %b[32], %b[38]
	  qpxor,1	%b[18], %b[38], %b[18]
	  qpaddw,3	%b[17], %b[28], %b[42]
	  qpsrcw,4	%b[45], 0xe, %b[41]
	}
	{
	  qpaddw,0	%r11, %r30, %b[44]
	  qpxor,1	%b[31], %b[35], %b[31]
	  qpxor,3	%r43, %b[39], %r43
	  qpxor,4	%r34, %b[40], %r34
	}
	{
	  qpaddw,0	%b[18], %r52, %b[35]
	  qpsrcw,1	%b[38], %r21, %b[38]
	  qpaddw,3	%r43, %r62, %b[39]
	  qpxor,4	%r40, %b[41], %r40
	}
	{
	  qpaddw,0	%b[31], %b[1], %b[40]
	  qpsrcw,1	%b[44], %r21, %b[44]
	  qpaddw,3	%r34, %r48, %b[41]
	  qpsrcw,4	%b[42], %r21, %b[42]
	}
	{
	  qpsrcw,0	%b[35], %r21, %b[35]
	  qpxor,1	%r51, %b[38], %r51
	  qpaddw,3	%r40, %b[9], %b[45]
	  qpsrcw,4	%b[39], %r23, %b[39]
	}
	{
	  qpsrcw,0	%b[40], %r23, %b[38]
	  qpxor,1	%r33, %b[44], %r33
	  qpxor,3	%r55, %b[42], %r55
	  qpsrcw,4	%b[41], %r23, %b[40]
	}
	{
	  qpaddw,0	%r51, %g28, %b[35]
	  qpxor,1	%r37, %b[35], %r37
	  qpaddw,3	%r55, %b[17], %b[42]
	  qpsrcw,4	%b[45], %r23, %b[41]
	}
	{
	  qpaddw,0	%r33, %r11, %b[44]
	  qpxor,1	%b[26], %b[38], %b[26]
	  qpxor,3	%b[29], %b[39], %b[29]
	  qpxor,4	%b[21], %b[40], %b[21]
	}
	{
	  qpaddw,0	%r37, %b[18], %b[38]
	  qpsrcw,1	%b[35], 0xe, %b[35]
	  qpaddw,3	%b[29], %r43, %b[39]
	  qpxor,4	%b[5], %b[41], %b[5]
	}
	{
	  qpaddw,0	%b[26], %b[31], %b[40]
	  qpsrcw,1	%b[44], 0xe, %b[44]
	  qpaddw,3	%b[21], %r34, %b[41]
	  qpsrcw,4	%b[42], 0xe, %b[42]
	}
	{
	  qpsrcw,0	%b[38], 0xe, %b[38]
	  qpxor,1	%b[27], %b[35], %b[27]
	  qpaddw,3	%b[5], %r40, %b[45]
	  qpsrcw,4	%b[39], %r22, %b[39]
	}
	{
	  qpsrcw,0	%b[40], %r22, %b[35]
	  qpxor,1	%b[37], %b[44], %b[37]
	  qpxor,3	%b[23], %b[42], %b[23]
	  qpsrcw,4	%b[41], %r22, %b[40]
	}
	{
	  qpaddw,0	%b[27], %r30, %b[38]
	  qpxor,1	%b[30], %b[38], %b[30]
	  qpaddw,3	%b[23], %r52, %b[42]
	  qpsrcw,4	%b[45], %r22, %b[41]
	}
	{
	  qpaddw,0	%b[37], %b[28], %b[44]
	  qpxor,1	%b[22], %b[35], %b[22]
	  qpxor,3	%b[10], %b[39], %b[10]
	  qpxor,4	%b[25], %b[40], %b[25]
	}
	{
	  qpaddw,0	%b[30], %b[32], %b[35]
	  qpsrcw,1	%b[38], %r23, %b[38]
	  qpaddw,3	%b[10], %b[29], %b[39]
	  qpxor,4	%b[24], %b[41], %b[24]
	}
	{
	  qpaddw,0	%b[22], %b[26], %b[40]
	  qpsrcw,1	%b[44], %r23, %b[44]
	  qpaddw,3	%b[25], %b[21], %b[41]
	  qpsrcw,4	%b[42], %r23, %b[42]
	}
	{
	  qpsrcw,0	%b[35], %r23, %b[35]
	  qpxor,1	%r37, %b[38], %r37
	  qpaddw,3	%b[24], %b[5], %b[45]
	  qpsrcw,4	%b[39], %r21, %b[39]
	}
	{
	  qpsrcw,0	%b[40], %r21, %b[38]
	  qpxor,1	%r51, %b[44], %r51
	  qpxor,3	%r33, %b[42], %r33
	  qpsrcw,4	%b[41], %r21, %b[40]
	}
	{
	  qpaddw,0	%r37, %b[27], %b[35]
	  qpxor,1	%r55, %b[35], %r55
	  qpaddw,3	%r33, %b[23], %b[42]
	  qpsrcw,4	%b[45], %r21, %b[41]
	}
	{
	  qpaddw,0	%r51, %b[37], %b[44]
	  qpxor,1	%b[1], %b[38], %b[1]
	  qpxor,3	%r62, %b[39], %r62
	  qpxor,4	%r48, %b[40], %r48
	}
	{
	  qpaddw,0	%r55, %b[30], %b[38]
	  qpsrcw,1	%b[35], %r22, %b[35]
	  qpaddw,3	%r62, %b[10], %b[39]
	  qpxor,4	%b[9], %b[41], %b[9]
	}
	{
	  qpaddw,0	%b[1], %b[22], %b[40]
	  qpsrcw,1	%b[44], %r22, %b[44]
	  qpaddw,3	%r48, %b[25], %b[41]
	  qpsrcw,4	%b[42], %r22, %b[42]
	}
	{
	  qpsrcw,0	%b[38], %r22, %b[38]
	  qpxor,1	%b[17], %b[35], %b[17]
	  qpaddw,3	%b[9], %b[24], %b[45]
	  qpsrcw,4	%b[39], 0xe, %b[39]
	}
	{
	  qpsrcw,0	%b[40], 0xe, %b[35]
	  qpxor,1	%b[18], %b[44], %b[18]
	  qpxor,3	%g28, %b[42], %g28
	  qpsrcw,4	%b[41], 0xe, %b[40]
	}
	{
	  qpaddw,0	%b[17], %r37, %b[38]
	  qpxor,1	%r11, %b[38], %r11
	  qpaddw,3	%g28, %r33, %b[42]
	  qpsrcw,4	%b[45], 0xe, %b[41]
	}
	{
	  qpaddw,0	%b[18], %r51, %b[44]
	  qpxor,1	%b[31], %b[35], %b[31]
	  qpxor,3	%r34, %b[40], %r34
	  qpxor,4	%r43, %b[39], %r43
	}
	{
	  qpaddw,0	%r11, %r55, %b[35]
	  qpsrcw,1	%b[38], %r21, %b[29]
	  qpaddw,3	%r56, %b[29], %r56
	  qpxor,4	%r40, %b[41], %r40
	}
	{
	  qpaddw,0	%r58, %b[26], %r53
	  qpsrcw,1	%b[44], %r21, %b[26]
	  qpaddw,3	%r53, %r43, %r43
	  qpsrcw,4	%b[42], %r21, %r58
	  stqp,5	%r1, _f16s,_lts0lo 0xb0, %r56
	}
	{
	  qpaddw,0	%r44, %b[21], %r44
	  qpsrcw,1	%b[35], %r21, %r41
	  stqp,2	%r1, _f16s,_lts0hi 0xc0, %r53
	  qpaddw,3	%r41, %r34, %r34
	  qpxor,4	%r57, %r56, %r57
	  stqp,5	%r1, _f16s,_lts0lo 0xa0, %r43
	}
	{
	  qpaddw,0	%r49, %b[5], %r49
	  qpxor,1	%r30, %b[29], %r30
	  stqp,2	0x10, %r1, %r44
	  qpaddw,3	%r60, %b[31], %r60
	  qpxor,4	%r54, %r43, %r54
	  stqp,5	%r1, 0x0, %r34
	}
	{
	  qpaddw,0	%r46, %r40, %r40
	  qpxor,1	%r59, %r53, %r46
	  stqp,2	%r1, _f16s,_lts0lo 0x60, %r49
	  qpxor,3	%r42, %r34, %r42
	  qpxor,4	%r52, %r58, %r52
	  stqp,5	%r1, _f16s,_lts0hi 0xf0, %r60
	}
	{
	  qpxor,0	%b[28], %b[26], %r58
	  qpxor,1	%r45, %r44, %r45
	  stqp,2	%r1, _f16s,_lts0lo 0x50, %r40
	  qpaddw,3	%b[3], %r62, %r61
	  qpxor,4	%r61, %r60, %r59
	}
	{
	  qpxor,0	%r50, %r49, %r50
	  qpxor,1	%r47, %r40, %r47
	  qpaddw,3	%b[0], %b[1], %r62
	  qpxor,4	%b[32], %r41, %r41
	  stqp,5	%r1, _f16s,_lts0lo 0x90, %r61
	}
	{
	  qpaddw,0	%b[8], %r48, %r48
	  qppermb,1	%r36, %g22, %r19, %g22
	  qpaddw,3	%b[6], %b[9], %b[0]
	  qpxor,4	%b[2], %r61, %b[1]
	  stqp,5	%r1, _f16s,_lts0lo 0xe0, %r62
	}
	{
	  qpaddw,0	%r30, %b[17], %r36
	  qpxor,1	%b[7], %r48, %b[3]
	  stqp,2	%r1, _f16s,_lts0lo 0x30, %r48
	  qpaddw,3	%r52, %g28, %b[2]
	  qpxor,4	%r63, %r62, %r63
	  stqp,5	%r1, _f16s,_lts0hi 0x40, %b[0]
	}
	{
	  qpaddw,0	%r58, %b[18], %b[5]
	  qpsrcw,1	%r36, 0xe, %r36
	  qpaddw,3	%r59, %r57, %b[6]
	  qpxor,4	%b[4], %b[0], %b[4]
	}
	{
	  qpaddw,0	%r47, %r45, %b[7]
	  qpsrcw,1	%b[5], 0xe, %b[5]
	  qpaddw,3	%r41, %r11, %b[8]
	  qpsrcw,4	%b[2], 0xe, %b[2]
	}
	{
	  qpaddw,0	%r54, %r50, %b[9]
	  qpsrcw,1	%b[7], %r23, %b[7]
	  qpaddw,3	%r42, %r46, %b[21]
	  qpsrcw,4	%b[6], %r23, %b[6]
	}
	{
	  qpsrcw,0	%b[9], %r23, %b[9]
	  qpxor,1	%b[27], %r36, %r36
	  qpsrcw,3	%b[8], 0xe, %b[8]
	  qpsrcw,4	%b[21], %r23, %b[21]
	}
	{
	  qpxor,0	%b[37], %b[5], %b[5]
	  qpxor,1	%b[1], %b[7], %b[7]
	  qpxor,3	%b[23], %b[2], %b[2]
	  qpxor,4	%b[3], %b[6], %b[6]
	}
	{
	  qpaddw,0	%b[12], %b[22], %b[12]
	  qpxor,1	%r63, %b[9], %b[9]
	  qpxor,3	%b[4], %b[21], %b[21]
	  qpxor,4	%b[30], %b[8], %b[8]
	}
	{
	  qpaddw,0	%b[16], %b[24], %b[16]
	  qpxor,1	%b[11], %b[12], %b[11]
	  stqp,2	%r1, _f16s,_lts0lo 0xd0, %b[12]
	  qpaddw,3	%b[14], %b[10], %b[10]
	  qppermb,4	%g20, %r15, %r19, %g20
	}
	{
	  qpaddw,0	%b[20], %b[25], %r15
	  qpxor,1	%b[15], %b[16], %b[15]
	  stqp,2	%r1, _f16s,_lts0lo 0x70, %b[16]
	  qpaddw,3	%r36, %r51, %b[14]
	  qpxor,4	%b[13], %b[10], %b[13]
	  stqp,5	%r1, _f16s,_lts0hi 0x80, %b[10]
	}
	{
	  qpaddw,0	%b[2], %r55, %b[20]
	  qpxor,1	%b[19], %r15, %b[19]
	  stqp,2	%r1, _f16s,_lts0lo 0x20, %r15
	  qpaddw,3	%b[5], %r33, %b[22]
	  qpsrcw,4	%b[14], %r23, %b[14]
	}
	{
	  qpaddw,0	%b[6], %r59, %b[23]
	  qpsrcw,1	%b[20], %r23, %b[20]
	  qpaddw,3	%b[7], %r47, %b[24]
	  qpsrcw,4	%b[22], %r23, %b[22]
	}
	{
	  qpaddw,0	%b[8], %r37, %b[25]
	  qpsrcw,1	%b[23], %r22, %b[23]
	  qpaddw,3	%b[9], %r54, %b[26]
	  qpsrcw,4	%b[24], %r22, %b[24]
	}
	{
	  qpaddw,0	%b[21], %r42, %b[27]
	  qpsrcw,1	%b[25], %r23, %b[25]
	  qpsrcw,3	%b[26], %r22, %b[26]
	  qpxor,4	%r41, %b[14], %r41
	}
	{
	  qpsrcw,0	%b[27], %r22, %b[14]
	  qpxor,1	%r58, %b[20], %r58
	  qpxor,3	%b[11], %b[24], %b[20]
	  qpxor,4	%r30, %b[22], %r30
	}
	{
	  qpxor,0	%r52, %b[25], %r52
	  qpxor,1	%b[15], %b[23], %b[22]
	  qpaddw,3	%r41, %r36, %b[24]
	  qpxor,4	%b[19], %b[26], %b[23]
	}
	{
	  qpaddw,0	%r58, %b[2], %b[25]
	  qpxor,1	%b[13], %b[14], %b[14]
	  qpaddw,3	%r30, %b[5], %b[26]
	  qpsrcw,4	%b[24], %r22, %b[24]
	}
	{
	  qpaddw,0	%b[22], %b[6], %b[28]
	  qpsrcw,1	%b[25], %r22, %b[25]
	  qpaddw,3	%b[20], %b[7], %b[27]
	  qpsrcw,4	%b[26], %r22, %b[26]
	}
	{
	  qpaddw,0	%r52, %b[8], %b[29]
	  qpsrcw,1	%b[28], %r21, %b[28]
	  qpaddw,3	%b[23], %b[9], %b[30]
	  qpsrcw,4	%b[27], %r21, %b[27]
	}
	{
	  qpaddw,0	%b[14], %b[21], %b[31]
	  qpsrcw,1	%b[29], %r22, %b[29]
	  qpsrcw,3	%b[30], %r21, %b[30]
	  qpxor,4	%g28, %b[24], %g28
	}
	{
	  qpsrcw,0	%b[31], %r21, %b[24]
	  qpxor,1	%b[17], %b[25], %b[17]
	  qpxor,3	%r45, %b[27], %b[25]
	  qpxor,4	%r11, %b[26], %r11
	}
	{
	  qpxor,0	%b[18], %b[29], %b[18]
	  qpxor,1	%r57, %b[28], %b[26]
	  qpaddw,3	%g28, %r41, %b[28]
	  qpxor,4	%r50, %b[30], %b[27]
	}
	{
	  qpaddw,0	%b[17], %r58, %b[29]
	  qpxor,1	%r46, %b[24], %b[24]
	  qpaddw,3	%r11, %r30, %b[30]
	  qpsrcw,4	%b[28], %r21, %b[28]
	}
	{
	  qpaddw,0	%b[26], %b[22], %b[32]
	  qpsrcw,1	%b[29], %r21, %b[29]
	  qpaddw,3	%b[25], %b[20], %b[31]
	  qpsrcw,4	%b[30], %r21, %b[30]
	}
	{
	  qpaddw,0	%b[18], %r52, %b[35]
	  qpsrcw,1	%b[32], 0xe, %b[32]
	  qpaddw,3	%b[27], %b[23], %b[37]
	  qpsrcw,4	%b[31], 0xe, %b[31]
	}
	{
	  qpaddw,0	%b[24], %b[14], %b[38]
	  qpsrcw,1	%b[35], %r21, %b[35]
	  qpsrcw,3	%b[37], 0xe, %b[37]
	  qpxor,4	%r51, %b[28], %r51
	}
	{
	  qpsrcw,0	%b[38], 0xe, %b[28]
	  qpxor,1	%r55, %b[29], %r55
	  qpxor,3	%r47, %b[31], %b[29]
	  qpxor,4	%r33, %b[30], %r33
	}
	{
	  qpxor,0	%r37, %b[35], %r37
	  qpxor,1	%r59, %b[32], %b[30]
	  qpaddw,3	%r51, %g28, %b[32]
	  qpxor,4	%r54, %b[37], %b[31]
	}
	{
	  qpaddw,0	%r55, %b[17], %b[35]
	  qpxor,1	%r42, %b[28], %b[28]
	  qpaddw,3	%r33, %r11, %b[37]
	  qpsrcw,4	%b[32], 0xe, %b[32]
	}
	{
	  qpaddw,0	%b[30], %b[9], %b[39]
	  qpsrcw,1	%b[35], 0xe, %b[35]
	  qpaddw,3	%b[29], %b[21], %b[38]
	  qpsrcw,4	%b[37], 0xe, %b[37]
	}
	{
	  qpaddw,0	%r37, %b[18], %b[40]
	  qpsrcw,1	%b[39], %r23, %b[39]
	  qpaddw,3	%b[31], %b[7], %b[41]
	  qpsrcw,4	%b[38], %r23, %b[38]
	}
	{
	  qpaddw,0	%b[28], %b[6], %b[42]
	  qpsrcw,1	%b[40], 0xe, %b[40]
	  qpsrcw,3	%b[41], %r23, %b[41]
	  qpxor,4	%r36, %b[32], %r36
	}
	{
	  qpsrcw,0	%b[42], %r23, %b[32]
	  qpxor,1	%b[2], %b[35], %b[2]
	  qpxor,3	%b[27], %b[38], %b[27]
	  qpxor,4	%b[5], %b[37], %b[5]
	}
	{
	  qpxor,0	%b[8], %b[40], %b[8]
	  qpxor,1	%b[24], %b[39], %b[24]
	  qpaddw,3	%r36, %r30, %b[35]
	  qpxor,4	%b[26], %b[41], %b[26]
	}
	{
	  qpaddw,0	%b[2], %r52, %b[32]
	  qpxor,1	%b[25], %b[32], %b[25]
	  qpaddw,3	%b[5], %r58, %b[37]
	  qpsrcw,4	%b[35], %r23, %b[35]
	}
	{
	  qpaddw,0	%b[24], %b[30], %b[39]
	  qpsrcw,1	%b[32], %r23, %b[32]
	  qpaddw,3	%b[27], %b[29], %b[38]
	  qpsrcw,4	%b[37], %r23, %b[37]
	}
	{
	  qpaddw,0	%b[8], %r41, %b[40]
	  qpsrcw,1	%b[39], %r22, %b[39]
	  qpaddw,3	%b[26], %b[31], %b[41]
	  qpsrcw,4	%b[38], %r22, %b[38]
	}
	{
	  qpaddw,0	%b[25], %b[28], %b[42]
	  qpsrcw,1	%b[40], %r23, %b[40]
	  qpsrcw,3	%b[41], %r22, %b[41]
	  qpxor,4	%r37, %b[35], %r37
	}
	{
	  qpsrcw,0	%b[42], %r22, %b[35]
	  qpxor,1	%r33, %b[32], %r33
	  qpxor,3	%b[22], %b[38], %b[22]
	  qpxor,4	%r51, %b[37], %r51
	}
	{
	  qpxor,0	%r55, %b[40], %r55
	  qpxor,1	%b[20], %b[39], %b[20]
	  qpaddw,3	%r37, %r36, %b[32]
	  qpxor,4	%b[14], %b[41], %b[14]
	}
	{
	  qpaddw,0	%r33, %b[2], %b[35]
	  qpxor,1	%b[23], %b[35], %b[23]
	  qpaddw,3	%r51, %b[5], %b[37]
	  qpsrcw,4	%b[32], %r22, %b[32]
	}
	{
	  qpaddw,0	%b[20], %b[24], %b[39]
	  qpsrcw,1	%b[35], %r22, %b[35]
	  qpaddw,3	%b[22], %b[27], %b[38]
	  qpsrcw,4	%b[37], %r22, %b[37]
	}
	{
	  qpaddw,0	%r55, %b[8], %b[40]
	  qpsrcw,1	%b[39], %r21, %b[39]
	  qpaddw,3	%b[14], %b[26], %b[41]
	  qpsrcw,4	%b[38], %r21, %b[38]
	}
	{
	  qpaddw,0	%b[23], %b[25], %b[42]
	  qpsrcw,1	%b[40], %r22, %b[40]
	  qpsrcw,3	%b[41], %r21, %b[41]
	  qpxor,4	%b[17], %b[32], %b[17]
	}
	{
	  qpsrcw,0	%b[42], %r21, %b[32]
	  qpxor,1	%g28, %b[35], %g28
	  qpxor,3	%b[21], %b[38], %b[21]
	  qpxor,4	%b[18], %b[37], %b[18]
	}
	{
	  qpxor,0	%r11, %b[40], %r11
	  qpxor,1	%b[9], %b[39], %b[9]
	  qpaddw,3	%b[17], %r37, %b[35]
	  qpxor,4	%b[7], %b[41], %b[7]
	}
	{
	  qpaddw,0	%g28, %r33, %b[32]
	  qpxor,1	%b[6], %b[32], %b[6]
	  qpaddw,3	%b[18], %r51, %b[37]
	  qpsrcw,4	%b[35], %r21, %b[35]
	}
	{
	  qpaddw,0	%b[9], %b[20], %b[39]
	  qpsrcw,1	%b[32], %r21, %b[32]
	  qpaddw,3	%b[21], %b[22], %b[38]
	  qpsrcw,4	%b[37], %r21, %b[37]
	}
	{
	  qpaddw,0	%r11, %r55, %b[40]
	  qpsrcw,1	%b[39], 0xe, %b[39]
	  qpaddw,3	%b[7], %b[14], %b[41]
	  qpsrcw,4	%b[38], 0xe, %b[38]
	}
	{
	  qpaddw,0	%b[6], %b[23], %b[42]
	  qpsrcw,1	%b[40], %r21, %b[40]
	  qpsrcw,3	%b[41], 0xe, %b[41]
	  qpxor,4	%r30, %b[35], %r30
	}
	{
	  qpsrcw,0	%b[42], 0xe, %b[35]
	  qpxor,1	%r52, %b[32], %r52
	  qpxor,3	%b[29], %b[38], %b[29]
	  qpxor,4	%r58, %b[37], %r58
	}
	{
	  qpxor,0	%r41, %b[40], %r41
	  qpxor,1	%b[30], %b[39], %b[30]
	  qpaddw,3	%r30, %b[17], %b[32]
	  qpxor,4	%b[31], %b[41], %b[31]
	}
	{
	  qpaddw,0	%r52, %g28, %b[35]
	  qpxor,1	%b[28], %b[35], %b[28]
	  qpaddw,3	%r58, %b[18], %b[37]
	  qpsrcw,4	%b[32], 0xe, %b[32]
	}
	{
	  qpaddw,0	%b[30], %b[26], %b[39]
	  qpsrcw,1	%b[35], 0xe, %b[35]
	  qpaddw,3	%b[29], %b[25], %b[38]
	  qpsrcw,4	%b[37], 0xe, %b[37]
	}
	{
	  qpaddw,0	%r41, %r11, %b[40]
	  qpsrcw,1	%b[39], %r23, %b[39]
	  qpaddw,3	%b[31], %b[27], %b[41]
	  qpsrcw,4	%b[38], %r23, %b[38]
	}
	{
	  qpaddw,0	%b[28], %b[24], %b[42]
	  qpsrcw,1	%b[40], 0xe, %b[40]
	  qpsrcw,3	%b[41], %r23, %b[41]
	  qpxor,4	%r36, %b[32], %r36
	}
	{
	  qpsrcw,0	%b[42], %r23, %b[32]
	  qpxor,1	%b[2], %b[35], %b[2]
	  qpxor,3	%b[7], %b[38], %b[7]
	  qpxor,4	%b[5], %b[37], %b[5]
	}
	{
	  qpxor,0	%b[8], %b[40], %b[8]
	  qpxor,1	%b[6], %b[39], %b[6]
	  qpaddw,3	%r36, %r51, %b[35]
	  qpxor,4	%b[9], %b[41], %b[9]
	}
	{
	  qpaddw,0	%b[2], %r55, %b[32]
	  qpxor,1	%b[21], %b[32], %b[21]
	  qpaddw,3	%b[5], %r33, %b[37]
	  qpsrcw,4	%b[35], %r23, %b[35]
	}
	{
	  qpaddw,0	%b[6], %b[30], %b[39]
	  qpsrcw,1	%b[32], %r23, %b[32]
	  qpaddw,3	%b[7], %b[29], %b[38]
	  qpsrcw,4	%b[37], %r23, %b[37]
	}
	{
	  qpaddw,0	%b[8], %r37, %b[40]
	  qpsrcw,1	%b[39], %r22, %b[39]
	  qpaddw,3	%b[9], %b[31], %b[41]
	  qpsrcw,4	%b[38], %r22, %b[38]
	}
	{
	  qpaddw,0	%b[21], %b[28], %b[42]
	  qpsrcw,1	%b[40], %r23, %b[40]
	  qpsrcw,3	%b[41], %r22, %b[41]
	  qpxor,4	%r41, %b[35], %r41
	}
	{
	  qpsrcw,0	%b[42], %r22, %b[35]
	  qpxor,1	%r58, %b[32], %r58
	  qpxor,3	%b[20], %b[38], %b[20]
	  qpxor,4	%r30, %b[37], %r30
	}
	{
	  qpxor,0	%r52, %b[40], %r52
	  qpxor,1	%b[22], %b[39], %b[22]
	  qpaddw,3	%r41, %r36, %b[32]
	  qpxor,4	%b[23], %b[41], %b[23]
	}
	{
	  qpaddw,0	%r58, %b[2], %b[35]
	  qpxor,1	%b[14], %b[35], %b[14]
	  qpaddw,3	%r30, %b[5], %b[37]
	  qpsrcw,4	%b[32], %r22, %b[32]
	}
	{
	  qpaddw,0	%b[22], %b[6], %b[39]
	  qpsrcw,1	%b[35], %r22, %b[35]
	  qpaddw,3	%b[20], %b[7], %b[38]
	  qpsrcw,4	%b[37], %r22, %b[37]
	}
	{
	  qpaddw,0	%r52, %b[8], %b[40]
	  qpsrcw,1	%b[39], %r21, %b[39]
	  qpaddw,3	%b[23], %b[9], %b[41]
	  qpsrcw,4	%b[38], %r21, %b[38]
	}
	{
	  qpaddw,0	%b[14], %b[21], %b[42]
	  qpsrcw,1	%b[40], %r22, %b[40]
	  qpsrcw,3	%b[41], %r21, %b[41]
	  qpxor,4	%g28, %b[32], %g28
	}
	{
	  qpsrcw,0	%b[42], %r21, %b[32]
	  qpxor,1	%b[17], %b[35], %b[17]
	  qpxor,3	%b[25], %b[38], %b[25]
	  qpxor,4	%r11, %b[37], %r11
	}
	{
	  qpxor,0	%b[18], %b[40], %b[18]
	  qpxor,1	%b[26], %b[39], %b[26]
	  qpaddw,3	%g28, %r41, %b[35]
	  qpxor,4	%b[27], %b[41], %b[27]
	}
	{
	  qpaddw,0	%b[17], %r58, %b[32]
	  qpxor,1	%b[24], %b[32], %b[24]
	  qpaddw,3	%r11, %r30, %b[37]
	  qpsrcw,4	%b[35], %r21, %b[35]
	}
	{
	  qpaddw,0	%b[26], %b[22], %b[39]
	  qpsrcw,1	%b[32], %r21, %b[32]
	  qpaddw,3	%b[25], %b[20], %b[38]
	  qpsrcw,4	%b[37], %r21, %b[37]
	}
	{
	  qpaddw,0	%b[18], %r52, %b[40]
	  qpsrcw,1	%b[39], 0xe, %b[39]
	  qpaddw,3	%b[27], %b[23], %b[41]
	  qpsrcw,4	%b[38], 0xe, %b[38]
	}
	{
	  qpaddw,0	%b[24], %b[14], %b[42]
	  qpsrcw,1	%b[40], %r21, %b[40]
	  qpsrcw,3	%b[41], 0xe, %b[41]
	  qpxor,4	%r51, %b[35], %r51
	}
	{
	  qpsrcw,0	%b[42], 0xe, %b[35]
	  qpxor,1	%r55, %b[32], %r55
	  qpxor,3	%b[29], %b[38], %b[29]
	  qpxor,4	%r33, %b[37], %r33
	}
	{
	  qpxor,0	%r37, %b[40], %r37
	  qpxor,1	%b[30], %b[39], %b[30]
	  qpaddw,3	%r51, %g28, %b[32]
	  qpxor,4	%b[31], %b[41], %b[31]
	}
	{
	  qpaddw,0	%r55, %b[17], %b[35]
	  qpxor,1	%b[28], %b[35], %b[28]
	  qpaddw,3	%r33, %r11, %b[37]
	  qpsrcw,4	%b[32], 0xe, %b[32]
	}
	{
	  qpaddw,0	%b[30], %b[9], %b[39]
	  qpsrcw,1	%b[35], 0xe, %b[35]
	  qpaddw,3	%b[29], %b[21], %b[38]
	  qpsrcw,4	%b[37], 0xe, %b[37]
	}
	{
	  qpaddw,0	%r37, %b[18], %b[40]
	  qpsrcw,1	%b[39], %r23, %b[39]
	  qpaddw,3	%b[31], %b[7], %b[41]
	  qpsrcw,4	%b[38], %r23, %b[38]
	}
	{
	  qpaddw,0	%b[28], %b[6], %b[42]
	  qpsrcw,1	%b[40], 0xe, %b[40]
	  qpsrcw,3	%b[41], %r23, %b[41]
	  qpxor,4	%r36, %b[32], %r36
	}
	{
	  qpsrcw,0	%b[42], %r23, %b[32]
	  qpxor,1	%b[2], %b[35], %b[2]
	  qpxor,3	%b[27], %b[38], %b[27]
	  qpxor,4	%b[5], %b[37], %b[5]
	}
	{
	  qpxor,0	%b[8], %b[40], %b[8]
	  qpxor,1	%b[24], %b[39], %b[24]
	  qpaddw,3	%g23, %r41, %g23
	  qpxor,4	%b[26], %b[41], %b[26]
	}
	{
	  qpaddw,0	%r35, %g28, %g28
	  qpxor,1	%b[25], %b[32], %r41
	  qpaddw,3	%g30, %r58, %g30
	  qppermb,4	%r17, %r39, %r18, %r35
	  stqp,5	%r1, _f16s,_lts0lo 0x360, %g23
	}
	{
	  qpaddw,0	%r29, %b[17], %r29
	  qppermb,1	%g18, %g16, %r18, %r30
	  stqp,2	%r1, _f16s,_lts0lo 0x370, %g28
	  qpaddw,3	%g19, %r30, %g19
	  qppermb,4	%r17, %r39, %r19, %r17
	  stqp,5	%r1, _f16s,_lts0hi 0x3c0, %g30
	}
	{
	  qpaddw,0	%g17, %b[5], %g17
	  qppermb,1	%g18, %g16, %r19, %g16
	  stqp,2	%r1, _f16s,_lts0lo 0x3d0, %r29
	  qpaddw,3	%g27, %r52, %g27
	  qppermb,4	%r13, %r32, %r18, %g18
	  stqp,5	%r1, _f16s,_lts0hi 0x310, %g19
	}
	{
	  qpaddw,0	%g25, %b[8], %g25
	  qppermb,1	%g26, %g24, %r18, %r38
	  stqp,2	%r1, _f16s,_lts0lo 0x300, %g17
	  qpaddw,3	%r38, %r11, %r11
	  qppermb,4	%r13, %r32, %r19, %r13
	  stqp,5	%r1, _f16s,_lts0hi 0x3b0, %g27
	}
	{
	  qpaddw,0	%r16, %r33, %r16
	  qppermb,1	%g26, %g24, %r19, %g24
	  stqp,2	%r1, _f16s,_lts0lo 0x3a0, %g25
	  qpaddw,3	%r31, %b[18], %r31
	  qppermb,4	%g28, %g23, %r18, %g26
	  stqp,5	%r1, _f16s,_lts0hi 0x320, %r11
	}
	{
	  qpaddw,0	%r12, %r37, %r12
	  qppermb,1	%r29, %g30, %r18, %g28
	  stqp,2	%r1, _f16s,_lts0lo 0x330, %r16
	  qpaddw,3	%r14, %r51, %r14
	  qppermb,4	%g28, %g23, %r19, %g23
	  stqp,5	%r1, _f16s,_lts0hi 0x380, %r31
	}
	{
	  qpaddw,0	%g21, %r36, %g21
	  qppermb,1	%g19, %g17, %r18, %r29
	  stqp,2	%r1, _f16s,_lts0lo 0x390, %r12
	  qpaddw,3	%r10, %r55, %r10
	  qppermb,4	%r29, %g30, %r19, %g30
	  stqp,5	%r1, _f16s,_lts0hi 0x340, %r14
	}
	{
	  qpaddw,0	%r4, %b[2], %r4
	  qppermb,1	%g19, %g17, %r19, %g17
	  stqp,2	%r1, _f16s,_lts0lo 0x350, %g21
	  qpaddw,3	%b[27], %b[29], %r32
	  qppermb,4	%g27, %g25, %r18, %g19
	  stqp,5	%r1, _f16s,_lts0hi 0x3e0, %r10
	}
	{
	  qpaddw,0	%b[24], %b[30], %r33
	  qppermb,1	%r16, %r11, %r19, %r37
	  stqp,2	%r1, _f16s,_lts0lo 0x3f0, %r4
	  qpaddw,3	%b[26], %b[31], %r36
	  qppermb,4	%g27, %g25, %r19, %g25
	}
	{
	  qpaddw,0	%r41, %b[28], %g27
	  qppermb,1	%r12, %r31, %r19, %r39
	  qppermb,3	%r16, %r11, %r18, %r11
	  qppermb,4	%r12, %r31, %r18, %r12
	}
	{
	  qppermb,0	%g21, %r14, %r18, %r31
	  qppermb,1	%g21, %r14, %r19, %g21
	  qpsrcw,3	%r32, %r22, %r16
	  qpsrcw,4	%r36, %r22, %r14
	}
	{
	  qpsrcw,0	%r33, %r22, %r32
	  qppermb,1	%r4, %r10, %r18, %r33
	  qppermb,3	%r4, %r10, %r19, %r4
	  qppermb,4	%b[36], %b[33], %r18, %r10
	}
	{
	  qpsrcw,0	%g27, %r22, %g27
	  qppermb,1	%b[36], %b[33], %r19, %r36
	  qppermb,3	%g31, %g29, %r18, %r51
	  qppermb,4	%g31, %g29, %r19, %g29
	  stqp,5	%r0, _f16s,_lts0lo 0x3b0, %r10
	}
	{
	  qppermb,0	%b[34], %b[43], %r18, %g31
	  qppermb,1	%b[34], %b[43], %r19, %r10
	  stqp,2	%r0, _f16s,_lts0lo 0x2b0, %r36
	  qppermb,3	%g22, %g20, %r18, %r52
	  qppermb,4	%g22, %g20, %r19, %g20
	  stqp,5	%r0, _f16s,_lts0hi 0x330, %r51
	}
	{
	  qppermb,0	%r35, %r30, %r18, %g22
	  qppermb,1	%r35, %r30, %r19, %r30
	  stqp,2	%r0, _f16s,_lts0hi 0x390, %g31
	  qppermb,3	%r17, %g16, %r18, %r35
	  qppermb,4	%r17, %g16, %r19, %g16
	  stqp,5	%r0, _f16s,_lts0lo 0x230, %g29
	}
	{
	  qppermb,0	%r38, %g18, %r18, %g29
	  qppermb,1	%r38, %g18, %r19, %g18
	  stqp,2	%r0, _f16s,_lts0lo 0x290, %r10
	  qppermb,3	%g24, %r13, %r18, %g31
	  qppermb,4	%g24, %r13, %r19, %g24
	  stqp,5	%r0, _f16s,_lts0hi 0x310, %r52
	}
	{
	  qppermb,0	%r37, %g17, %r18, %r10
	  qppermb,1	%r37, %g17, %r19, %g17
	  stqp,2	%r0, _f16s,_lts0lo 0x210, %g20
	  qppermb,3	%r11, %r29, %r18, %r13
	  qppermb,4	%r11, %r29, %r19, %r11
	  stqp,5	%r0, _f16s,_lts0hi 0x300, %r35
	}
	{
	  qppermb,0	%g19, %r12, %r18, %g20
	  qppermb,1	%g19, %r12, %r19, %g19
	  stqp,2	%r0, _f16s,_lts0lo 0x380, %g22
	  qpxor,3	%b[22], %r16, %r12
	  qppermb,4	%g26, %r31, %r18, %r16
	  stqp,5	%r0, _f16s,_lts0hi 0x280, %r30
	}
	{
	  qppermb,0	%g26, %r31, %r19, %g22
	  qppermb,1	%g23, %g21, %r18, %g26
	  stqp,2	%r0, _f16s,_lts0lo 0x200, %g16
	  qppermb,3	%g23, %g21, %r19, %g21
	  qpxor,4	%b[14], %r14, %g23
	  stqp,5	%r0, _f16s,_lts0hi 0x3a0, %g29
	}
	{
	  qppermb,0	%g25, %r39, %r18, %g16
	  qppermb,1	%g25, %r39, %r19, %g25
	  stqp,2	%r0, _f16s,_lts0lo 0x2a0, %g18
	  qpxor,3	%b[20], %r32, %g29
	  qppermb,4	%r33, %g28, %r18, %r14
	  stqp,5	%r0, _f16s,_lts0hi 0x320, %g31
	}
	{
	  qppermb,0	%r33, %g28, %r19, %g18
	  qppermb,1	%r4, %g30, %r18, %g28
	  stqp,2	%r0, _f16s,_lts0lo 0x220, %g24
	  qppermb,3	%r4, %g30, %r19, %g30
	  qpxor,4	%b[23], %g27, %g27
	  stqp,5	%r0, _f16s,_lts0hi 0x340, %r10
	}
	{
	  qpaddw,0	%r12, %b[27], %g17
	  qppermb,1	%r56, %r43, %r18, %g31
	  stqp,2	%r0, _f16s,_lts0lo 0x240, %g17
	  qpaddw,3	%g23, %b[26], %g24
	  qppermb,4	%r61, %b[10], %r18, %r4
	  stqp,5	%r0, _f16s,_lts0hi 0x3c0, %r13
	}
	{
	  qpsrcw,0	%g17, %r21, %g17
	  qppermb,1	%r56, %r43, %r19, %r10
	  stqp,2	%r0, _f16s,_lts0lo 0x2c0, %r11
	  qpaddw,3	%g29, %b[24], %g20
	  qpsrcw,4	%g24, %r21, %g24
	  stqp,5	%r0, _f16s,_lts0hi 0x3e0, %g20
	}
	{
	  qpxor,0	%b[21], %g17, %g17
	  qppermb,1	%r61, %b[10], %r19, %r11
	  stqp,2	%r0, _f16s,_lts0lo 0x2e0, %g19
	  qpaddw,3	%g27, %r41, %g19
	  qpsrcw,4	%g20, %r21, %g20
	  stqp,5	%r0, _f16s,_lts0hi 0x3d0, %r16
	}
	{
	  qpaddw,0	%g17, %r12, %g24
	  qppermb,1	%r44, %r34, %r18, %g26
	  stqp,2	%r0, _f16s,_lts0lo 0x2d0, %g22
	  qpxor,3	%b[7], %g24, %g22
	  qpsrcw,4	%g19, %r21, %g19
	  stqp,5	%r0, _f16s,_lts0hi 0x350, %g26
	}
	{
	  qpsrcw,0	%g24, 0xe, %g20
	  qppermb,1	%r48, %r15, %r18, %g21
	  stqp,2	%r0, _f16s,_lts0lo 0x250, %g21
	  qpxor,3	%b[6], %g19, %g19
	  qpxor,4	%b[9], %g20, %g16
	  stqp,5	%r0, _f16s,_lts0hi 0x360, %g16
	}
	{
	  qpxor,0	%b[29], %g20, %g20
	  qppermb,1	%r44, %r34, %r19, %g25
	  stqp,2	%r0, _f16s,_lts0lo 0x260, %g25
	  qpaddw,3	%g22, %g23, %g24
	  qppermb,4	%r48, %r15, %r19, %r13
	  stqp,5	%r0, _f16s,_lts0hi 0x3f0, %r14
	}
	{
	  qpaddw,0	%g20, %r41, %g28
	  qppermb,1	%r60, %r62, %r18, %r14
	  stqp,2	%r0, _f16s,_lts0lo 0x2f0, %g18
	  qpaddw,3	%g16, %g29, %g18
	  qpsrcw,4	%g24, 0xe, %g24
	  stqp,5	%r0, _f16s,_lts0hi 0x370, %g28
	}
	{
	  qpsrcw,0	%g28, %r23, %g28
	  qppermb,1	%b[12], %r53, %r18, %r15
	  stqp,2	%r0, _f16s,_lts0lo 0x270, %g30
	  qpaddw,3	%g19, %g27, %g30
	  qpsrcw,4	%g18, 0xe, %g18
	}
	{
	  qpxor,0	%g22, %g28, %g22
	  qppermb,1	%r60, %r62, %r19, %g28
	  qpsrcw,3	%g30, 0xe, %g30
	  qpxor,4	%b[31], %g24, %g24
	}
	{
	  qpaddw,0	%g22, %g20, %r16
	  qppermb,1	%b[12], %r53, %r19, %r17
	  qpxor,3	%b[28], %g30, %g30
	  qpxor,4	%b[30], %g18, %g18
	}
	{
	  qpsrcw,0	%r16, %r22, %r16
	  qppermb,1	%r40, %b[0], %r18, %r30
	  qpaddw,3	%g24, %b[27], %r29
	  qppermb,4	%b[16], %r49, %r18, %r31
	}
	{
	  qpxor,0	%g29, %r16, %g29
	  qppermb,1	%r40, %b[0], %r19, %r16
	  qpaddw,3	%g18, %b[26], %r32
	  qpsrcw,4	%r29, %r23, %r29
	}
	{
	  qpaddw,0	%g29, %g22, %r34
	  qppermb,1	%b[16], %r49, %r19, %r35
	  qpaddw,3	%g30, %b[24], %r33
	  qpsrcw,4	%r32, %r23, %r32
	}
	{
	  qpsrcw,0	%r34, %r21, %r29
	  qppermb,1	%r10, %r11, %r18, %r34
	  qpsrcw,3	%r33, %r23, %r33
	  qpxor,4	%g16, %r29, %g16
	}
	{
	  qpxor,0	%r41, %r29, %r29
	  qppermb,1	%r10, %r11, %r19, %r10
	  stqp,2	%r0, _f16s,_lts0lo 0x120, %r34
	  qpxor,3	%g17, %r33, %g17
	  qpxor,4	%g19, %r32, %g19
	}
	{
	  qpaddw,0	%r29, %g29, %r32
	  qppermb,1	%g31, %r4, %r18, %r33
	  stqp,2	%r0, _f16s,_lts0lo 0x20, %r10
	  qpaddw,3	%g16, %g24, %r11
	  qppermb,4	%g31, %r4, %r19, %g31
	}
	{
	  qpsrcw,0	%r32, 0xe, %r11
	  qppermb,1	%g21, %g26, %r18, %r32
	  stqp,2	%r0, _f16s,_lts0lo 0x1a0, %r33
	  qpaddw,3	%g19, %g18, %r4
	  qpsrcw,4	%r11, %r22, %r10
	  stqp,5	%r0, _f16s,_lts0hi 0xa0, %g31
	}
	{
	  qpxor,0	%g20, %r11, %g20
	  qppermb,1	%g21, %g26, %r19, %g21
	  stqp,2	%r0, _f16s,_lts0lo 0x180, %r32
	  qpaddw,3	%g17, %g30, %g31
	  qpsrcw,4	%r4, %r22, %r4
	}
	{
	  qpaddw,0	%g20, %g17, %g31
	  qppermb,1	%r14, %r15, %r18, %r10
	  stqp,2	%r0, _f16s,_lts0lo 0x80, %g21
	  qpxor,3	%g27, %r10, %g27
	  qpsrcw,4	%g31, %r22, %g26
	}
	{
	  qpsrcw,0	%g31, %r23, %g26
	  qppermb,1	%r14, %r15, %r19, %g31
	  stqp,2	%r0, _f16s,_lts0lo 0x1b0, %r10
	  qpxor,3	%g23, %g26, %g23
	  qpxor,4	%r12, %r4, %g21
	}
	{
	  qppermb,0	%r13, %g25, %r18, %r10
	  qppermb,1	%r13, %g25, %r19, %g25
	  stqp,2	%r0, _f16s,_lts0lo 0xb0, %g31
	  qpaddw,3	%g27, %g16, %r4
	  qppermb,4	%g28, %r17, %r18, %r11
	}
	{
	  qppermb,0	%g28, %r17, %r19, %g28
	  qppermb,1	%r35, %r16, %r18, %r12
	  stqp,2	%r0, _f16s,_lts0lo 0x100, %r10
	  qpaddw,3	%g21, %g19, %g31
	  qpsrcw,4	%r4, %r21, %r4
	  stqp,5	%r0, _f16s,_lts0hi 0x130, %r11
	}
	{
	  qppermb,0	%r35, %r16, %r19, %r11
	  qppermb,1	%r31, %r30, %r18, %r13
	  stqp,2	%r0, 0x0, %g25
	  qpaddw,3	%g23, %g17, %r10
	  qpsrcw,4	%g31, %r21, %g31
	}
	{
	  qppermb,0	%r31, %r30, %r19, %r10
	  stqp,2	%r0, _f16s,_lts0lo 0x30, %g28
	  qpsrcw,3	%r10, %r21, %g25
	  qpxor,4	%b[27], %r4, %r4
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x110, %r12
	  qpxor,3	%b[24], %g25, %g25
	  qpxor,4	%b[26], %g31, %g28
	}
	{
	  stqp,2	0x10, %r0, %r11
	  qpaddw,3	%r4, %g27, %g31
	  qpxor,4	%r4, %g26, %g26
	  stqp,5	%r0, _f16s,_lts0lo 0x190, %r13
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x90, %r10
	  qpaddw,3	%g28, %g21, %r4
	  qpsrcw,4	%g31, 0xe, %g31
	}
	{
	  qpaddw,3	%g25, %g23, %r10
	  qpsrcw,4	%r4, 0xe, %r4
	}
	{
	  qpxor,3	%g24, %g31, %g24
	  qpsrcw,4	%r10, 0xe, %r10
	}
	{
	  qpaddw,0	%g26, %g20, %g31
	  qpxor,3	%g30, %r10, %g30
	  qpxor,4	%g18, %r4, %g18
	}
	{
	  qpsrcw,0	%g31, %r22, %g31
	  qpaddw,3	%g24, %g22, %r4
	}
	{
	  qpxor,0	%g21, %g31, %g21
	  qpaddw,3	%g18, %g16, %r10
	  qpsrcw,4	%r4, %r23, %r4
	}
	{
	  qpaddw,0	%g21, %g26, %r11
	  qpaddw,3	%g30, %g19, %g31
	  qpsrcw,4	%r10, %r23, %r10
	}
	{
	  qpsrcw,0	%r11, %r21, %r4
	  qpsrcw,3	%g31, %r23, %g31
	  qpxor,4	%g28, %r4, %g28
	}
	{
	  qpxor,0	%g17, %r4, %g17
	  qpxor,3	%r29, %g31, %g31
	  qpxor,4	%g25, %r10, %g25
	}
	{
	  qpaddw,0	%g17, %g21, %r10
	  qpaddw,3	%g28, %g24, %r4
	}
	{
	  qpsrcw,0	%r10, 0xe, %r10
	  qpaddw,3	%g25, %g18, %r11
	  qpsrcw,4	%r4, %r22, %r4
	}
	{
	  qpxor,0	%g20, %r10, %g20
	  qpaddw,3	%g31, %g30, %r12
	  qpsrcw,4	%r11, %r22, %r11
	}
	{
	  qpaddw,0	%g20, %g31, %r4
	  qpxor,3	%g23, %r4, %g23
	  qpsrcw,4	%r12, %r22, %r10
	}
	{
	  qpsrcw,0	%r4, %r23, %r4
	  qpxor,3	%g27, %r10, %g27
	  qpxor,4	%g29, %r11, %g29
	}
	{
	  qpaddw,3	%g23, %g28, %r10
	}
	{
	  qpaddw,3	%g29, %g25, %r11
	  qpsrcw,4	%r10, %r21, %r10
	}
	{
	  qpaddw,3	%g27, %g31, %r12
	  qpsrcw,4	%r11, %r21, %r11
	}
	{
	  qpsrcw,3	%r12, %r21, %r12
	  qpxor,4	%g22, %r10, %g22
	}
	{
	  qpxor,3	%g19, %r12, %g19
	  qpxor,4	%g16, %r11, %g16
	}
	{
	  qpaddw,3	%g22, %g23, %r10
	  qpxor,4	%g22, %r4, %g22
	}
	{
	  qpaddw,3	%g16, %g29, %r4
	  qpsrcw,4	%r10, 0xe, %r10
	}
	{
	  qpaddw,3	%g19, %g27, %r11
	  qpsrcw,4	%r4, 0xe, %r4
	}
	{
	  qpxor,3	%g24, %r10, %g24
	  qpsrcw,4	%r11, 0xe, %r11
	}
	{
	  qpaddw,0	%g22, %g20, %r4
	  qpxor,3	%g30, %r11, %g30
	  qpxor,4	%g18, %r4, %g18
	}
	{
	  qpsrcw,0	%r4, %r22, %r4
	  qpaddw,3	%g24, %g26, %r10
	}
	{
	  qpxor,0	%g29, %r4, %g29
	  qpaddw,3	%g18, %g28, %r11
	  qpsrcw,4	%r10, %r23, %r10
	}
	{
	  qpaddw,0	%g29, %g22, %r12
	  qpaddw,3	%g30, %g25, %r4
	  qpsrcw,4	%r11, %r23, %r11
	}
	{
	  qpsrcw,0	%r12, %r21, %r10
	  qpsrcw,3	%r4, %r23, %r4
	  qpxor,4	%g16, %r10, %g16
	}
	{
	  qpxor,0	%g31, %r10, %g31
	  qpxor,3	%g17, %r4, %g17
	  qpxor,4	%g19, %r11, %g19
	}
	{
	  qpaddw,0	%g31, %g29, %r10
	  qpaddw,3	%g16, %g24, %r4
	}
	{
	  qpsrcw,0	%r10, 0xe, %r10
	  qpaddw,3	%g19, %g18, %r11
	  qpsrcw,4	%r4, %r22, %r4
	}
	{
	  qpxor,0	%g20, %r10, %g20
	  qpaddw,3	%g17, %g30, %r12
	  qpsrcw,4	%r11, %r22, %r11
	}
	{
	  qpaddw,0	%g20, %g17, %r4
	  qpxor,3	%g27, %r4, %g27
	  qpsrcw,4	%r12, %r22, %r10
	}
	{
	  qpsrcw,0	%r4, %r23, %r4
	  qpxor,3	%g23, %r10, %g23
	  qpxor,4	%g21, %r11, %g21
	}
	{
	  qpaddw,3	%g27, %g16, %r10
	}
	{
	  qpaddw,3	%g21, %g19, %r11
	  qpsrcw,4	%r10, %r21, %r10
	}
	{
	  qpaddw,3	%g23, %g17, %r12
	  qpsrcw,4	%r11, %r21, %r11
	}
	{
	  qpsrcw,3	%r12, %r21, %r12
	  qpxor,4	%g26, %r10, %g26
	}
	{
	  qpxor,3	%g25, %r12, %g25
	  qpxor,4	%g28, %r11, %g28
	}
	{
	  qpaddw,3	%g26, %g27, %r10
	  qpxor,4	%g26, %r4, %g26
	}
	{
	  qpaddw,3	%g28, %g21, %r4
	  qpsrcw,4	%r10, 0xe, %r10
	}
	{
	  qpaddw,3	%g25, %g23, %r11
	  qpsrcw,4	%r4, 0xe, %r4
	}
	{
	  qpxor,3	%g24, %r10, %g24
	  qpsrcw,4	%r11, 0xe, %r11
	}
	{
	  qpaddw,0	%g26, %g20, %r4
	  qpxor,3	%g30, %r11, %g30
	  qpxor,4	%g18, %r4, %g18
	}
	{
	  qpaddw,0	%r50, %g26, %r11
	  qpsrcw,1	%r4, %r22, %r4
	  qpaddw,3	%g24, %g22, %r10
	}
	{
	  qpxor,0	%g21, %r4, %g21
	  stqp,2	%r1, _f16s,_lts0lo 0x160, %r11
	  qpaddw,3	%g18, %g16, %r12
	  qpsrcw,4	%r10, %r23, %r10
	}
	{
	  qpaddw,0	%g21, %g26, %g26
	  qpaddw,3	%g30, %g19, %r4
	  qpsrcw,4	%r12, %r23, %r12
	}
	{
	  qpaddw,0	%b[15], %g21, %r10
	  qpsrcw,1	%g26, %r21, %g26
	  qpxor,3	%g28, %r10, %g28
	  qpsrcw,4	%r4, %r23, %r4
	}
	{
	  qppermb,0	%r10, %r11, %r18, %g26
	  qpxor,1	%g17, %g26, %g17
	  stqp,2	%r1, _f16s,_lts0lo 0x170, %r10
	  qpxor,3	%g31, %r4, %g31
	  qpxor,4	%g25, %r12, %g25
	}
	{
	  qpaddw,0	%g17, %g21, %g21
	  qppermb,1	%r10, %r11, %r19, %r10
	  qpaddw,3	%g28, %g24, %r4
	}
	{
	  qpaddw,0	%b[4], %g17, %g17
	  qpsrcw,1	%g21, 0xe, %g21
	  qpaddw,3	%g25, %g18, %r11
	  qpsrcw,4	%r4, %r22, %r4
	}
	{
	  qpaddw,0	%r57, %g28, %g21
	  qpxor,1	%g20, %g21, %g20
	  stqp,2	%r1, _f16s,_lts0lo 0x140, %g17
	  qpaddw,3	%g31, %g30, %r12
	  qpsrcw,4	%r11, %r22, %r11
	}
	{
	  qpaddw,0	%r46, %g25, %r4
	  stqp,2	%r1, _f16s,_lts0lo 0x1b0, %g21
	  qpxor,3	%g23, %r4, %g23
	  qpsrcw,4	%r12, %r22, %r12
	}
	{
	  qpaddw,0	%r45, %g31, %r11
	  stqp,2	%r1, _f16s,_lts0lo 0x1c0, %r4
	  qpxor,3	%g27, %r12, %g27
	  qpxor,4	%g29, %r11, %g29
	}
	{
	  qpaddw,0	%r47, %g20, %g20
	  stqp,2	%r1, _f16s,_lts0lo 0x110, %r11
	  qpaddw,3	%g23, %g28, %g28
	}
	{
	  qppermb,0	%g20, %g17, %r18, %r12
	  qppermb,1	%g20, %g17, %r19, %g17
	  stqp,2	%r1, _f16s,_lts0lo 0x150, %g20
	  qpaddw,3	%g29, %g25, %g25
	  qpsrcw,4	%g28, %r21, %g28
	}
	{
	  qpaddw,0	%b[13], %g23, %g31
	  qppermb,1	%g26, %r12, %r18, %r13
	  qpaddw,3	%g27, %g31, %g20
	  qpsrcw,4	%g25, %r21, %g25
	}
	{
	  qpaddw,0	%b[11], %g29, %g28
	  qppermb,1	%g26, %r12, %r19, %g26
	  stqp,2	%r1, _f16s,_lts0lo 0x180, %g31
	  qpxor,3	%g22, %g28, %g22
	  qpsrcw,4	%g20, %r21, %g20
	}
	{
	  qpaddw,0	%b[19], %g27, %g20
	  qppermb,1	%g28, %r4, %r18, %g25
	  stqp,2	%r0, _f16s,_lts0lo 0x1d0, %r13
	  qpxor,3	%g19, %g20, %g19
	  qpxor,4	%g16, %g25, %g16
	}
	{
	  qppermb,0	%g28, %r4, %r19, %r4
	  qppermb,1	%r10, %g17, %r18, %r12
	  stqp,2	%r1, _f16s,_lts0lo 0x1d0, %g28
	  qpaddw,3	%g22, %g23, %g23
	  qppermb,4	%r10, %g17, %r19, %g17
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0xd0, %g26
	  qpaddw,3	%g16, %g29, %g28
	  qpsrcw,4	%g23, 0xe, %g23
	  stqp,5	%r0, _f16s,_lts0hi 0x50, %g17
	}
	{
	  qpaddw,0	%b[1], %g22, %g22
	  stqp,2	%r1, _f16s,_lts0lo 0x120, %g20
	  qpaddw,3	%g19, %g27, %g17
	  qpsrcw,4	%g28, 0xe, %g26
	}
	{
	  qpaddw,0	%r63, %g16, %g16
	  qppermb,1	%g22, %g31, %r18, %g24
	  stqp,2	%r0, _f16s,_lts0lo 0x150, %r12
	  qpxor,3	%g24, %g23, %g23
	  qpsrcw,4	%g17, 0xe, %g17
	}
	{
	  qpaddw,0	%b[3], %g19, %g19
	  qppermb,1	%g22, %g31, %r19, %g26
	  stqp,2	%r1, _f16s,_lts0lo 0x190, %g22
	  qpxor,3	%g30, %g17, %g17
	  qpxor,4	%g18, %g26, %g18
	}
	{
	  qppermb,0	%g19, %g20, %r18, %g23
	  qppermb,1	%g19, %g20, %r19, %g20
	  stqp,2	%r1, _f16s,_lts0lo 0x1e0, %g16
	  qpaddw,3	%r54, %g23, %g22
	}
	{
	  stqp,2	%r1, _f16s,_lts0lo 0x130, %g19
	  qpaddw,3	%r59, %g18, %g18
	  qppermb,4	%g21, %g22, %r18, %g27
	  stqp,5	%r1, _f16s,_lts0hi 0x1a0, %g22
	}
	{
	  qpaddw,3	%r42, %g17, %g17
	  qppermb,4	%g21, %g22, %r19, %g19
	  stqp,5	%r1, _f16s,_lts0lo 0x1f0, %g18
	}
	{
	  qppermb,3	%g18, %g16, %r18, %g21
	  qppermb,4	%g18, %g16, %r19, %g16
	  stqp,5	%r1, _f16s,_lts0lo 0x100, %g17
	}
	{
	  qppermb,3	%r11, %g17, %r18, %g18
	  qppermb,4	%r11, %g17, %r19, %g17
	}
	{
	  qppermb,0	%g27, %g24, %r18, %g22
	  qppermb,1	%g27, %g24, %r19, %g24
	  qppermb,3	%g19, %g26, %r18, %g27
	  qppermb,4	%g19, %g26, %r19, %g19
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x1e0, %g22
	  qppermb,3	%g21, %g25, %r18, %g26
	  qppermb,4	%g21, %g25, %r19, %g21
	  stqp,5	%r0, _f16s,_lts0hi 0x160, %g27
	}
	{
	  qppermb,0	%g16, %r4, %r18, %g22
	  qppermb,1	%g16, %r4, %r19, %g16
	  stqp,2	%r0, _f16s,_lts0lo 0xe0, %g24
	  qppermb,3	%g23, %g18, %r18, %g25
	  qppermb,4	%g23, %g18, %r19, %g18
	  stqp,5	%r0, _f16s,_lts0hi 0x60, %g19
	}
	{
	  qppermb,0	%g20, %g17, %r18, %g19
	  qppermb,1	%g20, %g17, %r19, %g17
	  stqp,2	%r0, _f16s,_lts0hi 0x170, %g22
	  stqp,5	%r0, _f16s,_lts0lo 0x1f0, %g26
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0xf0, %g21
	  stqp,5	%r0, _f16s,_lts0hi 0x1c0, %g25
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x70, %g16
	  stqp,5	%r0, _f16s,_lts0hi 0xc0, %g18
	}
	{
	  ct	%ctpr1 ? %pred2
	  stqp,2	%r0, _f16s,_lts0lo 0x140, %g19
	  stqp,5	%r0, _f16s,_lts0hi 0x40, %g17
	}
	{
	  ct	%ctpr3 ? ~%pred2
	}
.L81970:
	{
	  setwd	wsz = 0x37, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0xd, rbs = 0x20, rcur = 0x0
	  ldisp	%ctpr2, .L82078
	  cmpldb,0	0x0, %r14, %pred0
	  addd,1	0x0, _f64,_lts1 0x80f72000000000, %g16
	  addd,2,sm	0x1, 0x0, %g17
	  addd,3,sm	%r0, %r10, %g18
	  addd,4	%r24, %r5, %g19
	  addd,5,sm	0x0, 0x0, %g21
	}
	{
	  disp	%ctpr1, .L81682
	  ldd,0,sm	%r0, %r10, %g24
	  addd,1	0x0, 0x0, %g22
	  aaurw,2	%r28, %aaincr1
	  addd,3,sm	0x0, %g18, %g20
	  addd,4	%r7, %r10, %g23
	  addd,5	%g19, %r10, %g19
	}
	{
	  insfd,0,sm	%g16, _f32s,_lts1 0x8800, %r14, %g25 ? %pred0
	  insfd,1,sm	%g16, _lit32_ref,_lts1 0x8800, %g17, %g25 ? ~%pred0
	  aaurwd,2	%r25, %aaincr2
	  addd,3,sm	%g20, _f16s,_lts0lo 0xc0, %g20
	  aaurwd,5	%g23, %aad2
	}
	{
	  rwd,0	%g25, %lsr
	  andd,1	%g25, _f64,_lts0 0xffffffff, %g16
	  aaurwd,2	%g22, %aasti2
	  aaurwd,5	%g22, %aasti1
	}
	{
	  shld,1	%g16, 0x2, %g16
	  aaurwd,2	%g19, %aad1
	  ldd,5,sm	%g18, 0x8, %g17
	}
	{
	  addd,0	%r6, %g16, %r4
	  aaurwq,2	%g20, %aad0
	}
	{
	  ldd,0,sm	%g18, _f16s,_lts0lo 0x10, %g16
	  ldd,2,sm	%g18, _f16s,_lts0hi 0x18, %g19
	  ldd,3,sm	%g18, _f16s,_lts1lo 0x20, %b[23]
	  ldd,5,sm	%g18, _f16s,_lts1hi 0x28, %b[22]
	}
	{
	  bap
	  ldd,0,sm	%g18, _f16s,_lts0lo 0x30, %b[11]
	  ldd,2,sm	%g18, _f16s,_lts0hi 0x38, %b[10]
	  ldd,3,sm	%g18, _f16s,_lts1lo 0x40, %b[21]
	  qppackdl,4,sm	%g17, %g24, %b[27]
	  ldd,5,sm	%g18, _f16s,_lts1hi 0x48, %b[20]
	}
	{
	  ldd,0,sm	%g18, _f16s,_lts0lo 0x50, %b[9]
	  ldd,2,sm	%g18, _f16s,_lts0hi 0x58, %b[8]
	  ldd,3,sm	%g18, _f16s,_lts1lo 0x60, %b[19]
	  ldd,5,sm	%g18, _f16s,_lts1hi 0x68, %b[18]
	}
	{
	  ldd,0,sm	%g18, _f16s,_lts0lo 0x70, %b[7]
	  qppackdl,1,sm	%g19, %g16, %b[26]
	  ldd,2,sm	%g18, _f16s,_lts0hi 0x78, %b[6]
	  ldd,3,sm	%g18, _f16s,_lts1lo 0x80, %b[17]
	  ldd,5,sm	%g18, _f16s,_lts1hi 0x88, %b[16]
	}
	{
	  ldd,0,sm	%g18, _f16s,_lts0lo 0x90, %b[5]
	  ldd,2,sm	%g18, _f16s,_lts0hi 0x98, %b[4]
	  ldd,3,sm	%g18, _f16s,_lts1lo 0xa0, %b[15]
	  ldd,5,sm	%g18, _f16s,_lts1hi 0xa8, %b[14]
	}
	{
	  nop 7
	  ldd,0,sm	%g18, _f16s,_lts0lo 0xb0, %b[3]
	  ldd,2,sm	%g18, _f16s,_lts0hi 0xb8, %b[2]
	}
	{
	  nop 3
	}
.L81682:
	{
	  loop_mode
	  alc	alcf=1, alct=1
	  abn	abnf=1, abnt=1
	  ct	%ctpr1 ? %NOT_LOOP_END
	  qppackdl,1,sm	%b[22], %b[23], %b[25]
	  staaqp,2	%b[27], %aad2[ %aasti2 ]
	  incr,2	%aaincr2
	  qppackdl,4,sm	%b[10], %b[11], %b[24]
	  staaqp,5	%b[26], %aad1[ %aasti1 ]
	  incr,5	%aaincr2
	  movad,0	area=0, ind=0, am=0, be=0, %b[13]
	  movad,1	area=0, ind=8, am=1, be=0, %b[12]
	  movad,2	area=0, ind=0, am=0, be=0, %b[1]
	  movad,3	area=0, ind=8, am=1, be=0, %b[0]
	}
	{
	  setwd	wsz = 0x37, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x16, rbs = 0x20, rcur = 0x0
	  disp	%ctpr3, .L2073
	  shld,0,sm	%r4, 0x3, %g16
	  shld,1	%r14, 0x1, %g17
	  shld,2	%r16, 0x1, %g18
	  adds,3	0x0, 0x0, %g19
	}
	{
	  ldd,0,sm	%r27, %g16, %g21
	  cmpedb,1	%g17, %r15, %pred0
	  ldd,2,sm	%r0, %g16, %g20
	}
	{
	  disp	%ctpr2, disp=0x0
	  cmpedb,0	%g18, %r17, %pred1
	  aaurw,2	%g19, %aabf0
	}
	{
	  addd,0	%r4, 0x2, %r4 ? ~%pred0
	}
	{
	  qppackdl,0,sm	%g21, %g20, %g17
	  shld,1,sm	%r4, 0x3, %g18
	}
	{
	  ct	%ctpr3 ? %pred1
	  ldd,0,sm	%r0, %g18, %g16
	  stqp,2	%r7, %g16, %g17 ? ~%pred0
	}
	{
	  nop 2
	}
	{
	  ct	%ctpr3 ? ~%pred1
	  std,2	%r7, %g18, %g16 ? ~%pred1
	}
	.section .text.async_prefetch_code, "ax", @progbits

	.align	8
.L82078:
	{
	  fapb	ct=1, dcd=0, fmt=4, mrng=0, d=0, incr=1, ind=0, asz=5, abs=0, disp=0
	  fapb	dpl=0, dcd=0, fmt=4, mrng=16, d=0, incr=1, ind=0, asz=5, abs=0, disp=16
	}
.L82120:
	{
	  fapb	ct=1, dcd=0, fmt=5, mrng=0, d=0, incr=1, ind=0, asz=5, abs=0, disp=0
	}
.previous

	.size	scrypt_1024_core_1_cycle_elway, .- scrypt_1024_core_1_cycle_elway
	.local	scrypt_1024_core_2_cycle_elway
	.type	scrypt_1024_core_2_cycle_elway, #function
	.align	8
scrypt_1024_core_2_cycle_elway:
	{
	  setwd	wsz = 0x4b, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x2a, rbs = 0x20, rcur = 0x0
	  addd,1	0x0, _f64,_lts2 0x3ff000003ff, %g16
	  addd,2	0x19, 0x0, %r10
	  addd,3	0x17, 0x0, %r11
	  addd,4	0x13, 0x0, %r12
	  addd,5	0x0, 0x0, %r5
	}
	{
	  addd,0	0x0, _f64,_lts0 0x1b1a191813121110, %g17
	  addd,1	0x0, _f64,_lts2 0x1f1e1d1c17161514, %g18
	  addd,2	0x0, %g16, %g19
	}
	{
	  qppackdl,0	%g17, _f64,_lts2 0xb0a090803020100, %r9
	  qppackdl,1	%g19, %g16, %r6
	}
	{
	  qppackdl,0	%g18, _f64,_lts1 0xf0e0d0c07060504, %r7
	  addd,1	0x0, _f16s,_lts0lo 0x820, %r13
	}
.L82135:
	{
	  disp	%ctpr1, .L82135
	  ldqp,0	%r1, _f16s,_lts0lo 0x100, %g16
	  addd,1	%r5, 0x1, %r5
	  ldqp,2	%r1, _f16s,_lts0hi 0x300, %g17
	  ldqp,3	%r1, _f16s,_lts1lo 0x1f0, %g18
	  ldqp,5	%r1, _f16s,_lts1hi 0x1c0, %g19
	}
	{
	  return	%ctpr3
	  ldqp,0	%r1, _f16s,_lts0lo 0x1b0, %g20
	  cmpldb,1	%r5, _f32s,_lts2 0x400, %pred0
	  ldqp,2	%r1, _f16s,_lts0hi 0x1a0, %g21
	  ldqp,3	%r1, _f16s,_lts1lo 0x160, %g22
	  ldqp,5	%r1, _f16s,_lts1hi 0x150, %g23
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0x110, %g24
	  ldqp,2	%r1, _f16s,_lts0hi 0xf0, %g25
	  ldqp,3	%r1, _f16s,_lts1lo 0xc0, %g26
	  ldqp,5	%r1, _f16s,_lts1hi 0xb0, %g27
	}
	{
	  qpand,0	%g17, %r6, %g29
	  qpand,1	%g16, %r6, %g28
	  ldqp,2	%r1, _f16s,_lts0lo 0xa0, %g30
	  ldqp,3	%r1, _f16s,_lts0hi 0x60, %g31
	  ldqp,5	%r1, _f16s,_lts1lo 0x50, %r4
	}
	{
	  qpsllw,0	%g29, 0x6, %g29
	  qpsllw,1	%g28, 0x6, %g28
	  ldqp,2	%r1, _f16s,_lts0lo 0x10, %r14
	  ldqp,3	%r1, 0x0, %r15
	  ldqp,5	%r1, _f16s,_lts0hi 0x1e0, %r16
	}
	{
	  qpswitchd,0	%g29, %r18
	  qpswitchd,1	%g28, %r17
	  ldqp,2	%r1, _f16s,_lts0lo 0x190, %r19
	  ldqp,3	%r1, _f16s,_lts0hi 0x140, %r20
	  ldqp,5	%r1, _f16s,_lts1lo 0x130, %r21
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0xe0, %r22
	  ldqp,2	%r1, _f16s,_lts0hi 0x90, %r23
	  ldqp,3	%r1, _f16s,_lts1lo 0x40, %r24
	  ldqp,5	%r1, _f16s,_lts1hi 0x30, %r25
	}
	{
	  ldqp,0	%r1, _f16s,_lts0lo 0x1d0, %r26
	  ldqp,2	%r1, _f16s,_lts0hi 0x180, %r27
	  ldqp,3	%r1, _f16s,_lts1lo 0x170, %r28
	  ldqp,5	%r1, _f16s,_lts1hi 0x120, %r29
	}
	{
	  getfd,0,sm	%g28, %r13, %r30
	  getfd,1,sm	%g29, %r13, %r31
	  adds,2	%g28, 0x4, %r32
	  adds,3	%g28, 0x5, %r33
	  adds,4	%g28, 0x6, %r34
	  adds,5	%g28, 0x7, %r35
	}
	{
	  getfd,0,sm	%r17, %r13, %r36
	  getfd,1,sm	%r18, %r13, %r37
	  adds,2	%g29, _f16s,_lts0lo 0x24, %r38
	  adds,3	%g29, _f16s,_lts0hi 0x25, %r39
	  adds,4	%g29, _f16s,_lts1lo 0x26, %r40
	  adds,5	%g29, _f16s,_lts1hi 0x27, %r41
	}
	{
	  adds,0	%r17, _f16s,_lts0lo 0x14, %r42
	  adds,1	%r17, _f16s,_lts0hi 0x15, %r43
	  adds,2	%r17, _f16s,_lts1lo 0x16, %r44
	  adds,3	%r17, %r11, %r45
	  adds,4	%r18, _f16s,_lts1hi 0x34, %r46
	  adds,5	%r18, _f32s,_lts2 0x35, %r47
	}
	{
	  adds,0	%r18, _f16s,_lts0lo 0x36, %r48
	  adds,1	%r18, _f16s,_lts0hi 0x37, %r49
	  adds,2	%r30, 0xc, %r50
	  adds,3	%r30, 0xd, %r51
	  adds,4	%r30, 0xe, %r52
	  adds,5	%r30, 0xf, %r53
	}
	{
	  adds,0	%r31, _f16s,_lts0lo 0x2c, %r54
	  adds,1	%r31, _f16s,_lts0hi 0x2d, %r55
	  adds,2	%r31, _f16s,_lts1lo 0x2e, %r56
	  adds,3	%r31, _f16s,_lts1hi 0x2f, %r57
	  adds,4	%r36, _f32s,_lts2 0x1c, %r58
	  adds,5	%r36, _f32s,_lts3 0x1d, %r59
	}
	{
	  adds,0	%r36, _f16s,_lts0lo 0x1e, %r60
	  adds,1	%r36, _f16s,_lts0hi 0x1f, %r61
	  adds,2	%r37, _f16s,_lts1lo 0x3c, %r62
	  adds,3	%r37, _f16s,_lts1hi 0x3d, %r63
	  adds,4	%r37, _f32s,_lts2 0x3e, %b[0]
	  adds,5	%r37, _f32s,_lts3 0x3f, %b[1]
	}
	{
	  adds,0	%g28, 0x1, %b[2]
	  adds,1	%g28, 0x2, %b[3]
	  adds,2	%g28, 0x3, %b[4]
	  adds,3	%g29, _f16s,_lts0lo 0x20, %b[5]
	  adds,4	%g29, _f16s,_lts0hi 0x21, %b[6]
	  adds,5	%g29, _f16s,_lts1lo 0x22, %b[7]
	}
	{
	  adds,0	%g29, _f16s,_lts0lo 0x23, %g29
	  adds,1	0x10, %r17, %b[8]
	  adds,2	%r17, _f16s,_lts0hi 0x11, %b[9]
	  adds,3	%r17, _f16s,_lts1lo 0x12, %b[10]
	  adds,4	%r17, %r12, %r17
	  adds,5	%r18, _f16s,_lts1hi 0x30, %b[11]
	}
	{
	  adds,0	%r18, _f16s,_lts0lo 0x31, %b[12]
	  adds,1	%r18, _f16s,_lts0hi 0x32, %b[13]
	  adds,2	%r18, _f16s,_lts1lo 0x33, %r18
	  adds,3	%r30, 0x8, %b[14]
	  adds,4	%r30, 0x9, %b[15]
	  adds,5	%r30, 0xa, %b[16]
	}
	{
	  adds,0	%r30, 0xb, %r30
	  adds,1	%r31, _f16s,_lts0lo 0x28, %b[17]
	  adds,2	%r31, _f16s,_lts0hi 0x29, %b[18]
	  adds,3	%r31, _f16s,_lts1lo 0x2a, %b[19]
	  adds,4	%r31, _f16s,_lts1hi 0x2b, %r31
	  sxt,5	0x6, %r32, %r32
	}
	{
	  sxt,0	0x6, %r33, %r33
	  sxt,1	0x6, %r34, %r34
	  sxt,2	0x6, %r35, %r35
	  adds,3	0x18, %r36, %b[20]
	  adds,4	%r36, %r10, %b[21]
	  adds,5	%r36, _f16s,_lts0lo 0x1a, %b[22]
	}
	{
	  adds,0	%r36, _f16s,_lts0lo 0x1b, %r36
	  adds,1	%r37, _f16s,_lts0hi 0x38, %b[23]
	  adds,2	%r37, _f16s,_lts1lo 0x39, %b[24]
	  adds,3	%r37, _f16s,_lts1hi 0x3a, %b[25]
	  adds,4	%r37, _f32s,_lts2 0x3b, %r37
	  sxt,5	0x6, %r38, %r38
	}
	{
	  sxt,0	0x6, %r39, %r39
	  sxt,1	0x6, %r40, %r40
	  sxt,2	0x6, %r41, %r41
	  sxt,3	0x6, %r42, %r42
	  sxt,4	0x6, %r43, %r43
	  sxt,5	0x6, %r44, %r44
	}
	{
	  sxt,0	0x6, %r45, %r45
	  sxt,1	0x6, %r46, %r46
	  sxt,2	0x6, %r47, %r47
	  sxt,3	0x6, %r48, %r48
	  sxt,4	0x6, %r49, %r49
	  sxt,5	0x6, %r50, %r50
	}
	{
	  sxt,0	0x6, %r51, %r51
	  sxt,1	0x6, %r52, %r52
	  sxt,2	0x6, %r53, %r53
	  sxt,3	0x6, %r54, %r54
	  sxt,4	0x6, %r55, %r55
	  sxt,5	0x6, %r56, %r56
	}
	{
	  sxt,0	0x6, %r57, %r57
	  sxt,1	0x6, %r58, %r58
	  sxt,2	0x6, %r59, %r59
	  sxt,3	0x6, %r60, %r60
	  sxt,4	0x6, %r61, %r61
	  sxt,5	0x6, %r62, %r62
	}
	{
	  sxt,0	0x6, %r63, %r63
	  sxt,1	0x6, %b[0], %b[0]
	  sxt,2	0x6, %b[1], %b[1]
	  shld,3	%g28, 0x4, %g28
	  sxt,4	0x6, %b[2], %b[2]
	  sxt,5	0x6, %b[3], %b[3]
	}
	{
	  sxt,0	0x6, %b[4], %b[4]
	  sxt,1	0x6, %b[5], %b[5]
	  sxt,2	0x6, %b[6], %b[6]
	  sxt,3	0x6, %b[7], %b[7]
	  sxt,4	0x6, %g29, %g29
	  sxt,5	0x6, %b[8], %b[8]
	}
	{
	  sxt,0	0x6, %b[9], %b[9]
	  sxt,1	0x6, %b[10], %b[10]
	  sxt,2	0x6, %r17, %r17
	  sxt,3	0x6, %b[11], %b[11]
	  sxt,4	0x6, %b[12], %b[12]
	  sxt,5	0x6, %b[13], %b[13]
	}
	{
	  sxt,0	0x6, %r18, %r18
	  sxt,1	0x6, %b[14], %b[14]
	  sxt,2	0x6, %b[15], %b[15]
	  sxt,3	0x6, %b[16], %b[16]
	  sxt,4	0x6, %r30, %r30
	  sxt,5	0x6, %b[17], %b[17]
	}
	{
	  sxt,0	0x6, %b[18], %b[18]
	  sxt,1	0x6, %b[19], %b[19]
	  sxt,2	0x6, %r31, %r31
	  shld,3	%r32, 0x4, %r32
	  shld,4	%r33, 0x4, %r33
	  shld,5	%r34, 0x4, %r34
	}
	{
	  shld,0	%r35, 0x4, %r35
	  sxt,1	0x6, %b[20], %b[20]
	  sxt,2	0x6, %b[21], %b[21]
	  sxt,3	0x6, %b[22], %b[22]
	  sxt,4	0x6, %r36, %r36
	  sxt,5	0x6, %b[23], %b[23]
	}
	{
	  sxt,0	0x6, %b[24], %b[24]
	  sxt,1	0x6, %b[25], %b[25]
	  sxt,2	0x6, %r37, %r37
	  shld,3	%r38, 0x4, %r38
	  shld,4	%r39, 0x4, %r39
	  shld,5	%r40, 0x4, %r40
	}
	{
	  shld,0	%r41, 0x4, %r41
	  shld,1	%r42, 0x4, %r42
	  shld,2	%r43, 0x4, %r43
	  shld,3	%r44, 0x4, %r44
	  shld,4	%r45, 0x4, %r45
	  shld,5	%r46, 0x4, %r46
	}
	{
	  shld,0	%r47, 0x4, %r47
	  shld,1	%r48, 0x4, %r48
	  shld,2	%r49, 0x4, %r49
	  shld,3	%r50, 0x4, %r50
	  shld,4	%r51, 0x4, %r51
	  shld,5	%r52, 0x4, %r52
	}
	{
	  shld,0	%r53, 0x4, %r53
	  shld,1	%r54, 0x4, %r54
	  shld,2	%r55, 0x4, %r55
	  shld,3	%r56, 0x4, %r56
	  shld,4	%r57, 0x4, %r57
	  shld,5	%r58, 0x4, %r58
	}
	{
	  shld,0	%r59, 0x4, %r59
	  shld,1	%r60, 0x4, %r60
	  shld,2	%r61, 0x4, %r61
	  shld,3	%r63, 0x4, %r63
	  shld,4	%r62, 0x4, %r62
	  shld,5	%b[0], 0x4, %b[0]
	}
	{
	  ldqp,0	%r2, %r32, %r32
	  shld,1	%b[1], 0x4, %b[1]
	  ldqp,2	%r2, %r50, %r50
	  ldqp,3	%r2, %r33, %r33
	  andd,4	%g28, _f64,_lts0 0xffffffff0, %g28
	  ldqp,5	%r2, %r51, %r51
	}
	{
	  ldqp,0	%r2, %r34, %r34
	  shld,1	%b[2], 0x4, %b[2]
	  ldqp,2	%r2, %r52, %r52
	  ldqp,3	%r2, %r35, %r35
	  shld,4	%b[3], 0x4, %b[3]
	  ldqp,5	%r2, %r53, %r53
	}
	{
	  ldqp,0	%r2, %r38, %r38
	  shld,1	%b[5], 0x4, %b[5]
	  ldqp,2	%r2, %r54, %r54
	  ldqp,3	%r2, %r39, %r39
	  shld,4	%b[4], 0x4, %b[4]
	  ldqp,5	%r2, %r55, %r55
	}
	{
	  ldqp,0	%r2, %r40, %r40
	  shld,1	%b[6], 0x4, %b[6]
	  ldqp,2	%r2, %r56, %r56
	  ldqp,3	%r2, %r41, %r41
	  shld,4	%b[7], 0x4, %b[7]
	  ldqp,5	%r2, %r57, %r57
	}
	{
	  ldqp,0	%r2, %r42, %r42
	  shld,1	%g29, 0x4, %g29
	  ldqp,2	%r2, %r58, %r58
	  ldqp,3	%r2, %r43, %r43
	  shld,4	%b[8], 0x4, %b[8]
	  ldqp,5	%r2, %r59, %r59
	}
	{
	  ldqp,0	%r2, %r44, %r44
	  shld,1	%b[9], 0x4, %b[9]
	  ldqp,2	%r2, %r60, %r60
	  ldqp,3	%r2, %r45, %r45
	  shld,4	%b[10], 0x4, %b[10]
	  ldqp,5	%r2, %r61, %r61
	}
	{
	  ldqp,0	%r2, %r46, %r46
	  shld,1	%r17, 0x4, %r17
	  ldqp,2	%r2, %r62, %r62
	  ldqp,3	%r2, %r47, %r47
	  shld,4	%b[11], 0x4, %b[11]
	  ldqp,5	%r2, %r63, %r63
	}
	{
	  ldqp,0	%r2, %r48, %r48
	  shld,1	%b[12], 0x4, %b[12]
	  ldqp,2	%r2, %b[0], %b[0]
	  ldqp,3	%r2, %r49, %r49
	  shld,4	%b[13], 0x4, %b[13]
	  ldqp,5	%r2, %b[1], %b[1]
	}
	{
	  shld,0	%r18, 0x4, %r18
	  shld,1	%b[14], 0x4, %b[14]
	  shld,2	%b[15], 0x4, %b[15]
	  shld,3	%b[16], 0x4, %b[16]
	  shld,4	%r30, 0x4, %r30
	  shld,5	%b[17], 0x4, %b[17]
	}
	{
	  shld,0	%b[18], 0x4, %b[18]
	  shld,1	%b[19], 0x4, %b[19]
	  shld,2	%r31, 0x4, %r31
	  shld,3	%b[20], 0x4, %b[20]
	  shld,4	%b[21], 0x4, %b[21]
	  shld,5	%b[22], 0x4, %b[22]
	}
	{
	  shld,0	%b[23], 0x4, %b[23]
	  shld,1	%r36, 0x4, %r36
	  shld,2	%b[24], 0x4, %b[24]
	  shld,3	%r37, 0x4, %r37
	  shld,4	%b[25], 0x4, %b[25]
	  ldqp,5	%r2, %g28, %g28
	}
	{
	  ldqp,0	%r2, %b[14], %b[14]
	  qppermb,1	%r50, %r32, %r7, %b[26]
	  ldqp,2	%r2, %b[2], %b[2]
	  ldqp,3	%r2, %b[15], %b[15]
	  qppermb,4	%r58, %r42, %r7, %b[27]
	  ldqp,5	%r2, %b[3], %b[3]
	}
	{
	  ldqp,0	%r2, %b[16], %b[16]
	  qppermb,1	%r58, %r42, %r9, %r42
	  ldqp,2	%r2, %b[4], %b[4]
	  ldqp,3	%r2, %r30, %r30
	  qppermb,4	%r50, %r32, %r9, %r32
	  ldqp,5	%r2, %b[5], %b[5]
	}
	{
	  ldqp,0	%r2, %b[17], %r50
	  qppermb,1	%r51, %r33, %r7, %b[17]
	  ldqp,2	%r2, %b[6], %r58
	  ldqp,3	%r2, %b[18], %b[6]
	  qppermb,4	%r59, %r43, %r7, %b[18]
	  ldqp,5	%r2, %b[7], %b[7]
	}
	{
	  ldqp,0	%r2, %b[19], %b[19]
	  qppermb,1	%r59, %r43, %r9, %r43
	  ldqp,2	%r2, %g29, %g29
	  ldqp,3	%r2, %r31, %r31
	  qppermb,4	%r51, %r33, %r9, %r33
	  ldqp,5	%r2, %b[8], %b[8]
	}
	{
	  ldqp,0	%r2, %b[20], %r51
	  qppermb,1	%r52, %r34, %r7, %b[20]
	  ldqp,2	%r2, %b[9], %r59
	  ldqp,3	%r2, %b[21], %b[9]
	  qppermb,4	%r60, %r44, %r7, %b[21]
	  ldqp,5	%r2, %b[10], %b[10]
	}
	{
	  ldqp,0	%r2, %b[22], %b[22]
	  qppermb,1	%r52, %r34, %r9, %r34
	  ldqp,2	%r2, %r17, %r17
	  ldqp,3	%r2, %r36, %r36
	  qppermb,4	%r60, %r44, %r9, %r44
	  ldqp,5	%r2, %b[11], %b[11]
	}
	{
	  ldqp,0	%r2, %b[23], %r52
	  qppermb,1	%r53, %r35, %r7, %b[23]
	  ldqp,2	%r2, %b[12], %r60
	  ldqp,3	%r2, %b[13], %b[13]
	  qppermb,4	%r61, %r45, %r7, %b[24]
	  ldqp,5	%r2, %b[24], %b[12]
	}
	{
	  ldqp,0	%r2, %r18, %r18
	  qppermb,1	%r53, %r35, %r9, %r35
	  ldqp,2	%r2, %b[25], %b[25]
	  qppermb,3	%r61, %r45, %r9, %r45
	  qppermb,4	%r54, %r38, %r7, %r53
	  ldqp,5	%r2, %r37, %r37
	}
	{
	  qppermb,0	%r62, %r46, %r7, %r61
	  qppermb,1	%r54, %r38, %r9, %r38
	  ldqp,2	%r1, _f16s,_lts0lo 0xd0, %r62
	  qppermb,3	%r62, %r46, %r9, %r46
	  qppermb,4	%r55, %r39, %r7, %r54
	  ldqp,5	%r1, _f16s,_lts0hi 0x80, %b[28]
	}
	{
	  qppermb,0	%r63, %r47, %r7, %b[29]
	  qppermb,1	%r55, %r39, %r9, %r39
	  ldqp,2	%r1, _f16s,_lts0lo 0x70, %r63
	  qppermb,3	%r63, %r47, %r9, %r47
	  qppermb,4	%r56, %r40, %r7, %r55
	  ldqp,5	%r1, _f16s,_lts0hi 0x20, %b[30]
	}
	{
	  qppermb,0	%b[0], %r48, %r7, %b[31]
	  qppermb,1	%r56, %r40, %r9, %r40
	  ldqp,2	%r1, _f16s,_lts0lo 0x3f0, %b[0]
	  qppermb,3	%b[0], %r48, %r9, %r48
	  qppermb,4	%r57, %r41, %r7, %r56
	  ldqp,5	%r1, _f16s,_lts0hi 0x3c0, %b[32]
	}
	{
	  qppermb,0	%b[1], %r49, %r7, %b[33]
	  qppermb,1	%r57, %r41, %r9, %r41
	  ldqp,2	%r1, _f16s,_lts0lo 0x3b0, %b[1]
	  qppermb,3	%b[1], %r49, %r9, %r49
	  qppermb,4	%b[14], %g28, %r7, %r57
	  ldqp,5	%r1, _f16s,_lts0hi 0x3a0, %b[34]
	}
	{
	  qppermb,0	%r51, %b[8], %r7, %b[35]
	  qppermb,1	%b[14], %g28, %r9, %g28
	  ldqp,2	%r1, _f16s,_lts0lo 0x360, %b[14]
	  qppermb,3	%r51, %b[8], %r9, %r51
	  qppermb,4	%b[15], %b[2], %r7, %b[8]
	  ldqp,5	%r1, _f16s,_lts0hi 0x350, %b[36]
	}
	{
	  qppermb,0	%b[9], %r59, %r7, %b[37]
	  qppermb,1	%b[15], %b[2], %r9, %b[2]
	  ldqp,2	%r1, _f16s,_lts0lo 0x310, %b[15]
	  qppermb,3	%b[9], %r59, %r9, %r59
	  qppermb,4	%b[27], %b[26], %r9, %b[9]
	  ldqp,5	%r1, _f16s,_lts0hi 0x2f0, %b[38]
	}
	{
	  qppermb,0	%b[16], %b[3], %r7, %b[39]
	  qppermb,1	%b[22], %b[10], %r7, %b[40]
	  ldqp,2	%r1, _f16s,_lts0lo 0x2c0, %b[16]
	  qppermb,3	%b[16], %b[3], %r9, %b[3]
	  qppermb,4	%b[22], %b[10], %r9, %b[10]
	  ldqp,5	%r1, _f16s,_lts0hi 0x2b0, %b[22]
	}
	{
	  qppermb,0	%r30, %b[4], %r7, %b[41]
	  qppermb,1	%r36, %r17, %r7, %b[42]
	  ldqp,2	%r1, _f16s,_lts0lo 0x2a0, %r36
	  qppermb,3	%r30, %b[4], %r9, %r30
	  qppermb,4	%r36, %r17, %r9, %r17
	  ldqp,5	%r1, _f16s,_lts0hi 0x260, %b[4]
	}
	{
	  qppermb,0	%r42, %r32, %r9, %b[43]
	  qppermb,1	%r50, %b[5], %r7, %b[44]
	  ldqp,2	%r1, _f16s,_lts0lo 0x250, %b[5]
	  qppermb,3	%r52, %b[11], %r7, %b[45]
	  qppermb,4	%r50, %b[5], %r9, %r50
	  ldqp,5	%r1, _f16s,_lts0hi 0x210, %b[46]
	}
	{
	  qppermb,0	%r52, %b[11], %r9, %r52
	  qppermb,1	%b[6], %r58, %r7, %b[11]
	  ldqp,2	%r1, _f16s,_lts0lo 0x200, %b[6]
	  qppermb,3	%b[12], %r60, %r7, %b[47]
	  qppermb,4	%b[6], %r58, %r9, %r58
	  ldqp,5	%r1, _f16s,_lts0hi 0x3e0, %b[48]
	}
	{
	  qppermb,0	%b[12], %r60, %r9, %r60
	  qppermb,1	%b[18], %b[17], %r9, %b[12]
	  ldqp,2	%r1, _f16s,_lts0lo 0x390, %b[51]
	  qppermb,3	%b[19], %b[7], %r7, %b[49]
	  qppermb,4	%b[25], %b[13], %r7, %b[50]
	  ldqp,5	%r1, _f16s,_lts0hi 0x340, %b[52]
	}
	{
	  qppermb,0	%b[19], %b[7], %r9, %b[7]
	  qppermb,1	%b[25], %b[13], %r9, %b[13]
	  ldqp,2	%r1, _f16s,_lts0lo 0x330, %b[53]
	  qppermb,3	%r31, %g29, %r7, %b[19]
	  qppermb,4	%r37, %r18, %r7, %b[25]
	  ldqp,5	%r1, _f16s,_lts0hi 0x2e0, %b[54]
	}
	{
	  qppermb,0	%r31, %g29, %r9, %g29
	  qppermb,1	%r37, %r18, %r9, %r18
	  ldqp,2	%r1, _f16s,_lts0lo 0x290, %b[55]
	  qppermb,3	%r43, %r33, %r7, %r31
	  qppermb,4	%b[21], %b[20], %r7, %r37
	  ldqp,5	%r1, _f16s,_lts0hi 0x240, %b[56]
	}
	{
	  qppermb,0	%r44, %r34, %r7, %b[57]
	  qppermb,1	%b[24], %b[23], %r7, %b[58]
	  ldqp,2	%r1, _f16s,_lts0hi 0x3d0, %b[62]
	  qppermb,3	%r45, %r35, %r9, %b[59]
	  qppermb,4	%r61, %r53, %r9, %b[60]
	  ldqp,5	%r1, _f16s,_lts0lo 0x230, %b[61]
	}
	{
	  qppermb,0	%r46, %r38, %r9, %b[63]
	  qppermb,1	%b[29], %r54, %r9, %b[64]
	  ldqp,2	%r1, _f16s,_lts0lo 0x380, %b[67]
	  qppermb,3	%r47, %r39, %r7, %b[65]
	  qppermb,4	%b[31], %r55, %r7, %b[66]
	  ldqp,5	%r1, _f16s,_lts0hi 0x370, %b[68]
	}
	{
	  qppermb,0	%r48, %r40, %r7, %b[69]
	  qppermb,1	%b[33], %r56, %r7, %b[70]
	  ldqp,2	%r1, _f16s,_lts0lo 0x320, %b[72]
	  qppermb,3	%r49, %r41, %r9, %b[71]
	  qpxor,4,sm	%g24, %b[9], %g24
	  ldqp,5	%r1, _f16s,_lts0hi 0x2d0, %b[73]
	}
	{
	  qppermb,0	%b[35], %r57, %r9, %b[74]
	  qppermb,1	%b[40], %b[39], %r7, %b[75]
	  ldqp,2	%r1, _f16s,_lts0lo 0x280, %b[77]
	  qpxor,3,sm	%g20, %r37, %g20
	  qppermb,4	%b[10], %b[3], %r7, %b[76]
	  ldqp,5	%r1, _f16s,_lts0hi 0x270, %b[78]
	}
	{
	  qpxor,0,sm	%g21, %b[57], %g21
	  qppermb,1	%r51, %g28, %r9, %b[79]
	  ldqp,2	%r1, _f16s,_lts0lo 0x220, %b[81]
	  qpxor,3,sm	%g16, %b[43], %g16
	  qppermb,4	%b[37], %b[8], %r9, %b[80]
	  stqp,5	%r0, _f16s,_lts0hi 0x110, %b[9]
	}
	{
	  qpxor,0,sm	%g23, %b[12], %g23
	  qppermb,1	%b[42], %b[41], %r7, %b[9]
	  stqp,2	%r0, _f16s,_lts0lo 0x100, %b[43]
	  qpxor,3,sm	%g18, %b[58], %g18
	  qppermb,4	%r17, %r30, %r9, %b[82]
	  stqp,5	%r0, _f16s,_lts0hi 0x150, %b[12]
	}
	{
	  qpxor,0,sm	%g19, %b[59], %g19
	  qppermb,1	%r59, %b[2], %r7, %b[12]
	  stqp,2	%r0, _f16s,_lts0lo 0x160, %r31
	  qpxor,3,sm	%g22, %r31, %g22
	  qppermb,4	%b[50], %b[49], %r7, %b[43]
	  stqp,5	%r0, _f16s,_lts0hi 0x1b0, %r37
	}
	{
	  qppermb,0	%b[45], %b[44], %r9, %r31
	  qppermb,1	%r52, %r50, %r9, %r37
	  stqp,2	%r0, _f16s,_lts0lo 0x1a0, %b[57]
	  qppermb,3	%b[13], %b[7], %r7, %b[83]
	  qppermb,4	%b[25], %b[19], %r7, %b[84]
	  stqp,5	%r0, _f16s,_lts0hi 0x1f0, %b[58]
	}
	{
	  qppermb,0	%b[47], %b[11], %r9, %b[57]
	  qppermb,1	%r60, %r58, %r7, %b[58]
	  stqp,2	%r0, _f16s,_lts0lo 0x1c0, %b[59]
	  qppermb,3	%r18, %g29, %r9, %b[85]
	  qppermb,4	%b[27], %b[26], %r7, %b[26]
	  stqp,5	%r0, _f16s,_lts0hi 0x310, %b[60]
	}
	{
	  qppermb,0	%r43, %r33, %r9, %r33
	  qppermb,1	%b[21], %b[20], %r9, %r43
	  stqp,2	%r0, _f16s,_lts0lo 0x300, %b[63]
	  qppermb,3	%r45, %r35, %r7, %r35
	  qppermb,4	%r61, %r53, %r7, %r45
	  stqp,5	%r0, _f16s,_lts0hi 0x350, %b[64]
	}
	{
	  qppermb,0	%r47, %r39, %r9, %r39
	  qppermb,1	%b[31], %r55, %r9, %r47
	  stqp,2	%r0, _f16s,_lts0lo 0x360, %b[65]
	  qppermb,3	%r49, %r41, %r7, %r41
	  qplog_0x96,4,sm	%r14, %b[74], %g24, %r14
	  stqp,5	%r0, _f16s,_lts0hi 0x3b0, %b[66]
	}
	{
	  qplog_0x96,0,sm	%r4, %b[80], %g23, %r4
	  qplog_0x96,1,sm	%g27, %b[75], %g20, %g27
	  stqp,2	%r0, _f16s,_lts0lo 0x3a0, %b[69]
	  qplog_0x96,3,sm	%g25, %b[9], %g18, %g25
	  qplog_0x96,4,sm	%g30, %b[76], %g21, %g30
	  stqp,5	%r0, _f16s,_lts0hi 0x3f0, %b[70]
	}
	{
	  qplog_0x96,0,sm	%g31, %b[12], %g22, %g31
	  qplog_0x96,1,sm	%r15, %b[79], %g16, %r15
	  stqp,2	%r0, _f16s,_lts0lo 0x3c0, %b[71]
	  qplog_0x96,3,sm	%g26, %b[82], %g19, %g26
	  qppermb,4	%b[35], %r57, %r7, %r49
	  stqp,5	0x10, %r0, %b[74]
	}
	{
	  qpxor,0,sm	%r21, %b[26], %r21
	  qppermb,1	%b[40], %b[39], %r9, %r53
	  stqp,2	%r0, _f16s,_lts0lo 0xb0, %b[75]
	  qpxor,3,sm	%r19, %r43, %r19
	  qppermb,4	%r17, %r30, %r7, %r17
	  stqp,5	%r0, _f16s,_lts0hi 0xa0, %b[76]
	}
	{
	  qpaddw,0	%r4, %r14, %r30
	  qpxor,1,sm	%r16, %r35, %r16
	  stqp,2	%r0, 0x0, %b[79]
	  qppermb,3	%r59, %b[2], %r9, %r55
	  qpxor,4,sm	%r20, %r33, %r20
	  stqp,5	%r0, _f16s,_lts0lo 0x50, %b[80]
	}
	{
	  qpaddw,0	%g25, %g27, %r57
	  qppermb,1	%b[50], %b[49], %r9, %r59
	  stqp,2	%r0, _f16s,_lts0lo 0xf0, %b[9]
	  qppermb,3	%b[45], %b[44], %r7, %r61
	  qppermb,4	%r60, %r58, %r9, %r58
	  stqp,5	%r0, _f16s,_lts0hi 0xc0, %b[82]
	}
	{
	  qpaddw,0	%g30, %g31, %r60
	  qppermb,1	%r18, %g29, %r7, %g29
	  stqp,2	%r0, _f16s,_lts0lo 0x60, %b[12]
	  qpaddw,3	%r15, %g26, %b[2]
	  qplog_0x96,4,sm	%r24, %r55, %r20, %r18
	  stqp,5	%r0, _f16s,_lts0hi 0x2b0, %b[43]
	}
	{
	  qpsrcw,0	%r30, %r10, %r24
	  qplog_0x96,1,sm	%r23, %r53, %r19, %r23
	  stqp,2	%r0, _f16s,_lts0lo 0x210, %r31
	  qplog_0x96,3,sm	%r25, %r49, %r21, %r25
	  qpsrcw,4	%b[2], %r10, %r30
	  stqp,5	%r0, _f16s,_lts0hi 0x200, %r37
	}
	{
	  qpsrcw,0	%r57, %r10, %r57
	  qplog_0x96,1,sm	%r22, %r17, %r16, %r22
	  stqp,2	%r0, _f16s,_lts0lo 0x2a0, %b[83]
	  qppermb,3	%r42, %r32, %r7, %r32
	  qppermb,4	%b[18], %b[17], %r7, %r42
	  stqp,5	%r0, _f16s,_lts0hi 0x2f0, %b[84]
	}
	{
	  qpsrcw,0	%r60, %r10, %r60
	  qppermb,1	%r44, %r34, %r9, %r34
	  stqp,2	%r0, _f16s,_lts0lo 0x250, %b[57]
	  qppermb,3	%b[24], %b[23], %r9, %r44
	  qppermb,4	%r46, %r38, %r7, %r38
	  stqp,5	%r0, _f16s,_lts0hi 0x260, %b[58]
	}
	{
	  qppermb,0	%b[29], %r54, %r7, %r46
	  qppermb,1	%r48, %r40, %r9, %r40
	  stqp,2	%r0, _f16s,_lts0lo 0x2c0, %b[85]
	  qppermb,3	%b[33], %r56, %r9, %r48
	  qpxor,4	%r18, %r30, %r30
	  stqp,5	%r0, _f16s,_lts0hi 0x130, %b[26]
	}
	{
	  qpxor,0	%r22, %r60, %r54
	  qpxor,1	%r23, %r24, %r24
	  stqp,2	%r0, _f16s,_lts0lo 0x140, %r33
	  qpaddw,3	%r30, %r15, %r56
	  qppermb,4	%b[10], %b[3], %r9, %r60
	  stqp,5	%r0, _f16s,_lts0hi 0x190, %r43
	}
	{
	  qpaddw,0	%r24, %r4, %r43
	  qpxor,1	%r25, %r57, %r33
	  stqp,2	%r0, _f16s,_lts0lo 0x1e0, %r35
	  qppermb,3	%r51, %g28, %r7, %g28
	  qpxor,4,sm	%r29, %r32, %r29
	  stqp,5	%r0, _f16s,_lts0hi 0x330, %r45
	}
	{
	  qpaddw,0	%r54, %g30, %r35
	  qpxor,1,sm	%r27, %r34, %r27
	  stqp,2	%r0, _f16s,_lts0lo 0x340, %r39
	  qppermb,3	%b[37], %b[8], %r7, %r51
	  qpxor,4,sm	%r28, %r42, %r28
	  stqp,5	%r0, _f16s,_lts0hi 0x390, %r47
	}
	{
	  qpaddw,0	%r33, %g25, %r57
	  qppermb,1	%b[42], %b[41], %r9, %b[2]
	  stqp,2	%r0, _f16s,_lts0lo 0x3e0, %r41
	  qpxor,3,sm	%r26, %r44, %r26
	  qppermb,4	%r52, %r50, %r7, %r50
	  stqp,5	%r0, _f16s,_lts0hi 0x30, %r49
	}
	{
	  qppermb,0	%b[13], %b[7], %r9, %r49
	  qppermb,1	%b[25], %b[19], %r9, %r52
	  stqp,2	%r0, _f16s,_lts0lo 0x90, %r53
	  qppermb,3	%b[47], %b[11], %r7, %b[3]
	  qpsrcw,4	%r56, %r11, %r56
	  stqp,5	%r0, _f16s,_lts0hi 0xe0, %r17
	}
	{
	  qplog_0x96,0,sm	%b[28], %r60, %r27, %r17
	  qpsrcw,1	%r43, %r11, %r43
	  stqp,2	%r0, _f16s,_lts0lo 0x40, %r55
	  qplog_0x96,3,sm	%b[30], %g28, %r29, %r53
	  qplog_0x96,4,sm	%r63, %r51, %r28, %r63
	  stqp,5	%r0, _f16s,_lts0hi 0x290, %r59
	}
	{
	  qpsrcw,0	%r35, %r11, %r35
	  qpsrcw,1	%r57, %r11, %r55
	  stqp,2	%r0, _f16s,_lts0lo 0x230, %r61
	  qpxor,3	%b[15], %b[60], %r57
	  qpxor,4,sm	%g17, %b[63], %g17
	  stqp,5	%r0, _f16s,_lts0hi 0x240, %r58
	}
	{
	  qplog_0x96,0,sm	%r62, %b[2], %r26, %r62
	  qpxor,1	%b[36], %b[64], %b[7]
	  stqp,2	%r0, _f16s,_lts0lo 0x2e0, %g29
	  qpxor,3	%b[14], %b[65], %b[8]
	  qpxor,4	%b[1], %b[66], %b[1]
	  stqp,5	%r0, _f16s,_lts0hi 0x120, %r32
	}
	{
	  qpxor,0	%b[34], %b[69], %r32
	  qpxor,1	%b[0], %b[70], %b[0]
	  stqp,2	%r0, _f16s,_lts0lo 0x170, %r42
	  qpxor,3	%b[32], %b[71], %b[9]
	  qplog_0x96,4,sm	%b[46], %r31, %r57, %r31
	  stqp,5	%r0, _f16s,_lts0hi 0x180, %r34
	}
	{
	  qpxor,0	%r17, %r56, %r34
	  qpxor,1	%r62, %r43, %r42
	  stqp,2	%r0, _f16s,_lts0lo 0x1d0, %r44
	  qplog_0x96,3,sm	%b[6], %r37, %g17, %r37
	  qplog_0x96,4	%b[16], %b[85], %b[9], %r43
	  stqp,5	%r0, _f16s,_lts0hi 0x320, %r38
	}
	{
	  qpxor,0	%r63, %r55, %r44
	  qpxor,1	%r53, %r35, %r35
	  stqp,2	%r0, _f16s,_lts0lo 0x370, %r46
	  qplog_0x96,3	%b[22], %b[43], %b[1], %r56
	  qplog_0x96,4	%b[4], %b[58], %b[8], %r55
	  stqp,5	%r0, _f16s,_lts0hi 0x380, %r40
	}
	{
	  qpaddw,0	%r34, %r30, %b[4]
	  qplog_0x96,1	%b[5], %b[57], %b[7], %b[5]
	  stqp,2	%r0, _f16s,_lts0lo 0x3d0, %r48
	  qpaddw,3	%r37, %r43, %b[6]
	  qpxor,4	%b[53], %r45, %r45
	  stqp,5	%r0, _f16s,_lts0hi 0x80, %r60
	}
	{
	  qpaddw,0	%r42, %r24, %r60
	  qplog_0x96,1	%r36, %b[83], %r32, %r36
	  stqp,2	%r0, _f16s,_lts0lo 0x20, %g28
	  qpxor,3	%b[52], %r39, %r39
	  qplog_0x96,4	%b[38], %b[84], %b[0], %b[10]
	  stqp,5	%r0, _f16s,_lts0hi 0x70, %r51
	}
	{
	  qpaddw,0	%r35, %r54, %g28
	  qpxor,1	%b[48], %r41, %r41
	  stqp,2	%r0, _f16s,_lts0lo 0xd0, %b[2]
	  qpaddw,3	%b[10], %r56, %r51
	  qpxor,4	%b[51], %r47, %r47
	  stqp,5	%r0, _f16s,_lts0hi 0x220, %r50
	}
	{
	  qpaddw,0	%r44, %r33, %b[2]
	  qpsrcw,1	%b[4], %r12, %b[4]
	  stqp,2	%r0, _f16s,_lts0lo 0x280, %r49
	  qpsrcw,3	%b[6], %r10, %b[6]
	  qplog_0x96,4	%b[56], %r58, %r39, %r58
	  stqp,5	%r0, _f16s,_lts0hi 0x2d0, %r52
	}
	{
	  qpaddw,0	%b[5], %r31, %b[11]
	  qpsrcw,1	%r60, %r12, %r60
	  stqp,2	%r0, _f16s,_lts0lo 0x270, %b[3]
	  qplog_0x96,3,sm	%b[61], %r61, %r45, %r61
	  qpsrcw,4	%r51, %r10, %r51
	}
	{
	  qpaddw,0	%r36, %r55, %b[12]
	  qpsrcw,1	%g28, %r12, %g28
	  qplog_0x96,3	%b[55], %r59, %r47, %r59
	  qpxor,4	%r58, %b[6], %b[6]
	}
	{
	  qpsrcw,0	%b[2], %r12, %b[2]
	  qpsrcw,1	%b[11], %r10, %b[11]
	  qplog_0x96,3	%b[54], %g29, %r41, %g29
	  qpxor,4	%r61, %r51, %r51
	}
	{
	  qpxor,0	%r14, %r60, %r60
	  qpsrcw,1	%b[12], %r10, %b[12]
	  qpaddw,3	%b[6], %r37, %b[13]
	  qpxor,4	%g26, %b[4], %b[4]
	}
	{
	  qpxor,0	%g27, %b[2], %b[2]
	  qpxor,1	%g31, %g28, %g28
	  qpaddw,3	%b[4], %r34, %b[14]
	  qpxor,4	%b[72], %r38, %r38
	}
	{
	  qpaddw,0	%r60, %r42, %b[15]
	  qpxor,1	%r59, %b[11], %b[11]
	  qpaddw,3	%r51, %b[10], %b[16]
	  qpxor,4	%b[68], %r46, %r46
	}
	{
	  qpaddw,0	%g28, %r35, %b[17]
	  qpxor,1	%g29, %b[12], %b[12]
	  qpxor,3	%b[67], %r40, %r40
	  qpxor,4	%b[62], %r48, %r48
	}
	{
	  qpaddw,0	%b[2], %r44, %b[18]
	  qpsrcw,1	%b[15], 0xe, %b[15]
	  qpsrcw,3	%b[14], 0xe, %b[14]
	  qpsrcw,4	%b[13], %r11, %b[13]
	}
	{
	  qpaddw,0	%b[11], %b[5], %b[19]
	  qpsrcw,1	%b[17], 0xe, %b[17]
	  qplog_0x96,3	%b[77], %r49, %r40, %r49
	  qplog_0x96,4,sm	%b[81], %r50, %r38, %r50
	}
	{
	  qpaddw,0	%b[12], %r36, %b[20]
	  qpsrcw,1	%b[18], 0xe, %b[18]
	  qpsrcw,3	%b[16], %r11, %b[16]
	  qplog_0x96,4	%b[78], %b[3], %r46, %b[3]
	}
	{
	  qplog_0x96,0	%b[73], %r52, %r48, %r52
	  qpsrcw,1	%b[19], %r11, %b[19]
	  qpxor,3	%r15, %b[14], %b[14]
	  qpxor,4	%r49, %b[13], %b[13]
	}
	{
	  qpxor,0	%g30, %b[17], %b[17]
	  qpxor,1	%r4, %b[15], %b[15]
	  qpaddw,3	%b[14], %r33, %b[21]
	  qpxor,4	%b[3], %b[16], %b[16]
	}
	{
	  qpxor,0	%g25, %b[18], %b[18]
	  qpsrcw,1	%b[20], %r11, %b[20]
	  qpaddw,3	%b[13], %b[6], %b[22]
	  qpsrcw,4	%b[21], %r10, %b[21]
	}
	{
	  qpaddw,0	%b[15], %r30, %b[23]
	  qpxor,1	%r52, %b[19], %b[19]
	  qpaddw,3	%b[16], %r51, %b[24]
	  qpsrcw,4	%b[22], %r12, %b[22]
	}
	{
	  qpaddw,0	%b[17], %r24, %b[25]
	  qpxor,1	%r50, %b[20], %b[20]
	  qpxor,3	%r60, %b[21], %r60
	  qpsrcw,4	%b[24], %r12, %b[21]
	}
	{
	  qpaddw,0	%b[18], %r54, %b[24]
	  qpsrcw,1	%b[23], %r10, %b[23]
	  qpaddw,3	%r60, %b[14], %b[26]
	  qpxor,4	%r43, %b[22], %b[22]
	}
	{
	  qpaddw,0	%b[19], %b[11], %b[27]
	  qpsrcw,1	%b[25], %r10, %b[25]
	  qpaddw,3	%b[22], %b[13], %b[28]
	  qpxor,4	%r56, %b[21], %b[21]
	}
	{
	  qpaddw,0	%b[20], %b[12], %b[29]
	  qpsrcw,1	%b[24], %r10, %b[24]
	  qpaddw,3	%b[21], %b[16], %b[30]
	  qpsrcw,4	%b[26], %r11, %b[26]
	}
	{
	  qpxor,0	%g28, %b[23], %g28
	  qpsrcw,1	%b[27], %r12, %b[23]
	  qpsrcw,3	%b[28], 0xe, %b[27]
	  qpsrcw,4	%b[30], 0xe, %b[28]
	}
	{
	  qpsrcw,0	%b[29], %r12, %b[25]
	  qpxor,1	%b[2], %b[25], %b[2]
	  qpxor,3	%r35, %b[26], %r35
	  qpxor,4	%r37, %b[27], %b[26]
	}
	{
	  qpaddw,0	%g28, %b[15], %b[24]
	  qpxor,1	%b[4], %b[24], %b[4]
	  qpaddw,3	%r35, %r60, %b[27]
	  qpxor,4	%b[10], %b[28], %b[28]
	}
	{
	  qpaddw,0	%b[2], %b[17], %b[29]
	  qpxor,1	%r31, %b[23], %b[23]
	  qpaddw,3	%b[26], %r51, %b[30]
	  qpsrcw,4	%b[27], %r12, %b[27]
	}
	{
	  qpaddw,0	%b[4], %b[18], %b[31]
	  qpxor,1	%r55, %b[25], %b[25]
	  qpaddw,3	%b[28], %b[12], %b[32]
	  qpsrcw,4	%b[30], %r10, %b[30]
	}
	{
	  qpaddw,0	%b[23], %b[19], %b[33]
	  qpsrcw,1	%b[24], %r11, %b[24]
	  qpxor,3	%r33, %b[27], %r33
	  qpsrcw,4	%b[32], %r10, %b[27]
	}
	{
	  qpaddw,0	%b[25], %b[20], %b[32]
	  qpsrcw,1	%b[29], %r11, %b[29]
	  qpaddw,3	%r33, %r35, %b[34]
	  qpxor,4	%b[22], %b[27], %b[22]
	}
	{
	  qpsrcw,0	%b[31], %r11, %b[27]
	  qpsrcw,1	%b[33], 0xe, %b[31]
	  qpaddw,3	%b[22], %b[28], %b[30]
	  qpxor,4	%b[23], %b[30], %b[23]
	}
	{
	  qpsrcw,0	%b[32], 0xe, %b[24]
	  qpxor,1	%r44, %b[24], %r44
	  qpaddw,3	%b[23], %b[26], %b[32]
	  qpsrcw,4	%b[34], 0xe, %b[33]
	}
	{
	  qpxor,0	%r42, %b[27], %r42
	  qpxor,1	%r34, %b[29], %r34
	  qpsrcw,3	%b[30], %r11, %b[27]
	  qpsrcw,4	%b[32], %r11, %b[29]
	}
	{
	  qpaddw,0	%r44, %g28, %b[30]
	  qpxor,1	%b[5], %b[31], %b[31]
	  qpxor,3	%b[14], %b[33], %b[14]
	  qpxor,4	%b[19], %b[27], %b[19]
	}
	{
	  qpaddw,0	%r34, %b[2], %b[27]
	  qpxor,1	%r36, %b[24], %b[24]
	  qpaddw,3	%b[14], %b[4], %b[32]
	  qpxor,4	%b[20], %b[29], %b[20]
	}
	{
	  qpaddw,0	%r42, %b[4], %b[29]
	  qpsrcw,1	%b[30], %r12, %b[30]
	  qpaddw,3	%b[19], %b[22], %b[33]
	  qpsrcw,4	%b[32], %r10, %b[32]
	}
	{
	  qpaddw,0	%b[31], %b[6], %b[34]
	  qpsrcw,1	%b[27], %r12, %b[27]
	  qpaddw,3	%b[20], %b[23], %b[35]
	  qpsrcw,4	%b[33], %r12, %b[33]
	}
	{
	  qpaddw,0	%b[24], %b[11], %b[36]
	  qpsrcw,1	%b[29], %r12, %b[29]
	  qpsrcw,3	%b[35], %r12, %b[35]
	  qpxor,4	%b[12], %b[33], %b[12]
	}
	{
	  qpxor,0	%r30, %b[30], %r30
	  qpsrcw,1	%b[34], %r10, %b[30]
	  qpaddw,3	%b[12], %b[19], %b[33]
	  qpxor,4	%r51, %b[35], %r51
	}
	{
	  qpsrcw,0	%b[36], %r10, %b[27]
	  qpxor,1	%r24, %b[27], %r24
	  qpaddw,3	%r51, %b[20], %b[34]
	  qpsrcw,4	%b[33], 0xe, %b[33]
	}
	{
	  qpaddw,0	%r30, %r44, %b[29]
	  qpxor,1	%r54, %b[29], %r54
	  qpsrcw,3	%b[34], 0xe, %b[34]
	  qpxor,4	%b[28], %b[33], %b[28]
	}
	{
	  qpaddw,0	%r24, %r34, %b[33]
	  qpxor,1	%b[25], %b[30], %b[25]
	  qpxor,3	%b[26], %b[34], %b[26]
	}
	{
	  qpaddw,0	%r54, %r42, %b[30]
	  qpxor,1	%b[21], %b[27], %b[21]
	  qpaddw,3	%b[26], %b[22], %b[27]
	  qpxor,4	%r30, %b[32], %r30
	}
	{
	  qpaddw,0	%b[25], %b[31], %b[32]
	  qpsrcw,1	%b[29], 0xe, %b[29]
	  qpaddw,3	%r30, %b[14], %b[34]
	  qpsrcw,4	%b[27], %r10, %b[27]
	}
	{
	  qpaddw,0	%b[21], %b[24], %b[35]
	  qpsrcw,1	%b[33], 0xe, %b[33]
	  qpsrcw,4	%b[34], %r11, %b[34]
	}
	{
	  qpsrcw,0	%b[30], 0xe, %b[30]
	  qpsrcw,1	%b[32], %r11, %b[32]
	  qpxor,4	%r34, %b[34], %r34
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[29]
	  qpxor,1	%b[15], %b[29], %b[15]
	  qpaddw,3	%r34, %r30, %b[34]
	}
	{
	  qpxor,0	%b[18], %b[30], %b[18]
	  qpxor,1	%b[17], %b[33], %b[17]
	  qpaddw,3	%b[28], %b[21], %b[30]
	  qpsrcw,4	%b[34], %r12, %b[33]
	}
	{
	  qpaddw,0	%b[15], %r60, %b[34]
	  qpxor,1	%b[16], %b[32], %b[16]
	  qpsrcw,3	%b[30], %r10, %b[30]
	  qpxor,4	%b[4], %b[33], %b[4]
	}
	{
	  qpaddw,0	%b[17], %g28, %b[32]
	  qpxor,1	%b[13], %b[29], %b[13]
	  qpaddw,3	%b[4], %r34, %b[29]
	  qpxor,4	%r51, %b[30], %r51
	}
	{
	  qpaddw,0	%b[18], %b[2], %b[30]
	  qpsrcw,1	%b[34], %r10, %b[33]
	  qpaddw,3	%r51, %b[28], %b[34]
	  qpsrcw,4	%b[29], 0xe, %b[29]
	}
	{
	  qpaddw,0	%b[16], %b[25], %b[35]
	  qpsrcw,1	%b[32], %r10, %b[32]
	  qpsrcw,3	%b[34], %r11, %b[34]
	  qpxor,4	%b[14], %b[29], %b[14]
	}
	{
	  qpaddw,0	%b[13], %b[21], %b[29]
	  qpsrcw,1	%b[30], %r10, %b[30]
	  qpxor,3	%b[16], %b[34], %b[34]
	}
	{
	  qpsrcw,0	%b[35], %r12, %b[33]
	  qpxor,1	%r24, %b[33], %r24
	  qpaddw,3	%b[34], %r51, %b[35]
	}
	{
	  qpsrcw,0	%b[29], %r12, %b[29]
	  qpxor,1	%r54, %b[32], %r54
	  qpsrcw,3	%b[35], %r12, %b[32]
	}
	{
	  qpaddw,0	%r24, %b[15], %b[30]
	  qpxor,1	%r33, %b[30], %r33
	  qpxor,3	%b[21], %b[32], %b[21]
	}
	{
	  qpaddw,0	%r54, %b[17], %b[32]
	  qpxor,1	%b[6], %b[33], %b[6]
	  qpaddw,3	%b[21], %b[34], %b[33]
	}
	{
	  qpaddw,0	%r33, %b[18], %b[35]
	  qpxor,1	%b[11], %b[29], %b[11]
	  qpsrcw,3	%b[33], 0xe, %b[29]
	}
	{
	  qpaddw,0	%b[6], %b[16], %b[16]
	  qpsrcw,1	%b[30], %r11, %b[30]
	  qpxor,3	%b[28], %b[29], %b[28]
	}
	{
	  qpaddw,0	%b[11], %b[13], %b[29]
	  qpsrcw,1	%b[32], %r11, %b[32]
	  qpaddw,3	%b[14], %r33, %b[33]
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[35]
	  qpsrcw,1	%b[16], 0xe, %b[16]
	  qpxor,3	%b[6], %b[27], %b[6]
	  qpsrcw,4	%b[33], %r10, %b[27]
	}
	{
	  qpsrcw,0	%b[29], 0xe, %b[29]
	  qpxor,1	%r42, %b[30], %r42
	  qpaddw,3	%b[6], %b[26], %b[30]
	}
	{
	  qpxor,0	%r44, %b[35], %r44
	  qpxor,1	%r35, %b[32], %r35
	  qpsrcw,3	%b[30], %r11, %b[30]
	}
	{
	  qpaddw,0	%r42, %r24, %b[32]
	  qpxor,1	%b[31], %b[16], %b[16]
	  qpxor,3	%b[13], %b[30], %b[13]
	}
	{
	  qpaddw,0	%r35, %r54, %b[30]
	  qpxor,1	%b[24], %b[29], %b[24]
	  qpaddw,3	%b[13], %b[6], %b[29]
	}
	{
	  qpaddw,0	%r44, %r33, %b[31]
	  qpsrcw,1	%b[32], %r12, %b[32]
	  qpsrcw,3	%b[29], %r12, %b[29]
	}
	{
	  qpaddw,0	%b[16], %b[23], %b[33]
	  qpsrcw,1	%b[30], %r12, %b[30]
	  qpxor,3	%b[22], %b[29], %b[22]
	}
	{
	  qpaddw,0	%b[24], %b[25], %b[29]
	  qpsrcw,1	%b[31], %r12, %b[31]
	  qpaddw,3	%b[22], %b[13], %b[35]
	}
	{
	  qpxor,0	%r60, %b[32], %r60
	  qpsrcw,1	%b[33], %r10, %b[32]
	  qpsrcw,3	%b[35], 0xe, %b[33]
	}
	{
	  qpsrcw,0	%b[29], %r10, %b[29]
	  qpxor,1	%g28, %b[30], %g28
	  qpxor,3	%b[26], %b[33], %b[26]
	}
	{
	  qpaddw,0	%r60, %r42, %b[30]
	  qpxor,1	%b[2], %b[31], %b[2]
	  qpaddw,3	%b[26], %r51, %b[31]
	}
	{
	  qpaddw,0	%g28, %r35, %b[33]
	  qpxor,1	%b[11], %b[32], %b[11]
	  qpsrcw,3	%b[31], %r10, %b[31]
	}
	{
	  qpaddw,0	%b[2], %r44, %b[32]
	  qpxor,1	%b[12], %b[29], %b[12]
	  qpxor,3	%r60, %b[27], %r60
	}
	{
	  qpaddw,0	%b[11], %b[16], %b[27]
	  qpsrcw,1	%b[30], 0xe, %b[29]
	  qpaddw,3	%r60, %b[14], %b[30]
	}
	{
	  qpaddw,0	%b[12], %b[24], %b[35]
	  qpsrcw,1	%b[33], 0xe, %b[33]
	  qpsrcw,4	%b[30], %r11, %b[30]
	}
	{
	  qpsrcw,0	%b[32], 0xe, %b[32]
	  qpsrcw,1	%b[27], %r11, %b[27]
	  qpxor,4	%r35, %b[30], %r35
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[29]
	  qpxor,1	%b[15], %b[29], %b[15]
	  qpaddw,3	%r35, %r60, %b[30]
	}
	{
	  qpxor,0	%b[18], %b[32], %b[18]
	  qpxor,1	%b[17], %b[33], %b[17]
	  qpaddw,3	%b[28], %b[12], %b[32]
	  qpsrcw,4	%b[30], %r12, %b[30]
	}
	{
	  qpaddw,0	%b[15], %r30, %b[33]
	  qpxor,1	%b[19], %b[27], %b[19]
	  qpsrcw,3	%b[32], %r10, %b[27]
	  qpxor,4	%r33, %b[30], %r33
	}
	{
	  qpaddw,0	%b[17], %r24, %b[30]
	  qpxor,1	%b[20], %b[29], %b[20]
	  qpaddw,3	%r33, %r35, %b[29]
	  qpxor,4	%b[22], %b[27], %b[22]
	}
	{
	  qpaddw,0	%b[18], %r54, %b[27]
	  qpsrcw,1	%b[33], %r10, %b[32]
	  qpaddw,3	%b[22], %b[28], %b[33]
	  qpsrcw,4	%b[29], 0xe, %b[29]
	}
	{
	  qpaddw,0	%b[19], %b[11], %b[35]
	  qpsrcw,1	%b[30], %r10, %b[30]
	  qpsrcw,3	%b[33], %r11, %b[33]
	  qpxor,4	%b[14], %b[29], %b[14]
	}
	{
	  qpaddw,0	%b[20], %b[12], %b[29]
	  qpsrcw,1	%b[27], %r10, %b[27]
	  qpxor,3	%b[19], %b[33], %b[33]
	}
	{
	  qpsrcw,0	%b[35], %r12, %b[32]
	  qpxor,1	%g28, %b[32], %g28
	  qpaddw,3	%b[33], %b[22], %b[35]
	}
	{
	  qpsrcw,0	%b[29], %r12, %b[29]
	  qpxor,1	%b[2], %b[30], %b[2]
	  qpsrcw,3	%b[35], %r12, %b[30]
	}
	{
	  qpaddw,0	%g28, %b[15], %b[27]
	  qpxor,1	%b[4], %b[27], %b[4]
	  qpxor,3	%b[12], %b[30], %b[12]
	}
	{
	  qpaddw,0	%b[2], %b[17], %b[30]
	  qpxor,1	%b[23], %b[32], %b[23]
	  qpaddw,3	%b[12], %b[33], %b[32]
	}
	{
	  qpaddw,0	%b[4], %b[18], %b[35]
	  qpxor,1	%b[25], %b[29], %b[25]
	  qpsrcw,3	%b[32], 0xe, %b[29]
	}
	{
	  qpaddw,0	%b[23], %b[19], %b[19]
	  qpsrcw,1	%b[27], %r11, %b[27]
	  qpxor,3	%b[28], %b[29], %b[28]
	}
	{
	  qpaddw,0	%b[25], %b[20], %b[29]
	  qpsrcw,1	%b[30], %r11, %b[30]
	  qpaddw,3	%b[14], %b[4], %b[32]
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[35]
	  qpsrcw,1	%b[19], 0xe, %b[19]
	  qpxor,3	%b[23], %b[31], %b[23]
	  qpsrcw,4	%b[32], %r10, %b[31]
	}
	{
	  qpsrcw,0	%b[29], 0xe, %b[27]
	  qpxor,1	%r44, %b[27], %r44
	  qpaddw,3	%b[23], %b[26], %b[29]
	}
	{
	  qpxor,0	%r42, %b[35], %r42
	  qpxor,1	%r34, %b[30], %r34
	  qpsrcw,3	%b[29], %r11, %b[29]
	}
	{
	  qpaddw,0	%r44, %g28, %b[30]
	  qpxor,1	%b[16], %b[19], %b[16]
	  qpxor,3	%b[20], %b[29], %b[19]
	}
	{
	  qpaddw,0	%r34, %b[2], %b[20]
	  qpxor,1	%b[24], %b[27], %b[24]
	  qpaddw,3	%b[19], %b[23], %b[27]
	}
	{
	  qpaddw,0	%r42, %b[4], %b[29]
	  qpsrcw,1	%b[30], %r12, %b[30]
	  qpsrcw,3	%b[27], %r12, %b[27]
	}
	{
	  qpaddw,0	%b[16], %b[6], %b[32]
	  qpsrcw,1	%b[20], %r12, %b[20]
	  qpxor,3	%r51, %b[27], %r51
	}
	{
	  qpaddw,0	%b[24], %b[11], %b[27]
	  qpsrcw,1	%b[29], %r12, %b[29]
	  qpaddw,3	%r51, %b[19], %b[35]
	}
	{
	  qpxor,0	%r30, %b[30], %r30
	  qpsrcw,1	%b[32], %r10, %b[30]
	  qpsrcw,3	%b[35], 0xe, %b[32]
	}
	{
	  qpsrcw,0	%b[27], %r10, %b[20]
	  qpxor,1	%r24, %b[20], %r24
	  qpxor,3	%b[26], %b[32], %b[26]
	}
	{
	  qpaddw,0	%r30, %r44, %b[27]
	  qpxor,1	%r54, %b[29], %r54
	  qpaddw,3	%b[26], %b[22], %b[29]
	}
	{
	  qpaddw,0	%r24, %r34, %b[32]
	  qpxor,1	%b[25], %b[30], %b[25]
	  qpsrcw,3	%b[29], %r10, %b[29]
	}
	{
	  qpaddw,0	%r54, %r42, %b[30]
	  qpxor,1	%b[21], %b[20], %b[20]
	  qpxor,3	%r30, %b[31], %r30
	}
	{
	  qpaddw,0	%b[25], %b[16], %b[21]
	  qpsrcw,1	%b[27], 0xe, %b[27]
	  qpaddw,3	%r30, %b[14], %b[31]
	}
	{
	  qpaddw,0	%b[20], %b[24], %b[35]
	  qpsrcw,1	%b[32], 0xe, %b[32]
	  qpsrcw,4	%b[31], %r11, %b[31]
	}
	{
	  qpsrcw,0	%b[30], 0xe, %b[30]
	  qpsrcw,1	%b[21], %r11, %b[21]
	  qpxor,4	%r34, %b[31], %r34
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[27]
	  qpxor,1	%b[15], %b[27], %b[15]
	  qpaddw,3	%r34, %r30, %b[31]
	}
	{
	  qpxor,0	%b[18], %b[30], %b[18]
	  qpxor,1	%b[17], %b[32], %b[17]
	  qpaddw,3	%b[28], %b[20], %b[30]
	  qpsrcw,4	%b[31], %r12, %b[31]
	}
	{
	  qpaddw,0	%b[15], %r60, %b[32]
	  qpxor,1	%b[34], %b[21], %b[21]
	  qpsrcw,3	%b[30], %r10, %b[30]
	  qpxor,4	%b[4], %b[31], %b[4]
	}
	{
	  qpaddw,0	%b[17], %g28, %b[31]
	  qpxor,1	%b[13], %b[27], %b[13]
	  qpaddw,3	%b[4], %r34, %b[27]
	  qpxor,4	%r51, %b[30], %r51
	}
	{
	  qpaddw,0	%b[18], %b[2], %b[30]
	  qpsrcw,1	%b[32], %r10, %b[32]
	  qpaddw,3	%r51, %b[28], %b[34]
	  qpsrcw,4	%b[27], 0xe, %b[27]
	}
	{
	  qpaddw,0	%b[21], %b[25], %b[35]
	  qpsrcw,1	%b[31], %r10, %b[31]
	  qpsrcw,3	%b[34], %r11, %b[34]
	  qpxor,4	%b[14], %b[27], %b[14]
	}
	{
	  qpaddw,0	%b[13], %b[20], %b[27]
	  qpsrcw,1	%b[30], %r10, %b[30]
	  qpxor,3	%b[21], %b[34], %b[34]
	}
	{
	  qpsrcw,0	%b[35], %r12, %b[32]
	  qpxor,1	%r24, %b[32], %r24
	  qpaddw,3	%b[34], %r51, %b[35]
	}
	{
	  qpsrcw,0	%b[27], %r12, %b[27]
	  qpxor,1	%r54, %b[31], %r54
	  qpsrcw,3	%b[35], %r12, %b[31]
	}
	{
	  qpaddw,0	%r24, %b[15], %b[30]
	  qpxor,1	%r33, %b[30], %r33
	  qpxor,3	%b[20], %b[31], %b[20]
	}
	{
	  qpaddw,0	%r54, %b[17], %b[31]
	  qpxor,1	%b[6], %b[32], %b[6]
	  qpaddw,3	%b[20], %b[34], %b[32]
	}
	{
	  qpaddw,0	%r33, %b[18], %b[35]
	  qpxor,1	%b[11], %b[27], %b[11]
	  qpsrcw,3	%b[32], 0xe, %b[27]
	}
	{
	  qpaddw,0	%b[6], %b[21], %b[21]
	  qpsrcw,1	%b[30], %r11, %b[30]
	  qpxor,3	%b[28], %b[27], %b[27]
	}
	{
	  qpaddw,0	%b[11], %b[13], %b[28]
	  qpsrcw,1	%b[31], %r11, %b[31]
	  qpaddw,3	%b[14], %r33, %b[32]
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[35]
	  qpsrcw,1	%b[21], 0xe, %b[21]
	  qpxor,3	%b[6], %b[29], %b[6]
	  qpsrcw,4	%b[32], %r10, %b[29]
	}
	{
	  qpsrcw,0	%b[28], 0xe, %b[28]
	  qpxor,1	%r42, %b[30], %r42
	  qpaddw,3	%b[6], %b[26], %b[30]
	}
	{
	  qpxor,0	%r44, %b[35], %r44
	  qpxor,1	%r35, %b[31], %r35
	  qpsrcw,3	%b[30], %r11, %b[30]
	}
	{
	  qpaddw,0	%r42, %r24, %b[31]
	  qpxor,1	%b[16], %b[21], %b[16]
	  qpxor,3	%b[13], %b[30], %b[13]
	}
	{
	  qpaddw,0	%r35, %r54, %b[21]
	  qpxor,1	%b[24], %b[28], %b[24]
	  qpaddw,3	%b[13], %b[6], %b[28]
	}
	{
	  qpaddw,0	%r44, %r33, %b[30]
	  qpsrcw,1	%b[31], %r12, %b[31]
	  qpsrcw,3	%b[28], %r12, %b[28]
	}
	{
	  qpaddw,0	%b[16], %b[23], %b[32]
	  qpsrcw,1	%b[21], %r12, %b[21]
	  qpxor,3	%b[22], %b[28], %b[22]
	}
	{
	  qpaddw,0	%b[24], %b[25], %b[28]
	  qpsrcw,1	%b[30], %r12, %b[30]
	  qpaddw,3	%b[22], %b[13], %b[35]
	}
	{
	  qpxor,0	%r60, %b[31], %r60
	  qpsrcw,1	%b[32], %r10, %b[31]
	  qpsrcw,3	%b[35], 0xe, %b[32]
	}
	{
	  qpsrcw,0	%b[28], %r10, %b[21]
	  qpxor,1	%g28, %b[21], %g28
	  qpxor,3	%b[26], %b[32], %b[26]
	}
	{
	  qpaddw,0	%r60, %r42, %b[28]
	  qpxor,1	%b[2], %b[30], %b[2]
	  qpaddw,3	%b[26], %r51, %b[30]
	}
	{
	  qpaddw,0	%g28, %r35, %b[32]
	  qpxor,1	%b[11], %b[31], %b[11]
	  qpsrcw,3	%b[30], %r10, %b[30]
	}
	{
	  qpaddw,0	%b[2], %r44, %b[31]
	  qpxor,1	%b[12], %b[21], %b[12]
	  qpxor,3	%r60, %b[29], %r60
	}
	{
	  qpaddw,0	%b[11], %b[16], %b[21]
	  qpsrcw,1	%b[28], 0xe, %b[28]
	  qpaddw,3	%r60, %b[14], %b[29]
	}
	{
	  qpaddw,0	%b[12], %b[24], %b[35]
	  qpsrcw,1	%b[32], 0xe, %b[32]
	  qpsrcw,4	%b[29], %r11, %b[29]
	}
	{
	  qpsrcw,0	%b[31], 0xe, %b[31]
	  qpsrcw,1	%b[21], %r11, %b[21]
	  qpxor,4	%r35, %b[29], %r35
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[28]
	  qpxor,1	%b[15], %b[28], %b[15]
	  qpaddw,3	%r35, %r60, %b[29]
	}
	{
	  qpxor,0	%b[18], %b[31], %b[18]
	  qpxor,1	%b[17], %b[32], %b[17]
	  qpaddw,3	%b[27], %b[12], %b[31]
	  qpsrcw,4	%b[29], %r12, %b[29]
	}
	{
	  qpaddw,0	%b[15], %r30, %b[32]
	  qpxor,1	%b[33], %b[21], %b[21]
	  qpsrcw,3	%b[31], %r10, %b[31]
	  qpxor,4	%r33, %b[29], %r33
	}
	{
	  qpaddw,0	%b[17], %r24, %b[29]
	  qpxor,1	%b[19], %b[28], %b[19]
	  qpaddw,3	%r33, %r35, %b[28]
	  qpxor,4	%b[22], %b[31], %b[22]
	}
	{
	  qpaddw,0	%b[18], %r54, %b[31]
	  qpsrcw,1	%b[32], %r10, %b[32]
	  qpaddw,3	%b[22], %b[27], %b[33]
	  qpsrcw,4	%b[28], 0xe, %b[28]
	}
	{
	  qpaddw,0	%b[21], %b[11], %b[35]
	  qpsrcw,1	%b[29], %r10, %b[29]
	  qpsrcw,3	%b[33], %r11, %b[33]
	  qpxor,4	%b[14], %b[28], %b[14]
	}
	{
	  qpaddw,0	%b[19], %b[12], %b[28]
	  qpsrcw,1	%b[31], %r10, %b[31]
	  qpxor,3	%b[21], %b[33], %b[33]
	}
	{
	  qpsrcw,0	%b[35], %r12, %b[32]
	  qpxor,1	%g28, %b[32], %g28
	  qpaddw,3	%b[33], %b[22], %b[35]
	}
	{
	  qpsrcw,0	%b[28], %r12, %b[28]
	  qpxor,1	%b[2], %b[29], %b[2]
	  qpsrcw,3	%b[35], %r12, %b[29]
	}
	{
	  qpaddw,0	%g28, %b[15], %b[31]
	  qpxor,1	%b[4], %b[31], %b[4]
	  qpxor,3	%b[12], %b[29], %b[12]
	}
	{
	  qpaddw,0	%b[2], %b[17], %b[29]
	  qpxor,1	%b[23], %b[32], %b[23]
	  qpaddw,3	%b[12], %b[33], %b[32]
	}
	{
	  qpaddw,0	%b[4], %b[18], %b[35]
	  qpxor,1	%b[25], %b[28], %b[25]
	  qpsrcw,3	%b[32], 0xe, %b[28]
	}
	{
	  qpaddw,0	%b[23], %b[21], %b[21]
	  qpsrcw,1	%b[31], %r11, %b[31]
	  qpxor,3	%b[27], %b[28], %b[27]
	}
	{
	  qpaddw,0	%b[25], %b[19], %b[28]
	  qpsrcw,1	%b[29], %r11, %b[29]
	  qpaddw,3	%b[14], %b[4], %b[32]
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[35]
	  qpsrcw,1	%b[21], 0xe, %b[21]
	  qpxor,3	%b[23], %b[30], %b[23]
	  qpsrcw,4	%b[32], %r10, %b[30]
	}
	{
	  qpsrcw,0	%b[28], 0xe, %b[28]
	  qpxor,1	%r44, %b[31], %r44
	  qpaddw,3	%b[23], %b[26], %b[31]
	}
	{
	  qpxor,0	%r42, %b[35], %r42
	  qpxor,1	%r34, %b[29], %r34
	  qpsrcw,3	%b[31], %r11, %b[29]
	}
	{
	  qpaddw,0	%r44, %g28, %b[31]
	  qpxor,1	%b[16], %b[21], %b[16]
	  qpxor,3	%b[19], %b[29], %b[19]
	}
	{
	  qpaddw,0	%r34, %b[2], %b[21]
	  qpxor,1	%b[24], %b[28], %b[24]
	  qpaddw,3	%b[19], %b[23], %b[28]
	}
	{
	  qpaddw,0	%r42, %b[4], %b[29]
	  qpsrcw,1	%b[31], %r12, %b[31]
	  qpsrcw,3	%b[28], %r12, %b[28]
	}
	{
	  qpaddw,0	%b[16], %b[6], %b[32]
	  qpsrcw,1	%b[21], %r12, %b[21]
	  qpxor,3	%r51, %b[28], %r51
	}
	{
	  qpaddw,0	%b[24], %b[11], %b[28]
	  qpsrcw,1	%b[29], %r12, %b[29]
	  qpaddw,3	%r51, %b[19], %b[35]
	}
	{
	  qpxor,0	%r30, %b[31], %r30
	  qpsrcw,1	%b[32], %r10, %b[31]
	  qpsrcw,3	%b[35], 0xe, %b[32]
	}
	{
	  qpsrcw,0	%b[28], %r10, %b[21]
	  qpxor,1	%r24, %b[21], %r24
	  qpxor,3	%b[26], %b[32], %b[26]
	}
	{
	  qpaddw,0	%r30, %r44, %b[28]
	  qpxor,1	%r54, %b[29], %r54
	  qpaddw,3	%b[26], %b[22], %b[29]
	}
	{
	  qpaddw,0	%r24, %r34, %b[32]
	  qpxor,1	%b[25], %b[31], %b[25]
	  qpsrcw,3	%b[29], %r10, %b[29]
	}
	{
	  qpaddw,0	%r54, %r42, %b[31]
	  qpxor,1	%b[20], %b[21], %b[20]
	  qpxor,3	%r30, %b[30], %r30
	}
	{
	  qpaddw,0	%b[25], %b[16], %b[21]
	  qpsrcw,1	%b[28], 0xe, %b[28]
	  qpaddw,3	%r30, %b[14], %b[30]
	}
	{
	  qpaddw,0	%b[20], %b[24], %b[35]
	  qpsrcw,1	%b[32], 0xe, %b[32]
	  qpsrcw,4	%b[30], %r11, %b[30]
	}
	{
	  qpsrcw,0	%b[31], 0xe, %b[31]
	  qpsrcw,1	%b[21], %r11, %b[21]
	  qpxor,4	%r34, %b[30], %r34
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[28]
	  qpxor,1	%b[15], %b[28], %b[15]
	  qpaddw,3	%r34, %r30, %b[30]
	}
	{
	  qpxor,0	%b[18], %b[31], %b[18]
	  qpxor,1	%b[17], %b[32], %b[17]
	  qpaddw,3	%b[27], %b[20], %b[31]
	  qpsrcw,4	%b[30], %r12, %b[30]
	}
	{
	  qpaddw,0	%b[15], %r60, %b[32]
	  qpxor,1	%b[34], %b[21], %b[21]
	  qpsrcw,3	%b[31], %r10, %b[31]
	  qpxor,4	%b[4], %b[30], %b[4]
	}
	{
	  qpaddw,0	%b[17], %g28, %b[30]
	  qpxor,1	%b[13], %b[28], %b[13]
	  qpaddw,3	%b[4], %r34, %b[28]
	  qpxor,4	%r51, %b[31], %r51
	}
	{
	  qpaddw,0	%b[18], %b[2], %b[31]
	  qpsrcw,1	%b[32], %r10, %b[32]
	  qpaddw,3	%r51, %b[27], %b[34]
	  qpsrcw,4	%b[28], 0xe, %b[28]
	}
	{
	  qpaddw,0	%b[21], %b[25], %b[35]
	  qpsrcw,1	%b[30], %r10, %b[30]
	  qpsrcw,3	%b[34], %r11, %b[34]
	  qpxor,4	%b[14], %b[28], %b[14]
	}
	{
	  qpaddw,0	%b[13], %b[20], %b[28]
	  qpsrcw,1	%b[31], %r10, %b[31]
	  qpxor,3	%b[21], %b[34], %b[34]
	}
	{
	  qpsrcw,0	%b[35], %r12, %b[32]
	  qpxor,1	%r24, %b[32], %r24
	  qpaddw,3	%b[34], %r51, %b[35]
	}
	{
	  qpsrcw,0	%b[28], %r12, %b[28]
	  qpxor,1	%r54, %b[30], %r54
	  qpsrcw,3	%b[35], %r12, %b[30]
	}
	{
	  qpaddw,0	%r24, %b[15], %b[31]
	  qpxor,1	%r33, %b[31], %r33
	  qpxor,3	%b[20], %b[30], %b[20]
	}
	{
	  qpaddw,0	%r54, %b[17], %b[30]
	  qpxor,1	%b[6], %b[32], %b[6]
	  qpaddw,3	%b[20], %b[34], %b[32]
	}
	{
	  qpaddw,0	%r33, %b[18], %b[35]
	  qpxor,1	%b[11], %b[28], %b[11]
	  qpsrcw,3	%b[32], 0xe, %b[28]
	}
	{
	  qpaddw,0	%b[6], %b[21], %b[21]
	  qpsrcw,1	%b[31], %r11, %b[31]
	  qpxor,3	%b[27], %b[28], %b[27]
	}
	{
	  qpaddw,0	%b[11], %b[13], %b[28]
	  qpsrcw,1	%b[30], %r11, %b[30]
	  qpaddw,3	%b[14], %r33, %b[32]
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[35]
	  qpsrcw,1	%b[21], 0xe, %b[21]
	  qpxor,3	%b[6], %b[29], %b[6]
	  qpsrcw,4	%b[32], %r10, %b[29]
	}
	{
	  qpsrcw,0	%b[28], 0xe, %b[28]
	  qpxor,1	%r42, %b[31], %r42
	  qpaddw,3	%b[6], %b[26], %b[31]
	}
	{
	  qpxor,0	%r44, %b[35], %r44
	  qpxor,1	%r35, %b[30], %r35
	  qpsrcw,3	%b[31], %r11, %b[30]
	}
	{
	  qpaddw,0	%r42, %r24, %b[31]
	  qpxor,1	%b[16], %b[21], %b[16]
	  qpxor,3	%b[13], %b[30], %b[13]
	}
	{
	  qpaddw,0	%r35, %r54, %b[21]
	  qpxor,1	%b[24], %b[28], %b[24]
	  qpaddw,3	%b[13], %b[6], %b[28]
	}
	{
	  qpaddw,0	%r44, %r33, %b[30]
	  qpsrcw,1	%b[31], %r12, %b[31]
	  qpsrcw,3	%b[28], %r12, %b[28]
	}
	{
	  qpaddw,0	%b[16], %b[23], %b[32]
	  qpsrcw,1	%b[21], %r12, %b[21]
	  qpxor,3	%b[22], %b[28], %b[22]
	}
	{
	  qpaddw,0	%b[24], %b[25], %b[28]
	  qpsrcw,1	%b[30], %r12, %b[30]
	  qpaddw,3	%b[22], %b[13], %b[35]
	}
	{
	  qpxor,0	%r60, %b[31], %r60
	  qpsrcw,1	%b[32], %r10, %b[31]
	  qpsrcw,3	%b[35], 0xe, %b[32]
	}
	{
	  qpsrcw,0	%b[28], %r10, %b[21]
	  qpxor,1	%g28, %b[21], %g28
	  qpxor,3	%b[26], %b[32], %b[26]
	}
	{
	  qpaddw,0	%r60, %r42, %b[28]
	  qpxor,1	%b[2], %b[30], %b[2]
	  qpaddw,3	%b[26], %r51, %b[30]
	}
	{
	  qpaddw,0	%g28, %r35, %b[32]
	  qpxor,1	%b[11], %b[31], %b[11]
	  qpsrcw,3	%b[30], %r10, %b[30]
	}
	{
	  qpaddw,0	%b[2], %r44, %b[31]
	  qpxor,1	%b[12], %b[21], %b[12]
	  qpxor,3	%r60, %b[29], %r60
	}
	{
	  qpaddw,0	%b[11], %b[16], %b[21]
	  qpsrcw,1	%b[28], 0xe, %b[28]
	  qpaddw,3	%r60, %b[14], %b[29]
	}
	{
	  qpaddw,0	%b[12], %b[24], %b[35]
	  qpsrcw,1	%b[32], 0xe, %b[32]
	  qpaddw,3	%r14, %r60, %r14
	  qpsrcw,4	%b[29], %r11, %b[29]
	}
	{
	  qpsrcw,0	%b[31], 0xe, %b[31]
	  qpsrcw,1	%b[21], %r11, %b[21]
	  qpxor,3	%g24, %r14, %g24
	  qpxor,4	%r35, %b[29], %r35
	  stqp,5	0x10, %r1, %r14
	}
	{
	  qpsrcw,0	%b[35], %r11, %b[15]
	  qpxor,1	%b[15], %b[28], %r14
	  qpaddw,3	%r35, %r60, %r60
	}
	{
	  qpxor,0	%b[18], %b[31], %b[18]
	  qpxor,1	%b[17], %b[32], %b[17]
	  qpaddw,3	%b[27], %b[12], %b[28]
	  qpsrcw,4	%r60, %r12, %r60
	}
	{
	  qpaddw,0	%r14, %r30, %b[29]
	  qpxor,1	%b[33], %b[21], %b[21]
	  qpxor,3	%r33, %r60, %r33
	  qpsrcw,4	%b[28], %r10, %b[28]
	}
	{
	  qpaddw,0	%b[17], %r24, %r60
	  qpxor,1	%b[19], %b[15], %b[15]
	  qpaddw,3	%r33, %r35, %b[19]
	  qpxor,4	%b[22], %b[28], %b[22]
	}
	{
	  qpaddw,0	%b[18], %r54, %b[28]
	  qpsrcw,1	%b[29], %r10, %b[29]
	  qpaddw,3	%b[22], %b[27], %b[31]
	  qpsrcw,4	%b[19], 0xe, %b[19]
	}
	{
	  qpaddw,0	%b[21], %b[11], %b[32]
	  qpsrcw,1	%r60, %r10, %r60
	  qpxor,3	%b[14], %b[19], %b[14]
	  qpsrcw,4	%b[31], %r11, %b[31]
	}
	{
	  qpaddw,0	%b[15], %b[12], %b[19]
	  qpsrcw,1	%b[28], %r10, %b[28]
	  qpaddw,3	%r15, %b[14], %r15
	  qpxor,4	%b[21], %b[31], %b[14]
	}
	{
	  qpsrcw,0	%b[32], %r12, %b[29]
	  qpxor,1	%g28, %b[29], %g28
	  qpaddw,3	%b[14], %b[22], %b[31]
	  qpxor,4	%g16, %r15, %g16
	  stqp,5	%r1, 0x0, %r15
	}
	{
	  qpsrcw,0	%b[19], %r12, %r60
	  qpxor,1	%b[2], %r60, %r15
	  qpaddw,3	%r25, %r33, %r25
	  qpsrcw,4	%b[31], %r12, %r33
	}
	{
	  qpaddw,0	%g28, %r14, %b[4]
	  qpxor,1	%b[4], %b[28], %b[2]
	  qpxor,3	%b[12], %r33, %r33
	  qpxor,4	%r21, %r25, %r21
	  stqp,5	%r1, _f16s,_lts0lo 0x30, %r25
	}
	{
	  qpaddw,0	%r15, %b[17], %r25
	  qpxor,1	%b[23], %b[29], %b[12]
	  qpaddw,3	%r33, %b[14], %b[19]
	}
	{
	  qpaddw,0	%b[2], %b[18], %b[23]
	  qpxor,1	%b[25], %r60, %r60
	  qpaddw,3	%g31, %g28, %g31
	  qpsrcw,4	%b[19], 0xe, %b[19]
	}
	{
	  qpaddw,0	%b[12], %b[21], %b[21]
	  qpsrcw,1	%b[4], %r11, %b[4]
	  qpaddw,3	%g27, %r15, %g27
	  qpxor,4	%g22, %g31, %g22
	  stqp,5	%r1, _f16s,_lts0lo 0x60, %g31
	}
	{
	  qpaddw,0	%r60, %b[15], %g31
	  qpsrcw,1	%r25, %r11, %r25
	  qpaddw,3	%g26, %b[2], %g26
	  qpxor,4	%g20, %g27, %g20
	  stqp,5	%r1, _f16s,_lts0lo 0xb0, %g27
	}
	{
	  qpsrcw,0	%b[23], %r11, %g27
	  qpsrcw,1	%b[21], 0xe, %b[21]
	  qpxor,3	%g19, %g26, %g19
	  qpxor,4	%b[12], %b[30], %b[12]
	  stqp,5	%r1, _f16s,_lts0lo 0xc0, %g26
	}
	{
	  qpsrcw,0	%g31, 0xe, %g31
	  qpxor,1	%r44, %b[4], %g26
	  qpaddw,3	%b[12], %b[26], %r44
	  qpxor,4	%b[27], %b[19], %b[4]
	}
	{
	  qpxor,0	%r42, %g27, %g27
	  qpxor,1	%r34, %r25, %r25
	  qpaddw,3	%g16, %g19, %r42
	  qpsrcw,4	%r44, %r11, %r34
	}
	{
	  qpaddw,0	%g26, %g28, %g28
	  qpxor,1	%b[16], %b[21], %r44
	  qpsrcw,3	%r42, %r10, %r42
	  qpxor,4	%b[15], %r34, %r34
	}
	{
	  qpaddw,0	%r25, %r15, %r15
	  qpxor,1	%b[24], %g31, %g31
	  qpaddw,3	%r34, %b[12], %b[15]
	}
	{
	  qpaddw,0	%g27, %b[2], %b[2]
	  qpsrcw,1	%g28, %r12, %g28
	  qpaddw,3	%r53, %r35, %r35
	  qpsrcw,4	%b[15], %r12, %b[15]
	}
	{
	  qpaddw,0	%r44, %b[6], %r53
	  qpsrcw,1	%r15, %r12, %r15
	  qpaddw,3	%r63, %g26, %r63
	  qpxor,4	%r51, %b[15], %r51
	  stqp,5	%r1, _f16s,_lts0lo 0x20, %r35
	}
	{
	  qpaddw,0	%g31, %b[11], %b[15]
	  qpsrcw,1	%b[2], %r12, %b[2]
	  qpaddw,3	%r51, %r34, %b[16]
	  qpxor,4	%r29, %r35, %r29
	  stqp,5	%r1, _f16s,_lts0lo 0x70, %r63
	}
	{
	  qpsrcw,0	%r53, %r10, %r30
	  qpxor,1	%r30, %g28, %g28
	  qpaddw,3	%r17, %r25, %r17
	  qpsrcw,4	%b[16], 0xe, %r35
	}
	{
	  qpsrcw,0	%b[15], %r10, %r24
	  qpxor,1	%r24, %r15, %r15
	  qpaddw,3	%r62, %g27, %r53
	  qpxor,4	%r28, %r63, %r28
	  stqp,5	%r1, _f16s,_lts0lo 0x80, %r17
	}
	{
	  qpaddw,0	%g28, %g26, %g26
	  qpxor,1	%r54, %b[2], %r54
	  qpxor,3	%b[26], %r35, %r27
	  qpxor,4	%r27, %r17, %r17
	  stqp,5	%r1, _f16s,_lts0lo 0xd0, %r53
	}
	{
	  qpaddw,0	%r15, %r25, %r25
	  qpxor,1	%r60, %r30, %r30
	  qpaddw,3	%r43, %b[22], %r35
	  qpxor,4	%r26, %r53, %r26
	}
	{
	  qpaddw,0	%r54, %g27, %g27
	  qpxor,1	%b[20], %r24, %r24
	  qpaddw,3	%r18, %g28, %g28
	  qpxor,4	%b[9], %r35, %r18
	  stqp,5	%r1, _f16s,_lts0lo 0x2c0, %r35
	}
	{
	  qpaddw,0	%r30, %r44, %r35
	  qpsrcw,1	%g26, 0xe, %g26
	  qpaddw,3	%r23, %r15, %r15
	  qpxor,4	%r20, %g28, %r20
	  stqp,5	%r1, _f16s,_lts0lo 0x40, %g28
	}
	{
	  qpaddw,0	%r24, %g31, %g28
	  qpsrcw,1	%r25, 0xe, %r23
	  qpaddw,3	%r22, %r54, %r22
	  qpxor,4	%r19, %r15, %r19
	  stqp,5	%r1, _f16s,_lts0lo 0x90, %r15
	}
	{
	  qpsrcw,0	%g27, 0xe, %g27
	  qpsrcw,1	%r35, %r11, %r15
	  qpxor,3	%r20, %r42, %r25
	  qpxor,4	%r16, %r22, %r16
	  stqp,5	%r1, _f16s,_lts0lo 0xe0, %r22
	}
	{
	  qpsrcw,0	%g28, %r11, %g28
	  qpxor,1	%r14, %g26, %g26
	  qpaddw,3	%r25, %g16, %r14
	}
	{
	  qpxor,0	%b[18], %g27, %g27
	  qpxor,1	%b[17], %r23, %r22
	  qpaddw,3	%r31, %b[12], %r23
	  qpsrcw,4	%r14, %r11, %r14
	}
	{
	  qpaddw,0	%r4, %g26, %g26
	  qpxor,1	%b[34], %r15, %r4
	  qpaddw,3	%b[10], %b[4], %r15
	  qpxor,4	%r17, %r14, %r14
	  stqp,5	%r1, _f16s,_lts0lo 0x210, %r23
	}
	{
	  qpaddw,0	%g30, %r22, %g30
	  qpxor,1	%b[13], %g28, %g28
	  stqp,2	%r1, _f16s,_lts0lo 0x50, %g26
	  qpaddw,3	%r37, %r27, %r22
	  qpxor,4	%r57, %r23, %r23
	  stqp,5	%r1, _f16s,_lts0hi 0x2f0, %r15
	}
	{
	  qpaddw,0	%g25, %g27, %g25
	  qpxor,1	%g23, %g26, %g23
	  stqp,2	%r1, _f16s,_lts0lo 0xa0, %g30
	  qpaddw,3	%r55, %r30, %g26
	  qpxor,4	%b[0], %r15, %g27
	  stqp,5	%r1, _f16s,_lts0hi 0x200, %r22
	}
	{
	  qpaddw,0	%r4, %r30, %r15
	  qpxor,1	%g21, %g30, %g21
	  stqp,2	%r1, _f16s,_lts0lo 0xf0, %g25
	  qpaddw,3	%r56, %r24, %g30
	  qpxor,4	%g17, %r22, %g17
	  stqp,5	%r1, _f16s,_lts0hi 0x260, %g26
	}
	{
	  qpaddw,0	%g28, %r24, %r22
	  qpxor,1	%g18, %g25, %g18
	  qpaddw,3	%r14, %r25, %g25
	  qpxor,4	%b[8], %g26, %g26
	  stqp,5	%r1, _f16s,_lts0lo 0x2b0, %g30
	}
	{
	  qpaddw,0	%g23, %g24, %r24
	  qpsrcw,1	%r15, %r12, %r15
	  qpaddw,3	%g29, %r33, %g29
	  qpxor,4	%b[1], %g30, %g30
	}
	{
	  qpaddw,0	%g21, %g22, %r27
	  qpsrcw,1	%r22, %r12, %r22
	  qpaddw,3	%r61, %r51, %r30
	  qpsrcw,4	%g25, %r12, %g25
	  stqp,5	%r1, _f16s,_lts0lo 0x2e0, %g29
	}
	{
	  qpaddw,0	%g18, %g20, %r31
	  qpsrcw,1	%r24, %r10, %r24
	  qpaddw,3	%g17, %r18, %r33
	  qpxor,4	%r41, %g29, %g29
	  stqp,5	%r1, _f16s,_lts0lo 0x230, %r30
	}
	{
	  qpsrcw,0	%r27, %r10, %r27
	  qpxor,1	%b[6], %r15, %r15
	  qpaddw,3	%g27, %g30, %r35
	  qpxor,4	%r45, %r30, %r30
	}
	{
	  qpsrcw,0	%r31, %r10, %r31
	  qpxor,1	%b[11], %r22, %r22
	  qpsrcw,3	%r33, %r10, %r33
	  qpxor,4	%g19, %g25, %g25
	}
	{
	  qpaddw,0	%r15, %r4, %r37
	  qpxor,1	%r19, %r24, %r24
	  qpaddw,3	%g25, %r14, %r41
	  qpsrcw,4	%r35, %r10, %r35
	}
	{
	  qpaddw,0	%r22, %g28, %r42
	  qpxor,1	%r16, %r27, %r27
	  qpaddw,3	%r52, %b[14], %r43
	  qpxor,4	%r30, %r35, %r35
	}
	{
	  qpaddw,0	%r24, %g23, %r45
	  qpxor,1	%r21, %r31, %r31
	  qpaddw,3	%r58, %r15, %r15
	  qpsrcw,4	%r41, 0xe, %r41
	  stqp,5	%r1, _f16s,_lts0lo 0x2d0, %r43
	}
	{
	  qpaddw,0	%r27, %g21, %r51
	  qpsrcw,1	%r37, 0xe, %r37
	  qpaddw,3	%r59, %r22, %r22
	  qpxor,4	%r39, %r15, %r39
	  stqp,5	%r1, _f16s,_lts0lo 0x240, %r15
	}
	{
	  qpaddw,0	%r31, %g18, %r15
	  qpsrcw,1	%r42, 0xe, %r42
	  qpxor,3	%r39, %r33, %r33
	  qpxor,4	%r47, %r22, %r47
	  stqp,5	%r1, _f16s,_lts0lo 0x290, %r22
	}
	{
	  qpsrcw,0	%r51, %r11, %r45
	  qpsrcw,1	%r45, %r11, %r22
	  qpaddw,3	%r50, %r34, %r34
	  qpxor,4	%r48, %r43, %r43
	}
	{
	  qpsrcw,0	%r15, %r11, %r15
	  qpxor,1	%r44, %r37, %r37
	  qpaddw,3	%b[3], %r4, %r4
	  qpxor,4	%g16, %r41, %r41
	  stqp,5	%r1, _f16s,_lts0lo 0x220, %r34
	}
	{
	  qpaddw,0	%b[5], %r37, %r37
	  qpxor,1	%g31, %r42, %g31
	  qpaddw,3	%r49, %g28, %g28
	  qpxor,4	%r38, %r34, %r34
	  stqp,5	%r1, _f16s,_lts0lo 0x270, %r4
	}
	{
	  qpaddw,0	%r36, %g31, %g31
	  qpxor,1	%r26, %r22, %r22
	  stqp,2	%r1, _f16s,_lts0lo 0x250, %r37
	  qpaddw,3	%r35, %g27, %r36
	  qpxor,4	%r46, %r4, %r4
	  stqp,5	%r1, _f16s,_lts0hi 0x280, %g28
	}
	{
	  qpxor,0	%r28, %r15, %r15
	  qpxor,1	%r29, %r45, %r38
	  stqp,2	%r1, _f16s,_lts0lo 0x2a0, %g31
	  qpaddw,3	%r33, %g17, %r42
	  qpxor,4	%r40, %g28, %g28
	}
	{
	  qpaddw,0	%r22, %r24, %r40
	  qpxor,1	%b[7], %r37, %r37
	  qpsrcw,3	%r42, %r11, %r42
	  qpsrcw,4	%r36, %r11, %r36
	}
	{
	  qpaddw,0	%r38, %r27, %r44
	  qpxor,1	%r32, %g31, %g31
	  qpaddw,3	%r41, %r31, %r32
	  qpxor,4	%r4, %r36, %r36
	}
	{
	  qpaddw,0	%r15, %r31, %r45
	  qpsrcw,1	%r40, %r12, %r40
	  qpaddw,3	%r36, %r35, %r46
	  qpxor,4	%g28, %r42, %r42
	}
	{
	  qpaddw,0	%r37, %r23, %r48
	  qpsrcw,1	%r44, %r12, %r44
	  qpaddw,3	%r42, %r33, %r49
	  qpsrcw,4	%r32, %r10, %r32
	}
	{
	  qpaddw,0	%g31, %g26, %r50
	  qpsrcw,1	%r45, %r12, %r45
	  qpsrcw,3	%r46, %r12, %r46
	  qpsrcw,4	%r49, %r12, %r49
	}
	{
	  qpxor,0	%g24, %r40, %r40
	  qpsrcw,1	%r48, %r10, %r48
	  qpxor,3	%g30, %r46, %r46
	  qpxor,4	%r18, %r49, %r49
	}
	{
	  qpsrcw,0	%r50, %r10, %r50
	  qpxor,1	%g22, %r44, %r44
	  qpaddw,3	%r46, %r36, %r51
	}
	{
	  qpaddw,0	%r40, %r22, %r52
	  qpxor,1	%g20, %r45, %r45
	  qpaddw,3	%r49, %r42, %r53
	  qpsrcw,4	%r51, 0xe, %r51
	}
	{
	  qpaddw,0	%r44, %r38, %r54
	  qpxor,1	%r47, %r48, %r48
	  qpsrcw,3	%r53, 0xe, %r53
	  qpxor,4	%g27, %r51, %r51
	}
	{
	  qpaddw,0	%r45, %r15, %r55
	  qpxor,1	%g29, %r50, %r50
	  qpxor,3	%r40, %r32, %r32
	  qpxor,4	%g17, %r53, %r40
	}
	{
	  qpaddw,0	%r48, %r37, %r53
	  qpsrcw,1	%r52, 0xe, %r52
	  qpaddw,3	%r32, %r41, %r56
	}
	{
	  qpaddw,0	%r50, %g31, %r57
	  qpsrcw,1	%r54, 0xe, %r54
	  qpaddw,3	%r40, %r35, %r58
	  qpsrcw,4	%r56, %r11, %r56
	}
	{
	  qpsrcw,0	%r55, 0xe, %r55
	  qpsrcw,1	%r53, %r11, %r53
	  qpsrcw,3	%r58, %r10, %r56
	  qpxor,4	%r38, %r56, %r38
	}
	{
	  qpsrcw,0	%r57, %r11, %r57
	  qpxor,1	%g23, %r52, %r52
	  qpaddw,3	%r38, %r32, %r58
	}
	{
	  qpxor,0	%g18, %r55, %r55
	  qpxor,1	%g21, %r54, %r54
	  qpaddw,3	%r51, %r50, %r59
	  qpsrcw,4	%r58, %r12, %r58
	}
	{
	  qpaddw,0	%r52, %r25, %r60
	  qpxor,1	%r43, %r53, %r53
	  qpsrcw,3	%r59, %r10, %r59
	  qpxor,4	%r31, %r58, %r31
	}
	{
	  qpaddw,0	%r54, %r24, %r58
	  qpxor,1	%r34, %r57, %r57
	  qpaddw,3	%r31, %r38, %r61
	  qpxor,4	%r49, %r59, %r49
	}
	{
	  qpaddw,0	%r55, %r27, %r59
	  qpsrcw,1	%r60, %r10, %r60
	  qpaddw,3	%r49, %r51, %r62
	  qpsrcw,4	%r61, 0xe, %r61
	}
	{
	  qpaddw,0	%r53, %r48, %r63
	  qpsrcw,1	%r58, %r10, %r58
	  qpsrcw,3	%r62, %r11, %r62
	  qpxor,4	%r41, %r61, %r41
	}
	{
	  qpaddw,0	%r57, %r50, %r61
	  qpsrcw,1	%r59, %r10, %r59
	  qpxor,3	%r53, %r62, %r62
	}
	{
	  qpsrcw,0	%r63, %r12, %r60
	  qpxor,1	%r44, %r60, %r44
	  qpaddw,3	%r62, %r49, %r63
	}
	{
	  qpsrcw,0	%r61, %r12, %r58
	  qpxor,1	%r45, %r58, %r45
	  qpsrcw,3	%r63, %r12, %r61
	}
	{
	  qpaddw,0	%r44, %r52, %r59
	  qpxor,1	%g25, %r59, %g25
	  qpxor,3	%r50, %r61, %r50
	}
	{
	  qpaddw,0	%r45, %r54, %r61
	  qpxor,1	%r23, %r60, %r60
	  qpaddw,3	%r50, %r62, %r63
	}
	{
	  qpaddw,0	%g25, %r55, %b[0]
	  qpxor,1	%g26, %r58, %r58
	  qpsrcw,3	%r63, 0xe, %r63
	}
	{
	  qpaddw,0	%r60, %r53, %r53
	  qpsrcw,1	%r59, %r11, %r59
	  qpxor,3	%r51, %r63, %r51
	}
	{
	  qpaddw,0	%r58, %r57, %r63
	  qpsrcw,1	%r61, %r11, %r61
	  qpaddw,3	%r41, %g25, %b[1]
	}
	{
	  qpsrcw,0	%b[0], %r11, %b[0]
	  qpsrcw,1	%r53, 0xe, %r53
	  qpxor,3	%r60, %r56, %r56
	  qpsrcw,4	%b[1], %r10, %r60
	}
	{
	  qpsrcw,0	%r63, 0xe, %r59
	  qpxor,1	%r15, %r59, %r15
	  qpaddw,3	%r56, %r40, %r63
	}
	{
	  qpxor,0	%r22, %b[0], %r22
	  qpxor,1	%r14, %r61, %r14
	  qpsrcw,3	%r63, %r11, %r61
	}
	{
	  qpaddw,0	%r15, %r44, %r63
	  qpxor,1	%r37, %r53, %r53
	  qpxor,3	%r57, %r61, %r57
	}
	{
	  qpaddw,0	%r14, %r45, %r61
	  qpxor,1	%g31, %r59, %r59
	  qpaddw,3	%r57, %r56, %b[0]
	}
	{
	  qpaddw,0	%r22, %g25, %b[1]
	  qpsrcw,1	%r63, %r12, %r63
	  qpsrcw,3	%b[0], %r12, %b[0]
	}
	{
	  qpaddw,0	%r53, %r33, %b[2]
	  qpsrcw,1	%r61, %r12, %r61
	  qpxor,3	%r35, %b[0], %r35
	}
	{
	  qpaddw,0	%r59, %r48, %b[0]
	  qpsrcw,1	%b[1], %r12, %b[1]
	  qpaddw,3	%r35, %r57, %b[3]
	}
	{
	  qpxor,0	%r25, %r63, %r25
	  qpsrcw,1	%b[2], %r10, %r63
	  qpsrcw,3	%b[3], 0xe, %b[2]
	}
	{
	  qpsrcw,0	%b[0], %r10, %r61
	  qpxor,1	%r24, %r61, %r24
	  qpxor,3	%r40, %b[2], %r40
	}
	{
	  qpaddw,0	%r25, %r15, %b[0]
	  qpxor,1	%r27, %b[1], %r27
	  qpaddw,3	%r40, %r49, %b[1]
	}
	{
	  qpaddw,0	%r24, %r14, %b[2]
	  qpxor,1	%r58, %r63, %r58
	  qpsrcw,3	%b[1], %r10, %r63
	}
	{
	  qpaddw,0	%r27, %r22, %b[1]
	  qpxor,1	%r46, %r61, %r46
	  qpxor,3	%r25, %r60, %r25
	}
	{
	  qpaddw,0	%r58, %r53, %r60
	  qpsrcw,1	%b[0], 0xe, %r61
	  qpaddw,3	%r25, %r41, %b[0]
	}
	{
	  qpaddw,0	%r46, %r59, %b[3]
	  qpsrcw,1	%b[2], 0xe, %b[2]
	  qpsrcw,4	%b[0], %r11, %b[0]
	}
	{
	  qpsrcw,0	%b[1], 0xe, %b[1]
	  qpsrcw,1	%r60, %r11, %r60
	  qpxor,4	%r14, %b[0], %r14
	}
	{
	  qpsrcw,0	%b[3], %r11, %r61
	  qpxor,1	%r52, %r61, %r52
	  qpaddw,3	%r14, %r25, %b[0]
	}
	{
	  qpxor,0	%r55, %b[1], %r55
	  qpxor,1	%r54, %b[2], %r54
	  qpaddw,3	%r51, %r46, %b[1]
	  qpsrcw,4	%b[0], %r12, %b[0]
	}
	{
	  qpaddw,0	%r52, %r32, %b[2]
	  qpxor,1	%r36, %r60, %r36
	  qpsrcw,3	%b[1], %r10, %r60
	  qpxor,4	%g25, %b[0], %g25
	}
	{
	  qpaddw,0	%r54, %r44, %b[0]
	  qpxor,1	%r42, %r61, %r42
	  qpaddw,3	%g25, %r14, %r61
	  qpxor,4	%r35, %r60, %r35
	}
	{
	  qpaddw,0	%r55, %r45, %r60
	  qpsrcw,1	%b[2], %r10, %b[1]
	  qpaddw,3	%r35, %r51, %b[2]
	  qpsrcw,4	%r61, 0xe, %r61
	}
	{
	  qpaddw,0	%r36, %r58, %b[3]
	  qpsrcw,1	%b[0], %r10, %b[0]
	  qpsrcw,3	%b[2], %r11, %b[2]
	  qpxor,4	%r41, %r61, %r41
	}
	{
	  qpaddw,0	%r42, %r46, %r61
	  qpsrcw,1	%r60, %r10, %r60
	  qpxor,3	%r36, %b[2], %b[2]
	}
	{
	  qpsrcw,0	%b[3], %r12, %b[1]
	  qpxor,1	%r24, %b[1], %r24
	  qpaddw,3	%b[2], %r35, %b[3]
	}
	{
	  qpsrcw,0	%r61, %r12, %r61
	  qpxor,1	%r27, %b[0], %r27
	  qpsrcw,3	%b[3], %r12, %b[0]
	}
	{
	  qpaddw,0	%r24, %r52, %r60
	  qpxor,1	%r31, %r60, %r31
	  qpxor,3	%r46, %b[0], %r46
	}
	{
	  qpaddw,0	%r27, %r54, %b[0]
	  qpxor,1	%r33, %b[1], %r33
	  qpaddw,3	%r46, %b[2], %b[1]
	}
	{
	  qpaddw,0	%r31, %r55, %b[3]
	  qpxor,1	%r48, %r61, %r48
	  qpsrcw,3	%b[1], 0xe, %r61
	}
	{
	  qpaddw,0	%r33, %r36, %r36
	  qpsrcw,1	%r60, %r11, %r60
	  qpxor,3	%r51, %r61, %r51
	}
	{
	  qpaddw,0	%r48, %r42, %r61
	  qpsrcw,1	%b[0], %r11, %b[0]
	  qpaddw,3	%r41, %r31, %b[1]
	}
	{
	  qpsrcw,0	%b[3], %r11, %b[3]
	  qpsrcw,1	%r36, 0xe, %r36
	  qpxor,3	%r33, %r63, %r33
	  qpsrcw,4	%b[1], %r10, %r63
	}
	{
	  qpsrcw,0	%r61, 0xe, %r60
	  qpxor,1	%r22, %r60, %r22
	  qpaddw,3	%r33, %r40, %r61
	}
	{
	  qpxor,0	%r15, %b[3], %r15
	  qpxor,1	%r38, %b[0], %r38
	  qpsrcw,3	%r61, %r11, %r61
	}
	{
	  qpaddw,0	%r22, %r24, %b[0]
	  qpxor,1	%r53, %r36, %r36
	  qpxor,3	%r42, %r61, %r42
	}
	{
	  qpaddw,0	%r38, %r27, %r53
	  qpxor,1	%r59, %r60, %r59
	  qpaddw,3	%r42, %r33, %r60
	}
	{
	  qpaddw,0	%r15, %r31, %r61
	  qpsrcw,1	%b[0], %r12, %b[0]
	  qpsrcw,3	%r60, %r12, %r60
	}
	{
	  qpaddw,0	%r36, %r56, %b[1]
	  qpsrcw,1	%r53, %r12, %r53
	  qpxor,3	%r49, %r60, %r49
	}
	{
	  qpaddw,0	%r59, %r58, %r60
	  qpsrcw,1	%r61, %r12, %r61
	  qpaddw,3	%r49, %r42, %b[3]
	}
	{
	  qpxor,0	%r32, %b[0], %r32
	  qpsrcw,1	%b[1], %r10, %b[0]
	  qpsrcw,3	%b[3], 0xe, %b[1]
	}
	{
	  qpsrcw,0	%r60, %r10, %r53
	  qpxor,1	%r44, %r53, %r44
	  qpxor,3	%r40, %b[1], %r40
	}
	{
	  qpaddw,0	%r32, %r22, %r60
	  qpxor,1	%r45, %r61, %r45
	  qpaddw,3	%r40, %r35, %r61
	}
	{
	  qpaddw,0	%r44, %r38, %b[1]
	  qpxor,1	%r48, %b[0], %r48
	  qpsrcw,3	%r61, %r10, %r61
	}
	{
	  qpaddw,0	%r45, %r15, %b[0]
	  qpxor,1	%r50, %r53, %r50
	  qpxor,3	%r32, %r63, %r32
	}
	{
	  qpaddw,0	%r48, %r36, %r53
	  qpsrcw,1	%r60, 0xe, %r60
	  qpaddw,3	%r32, %r41, %r63
	}
	{
	  qpaddw,0	%r50, %r59, %b[3]
	  qpsrcw,1	%b[1], 0xe, %b[1]
	  qpsrcw,4	%r63, %r11, %r63
	}
	{
	  qpsrcw,0	%b[0], 0xe, %b[0]
	  qpsrcw,1	%r53, %r11, %r53
	  qpxor,4	%r38, %r63, %r38
	}
	{
	  qpsrcw,0	%b[3], %r11, %r60
	  qpxor,1	%r52, %r60, %r52
	  qpaddw,3	%r38, %r32, %r63
	}
	{
	  qpxor,0	%r55, %b[0], %r55
	  qpxor,1	%r54, %b[1], %r54
	  qpaddw,3	%r51, %r50, %b[0]
	  qpsrcw,4	%r63, %r12, %r63
	}
	{
	  qpaddw,0	%r52, %r25, %b[1]
	  qpxor,1	%r62, %r53, %r53
	  qpsrcw,3	%b[0], %r10, %r62
	  qpxor,4	%r31, %r63, %r31
	}
	{
	  qpaddw,0	%r54, %r24, %r63
	  qpxor,1	%r57, %r60, %r57
	  qpaddw,3	%r31, %r38, %r60
	  qpxor,4	%r49, %r62, %r49
	}
	{
	  qpaddw,0	%r55, %r27, %r62
	  qpsrcw,1	%b[1], %r10, %b[0]
	  qpaddw,3	%r49, %r51, %b[1]
	  qpsrcw,4	%r60, 0xe, %r60
	}
	{
	  qpaddw,0	%r53, %r48, %b[3]
	  qpsrcw,1	%r63, %r10, %r63
	  qpsrcw,3	%b[1], %r11, %b[1]
	  qpxor,4	%r41, %r60, %r41
	}
	{
	  qpaddw,0	%r57, %r50, %r60
	  qpsrcw,1	%r62, %r10, %r62
	  qpxor,3	%r53, %b[1], %b[1]
	}
	{
	  qpsrcw,0	%b[3], %r12, %b[0]
	  qpxor,1	%r44, %b[0], %r44
	  qpaddw,3	%b[1], %r49, %b[3]
	}
	{
	  qpsrcw,0	%r60, %r12, %r60
	  qpxor,1	%r45, %r63, %r45
	  qpsrcw,3	%b[3], %r12, %r63
	}
	{
	  qpaddw,0	%r44, %r52, %r62
	  qpxor,1	%g25, %r62, %g25
	  qpxor,3	%r50, %r63, %r50
	}
	{
	  qpaddw,0	%r45, %r54, %r63
	  qpxor,1	%r56, %b[0], %r56
	  qpaddw,3	%r50, %b[1], %b[0]
	}
	{
	  qpaddw,0	%g25, %r55, %b[3]
	  qpxor,1	%r58, %r60, %r58
	  qpsrcw,3	%b[0], 0xe, %r60
	}
	{
	  qpaddw,0	%r56, %r53, %r53
	  qpsrcw,1	%r62, %r11, %r62
	  qpxor,3	%r51, %r60, %r51
	}
	{
	  qpaddw,0	%r58, %r57, %r60
	  qpsrcw,1	%r63, %r11, %r63
	  qpaddw,3	%r41, %g25, %b[0]
	}
	{
	  qpsrcw,0	%b[3], %r11, %b[3]
	  qpsrcw,1	%r53, 0xe, %r53
	  qpxor,3	%r56, %r61, %r56
	  qpsrcw,4	%b[0], %r10, %r61
	}
	{
	  qpsrcw,0	%r60, 0xe, %r60
	  qpxor,1	%r15, %r62, %r15
	  qpaddw,3	%r56, %r40, %r62
	}
	{
	  qpxor,0	%r22, %b[3], %r22
	  qpxor,1	%r14, %r63, %r14
	  qpsrcw,3	%r62, %r11, %r62
	}
	{
	  qpaddw,0	%r15, %r44, %r63
	  qpxor,1	%r36, %r53, %r36
	  qpxor,3	%r57, %r62, %r53
	}
	{
	  qpaddw,0	%r14, %r45, %r57
	  qpxor,1	%r59, %r60, %r59
	  qpaddw,3	%r53, %r56, %r60
	}
	{
	  qpaddw,0	%r22, %g25, %r62
	  qpsrcw,1	%r63, %r12, %r63
	  qpsrcw,3	%r60, %r12, %r60
	}
	{
	  qpaddw,0	%r36, %r33, %b[0]
	  qpsrcw,1	%r57, %r12, %r57
	  qpxor,3	%r35, %r60, %r35
	}
	{
	  qpaddw,0	%r59, %r48, %r60
	  qpsrcw,1	%r62, %r12, %r62
	  qpaddw,3	%r35, %r53, %b[3]
	}
	{
	  qpxor,0	%r25, %r63, %r25
	  qpsrcw,1	%b[0], %r10, %r63
	  qpsrcw,3	%b[3], 0xe, %b[0]
	}
	{
	  qpsrcw,0	%r60, %r10, %r57
	  qpxor,1	%r24, %r57, %r24
	  qpxor,3	%r40, %b[0], %r40
	}
	{
	  qpaddw,0	%r25, %r15, %r60
	  qpxor,1	%r27, %r62, %r27
	  qpaddw,3	%r40, %r49, %r62
	}
	{
	  qpaddw,0	%r24, %r14, %b[0]
	  qpxor,1	%r58, %r63, %r58
	  qpsrcw,3	%r62, %r10, %r62
	}
	{
	  qpaddw,0	%r27, %r22, %r63
	  qpxor,1	%r46, %r57, %r46
	  qpxor,3	%r25, %r61, %r25
	}
	{
	  qpaddw,0	%r58, %r36, %r57
	  qpsrcw,1	%r60, 0xe, %r60
	  qpaddw,3	%r25, %r41, %r61
	}
	{
	  qpaddw,0	%r46, %r59, %b[3]
	  qpsrcw,1	%b[0], 0xe, %b[0]
	  qpsrcw,4	%r61, %r11, %r61
	}
	{
	  qpsrcw,0	%r63, 0xe, %r63
	  qpsrcw,1	%r57, %r11, %r57
	  qpxor,4	%r14, %r61, %r14
	}
	{
	  qpsrcw,0	%b[3], %r11, %r60
	  qpxor,1	%r52, %r60, %r52
	  qpaddw,3	%r14, %r25, %r61
	}
	{
	  qpxor,0	%r55, %r63, %r55
	  qpxor,1	%r54, %b[0], %r54
	  qpaddw,3	%r51, %r46, %r63
	  qpsrcw,4	%r61, %r12, %r61
	}
	{
	  qpaddw,0	%r52, %r32, %b[0]
	  qpxor,1	%b[2], %r57, %r57
	  qpsrcw,3	%r63, %r10, %r63
	  qpxor,4	%g25, %r61, %g25
	}
	{
	  qpaddw,0	%r54, %r44, %r61
	  qpxor,1	%r42, %r60, %r42
	  qpaddw,3	%g25, %r14, %r60
	  qpxor,4	%r35, %r63, %r35
	}
	{
	  qpaddw,0	%r55, %r45, %r63
	  qpsrcw,1	%b[0], %r10, %b[0]
	  qpaddw,3	%r35, %r51, %b[2]
	  qpsrcw,4	%r60, 0xe, %r60
	}
	{
	  qpaddw,0	%r57, %r58, %b[3]
	  qpsrcw,1	%r61, %r10, %r61
	  qpsrcw,3	%b[2], %r11, %b[2]
	  qpxor,4	%r41, %r60, %r41
	}
	{
	  qpaddw,0	%r42, %r46, %r60
	  qpsrcw,1	%r63, %r10, %r63
	  qpxor,3	%r57, %b[2], %b[2]
	}
	{
	  qpsrcw,0	%b[3], %r12, %b[0]
	  qpxor,1	%r24, %b[0], %r24
	  qpaddw,3	%b[2], %r35, %b[3]
	}
	{
	  qpsrcw,0	%r60, %r12, %r60
	  qpxor,1	%r27, %r61, %r27
	  qpsrcw,3	%b[3], %r12, %r61
	}
	{
	  qpaddw,0	%r24, %r52, %r63
	  qpxor,1	%r31, %r63, %r31
	  qpxor,3	%r46, %r61, %r46
	}
	{
	  qpaddw,0	%r27, %r54, %r61
	  qpxor,1	%r33, %b[0], %r33
	  qpaddw,3	%r46, %b[2], %b[0]
	}
	{
	  qpaddw,0	%r31, %r55, %b[3]
	  qpxor,1	%r48, %r60, %r48
	  qpsrcw,3	%b[0], 0xe, %r60
	}
	{
	  qpaddw,0	%r33, %r57, %r57
	  qpsrcw,1	%r63, %r11, %r63
	  qpxor,3	%r51, %r60, %r51
	}
	{
	  qpaddw,0	%r48, %r42, %r60
	  qpsrcw,1	%r61, %r11, %r61
	  qpaddw,3	%r41, %r31, %b[0]
	}
	{
	  qpsrcw,0	%b[3], %r11, %b[3]
	  qpsrcw,1	%r57, 0xe, %r57
	  qpxor,3	%r33, %r62, %r33
	  qpsrcw,4	%b[0], %r10, %r62
	}
	{
	  qpsrcw,0	%r60, 0xe, %r60
	  qpxor,1	%r22, %r63, %r22
	  qpaddw,3	%r33, %r40, %r63
	}
	{
	  qpxor,0	%r15, %b[3], %r15
	  qpxor,1	%r38, %r61, %r38
	  qpsrcw,3	%r63, %r11, %r61
	}
	{
	  qpaddw,0	%r22, %r24, %r63
	  qpxor,1	%r36, %r57, %r36
	  qpxor,3	%r42, %r61, %r42
	}
	{
	  qpaddw,0	%r38, %r27, %r57
	  qpxor,1	%r59, %r60, %r59
	  qpaddw,3	%r42, %r33, %r60
	}
	{
	  qpaddw,0	%r15, %r31, %r61
	  qpsrcw,1	%r63, %r12, %r63
	  qpsrcw,3	%r60, %r12, %r60
	}
	{
	  qpaddw,0	%r36, %r56, %b[0]
	  qpsrcw,1	%r57, %r12, %r57
	  qpxor,3	%r49, %r60, %r49
	}
	{
	  qpaddw,0	%r59, %r58, %r60
	  qpsrcw,1	%r61, %r12, %r61
	  qpaddw,3	%r49, %r42, %b[3]
	}
	{
	  qpxor,0	%r32, %r63, %r32
	  qpsrcw,1	%b[0], %r10, %r63
	  qpsrcw,3	%b[3], 0xe, %b[0]
	}
	{
	  qpsrcw,0	%r60, %r10, %r57
	  qpxor,1	%r44, %r57, %r44
	  qpxor,3	%r40, %b[0], %r40
	}
	{
	  qpaddw,0	%r32, %r22, %r60
	  qpxor,1	%r45, %r61, %r45
	  qpaddw,3	%r40, %r35, %r61
	}
	{
	  qpaddw,0	%r44, %r38, %b[0]
	  qpxor,1	%r48, %r63, %r48
	  qpsrcw,3	%r61, %r10, %r61
	}
	{
	  qpaddw,0	%r45, %r15, %r63
	  qpxor,1	%r50, %r57, %r50
	  qpxor,3	%r32, %r62, %r32
	}
	{
	  qpaddw,0	%r48, %r36, %r57
	  qpsrcw,1	%r60, 0xe, %r60
	  qpaddw,3	%r32, %r41, %r62
	}
	{
	  qpaddw,0	%r50, %r59, %b[3]
	  qpsrcw,1	%b[0], 0xe, %b[0]
	  qpsrcw,4	%r62, %r11, %r62
	}
	{
	  qpsrcw,0	%r63, 0xe, %r63
	  qpsrcw,1	%r57, %r11, %r57
	  qpxor,4	%r38, %r62, %r38
	}
	{
	  qpsrcw,0	%b[3], %r11, %r60
	  qpxor,1	%r52, %r60, %r52
	  qpaddw,3	%r38, %r32, %r62
	}
	{
	  qpxor,0	%r55, %r63, %r55
	  qpxor,1	%r54, %b[0], %r54
	  qpaddw,3	%r51, %r50, %r63
	  qpsrcw,4	%r62, %r12, %r62
	}
	{
	  qpaddw,0	%r52, %r25, %b[0]
	  qpxor,1	%b[1], %r57, %r57
	  qpsrcw,3	%r63, %r10, %r63
	  qpxor,4	%r31, %r62, %r31
	}
	{
	  qpaddw,0	%r54, %r24, %r62
	  qpxor,1	%r53, %r60, %r53
	  qpaddw,3	%r31, %r38, %r60
	  qpxor,4	%r49, %r63, %r49
	}
	{
	  qpaddw,0	%r55, %r27, %r63
	  qpsrcw,1	%b[0], %r10, %b[0]
	  qpaddw,3	%r49, %r51, %b[1]
	  qpsrcw,4	%r60, 0xe, %r60
	}
	{
	  qpaddw,0	%r57, %r48, %b[3]
	  qpsrcw,1	%r62, %r10, %r62
	  qpsrcw,3	%b[1], %r11, %b[1]
	  qpxor,4	%r41, %r60, %r41
	}
	{
	  qpaddw,0	%r53, %r50, %r60
	  qpsrcw,1	%r63, %r10, %r63
	  qpxor,3	%r57, %b[1], %b[1]
	}
	{
	  qpsrcw,0	%b[3], %r12, %b[0]
	  qpxor,1	%r44, %b[0], %r44
	  qpaddw,3	%b[1], %r49, %b[3]
	}
	{
	  qpsrcw,0	%r60, %r12, %r60
	  qpxor,1	%r45, %r62, %r45
	  qpsrcw,3	%b[3], %r12, %r62
	}
	{
	  qpaddw,0	%r44, %r52, %r63
	  qpxor,1	%g25, %r63, %g25
	  qpxor,3	%r50, %r62, %r50
	}
	{
	  qpaddw,0	%r45, %r54, %r62
	  qpxor,1	%r56, %b[0], %r56
	  qpaddw,3	%r50, %b[1], %b[0]
	}
	{
	  qpaddw,0	%g25, %r55, %b[3]
	  qpxor,1	%r58, %r60, %r58
	  qpsrcw,3	%b[0], 0xe, %r60
	}
	{
	  qpaddw,0	%r56, %r57, %r57
	  qpsrcw,1	%r63, %r11, %r63
	  qpxor,3	%r51, %r60, %r51
	}
	{
	  qpaddw,0	%r58, %r53, %r60
	  qpsrcw,1	%r62, %r11, %r62
	  qpaddw,3	%r41, %g25, %b[0]
	}
	{
	  qpsrcw,0	%b[3], %r11, %b[3]
	  qpsrcw,1	%r57, 0xe, %r57
	  qpxor,3	%r56, %r61, %r56
	  qpsrcw,4	%b[0], %r10, %r61
	}
	{
	  qpsrcw,0	%r60, 0xe, %r60
	  qpxor,1	%r15, %r63, %r15
	  qpaddw,3	%r56, %r40, %r63
	}
	{
	  qpxor,0	%r22, %b[3], %r22
	  qpxor,1	%r14, %r62, %r14
	  qpsrcw,3	%r63, %r11, %r62
	}
	{
	  qpaddw,0	%r15, %r44, %r63
	  qpxor,1	%r36, %r57, %r36
	  qpxor,3	%r53, %r62, %r53
	}
	{
	  qpaddw,0	%r14, %r45, %r57
	  qpxor,1	%r59, %r60, %r59
	  qpaddw,3	%r53, %r56, %r60
	}
	{
	  qpaddw,0	%r22, %g25, %r62
	  qpsrcw,1	%r63, %r12, %r63
	  qpsrcw,3	%r60, %r12, %r60
	}
	{
	  qpaddw,0	%r36, %r33, %b[0]
	  qpsrcw,1	%r57, %r12, %r57
	  qpxor,3	%r35, %r60, %r35
	}
	{
	  qpaddw,0	%r59, %r48, %r60
	  qpsrcw,1	%r62, %r12, %r62
	  qpaddw,3	%r35, %r53, %b[3]
	}
	{
	  qpxor,0	%r25, %r63, %r25
	  qpsrcw,1	%b[0], %r10, %r63
	  qpsrcw,3	%b[3], 0xe, %b[0]
	}
	{
	  qpsrcw,0	%r60, %r10, %r57
	  qpxor,1	%r24, %r57, %r24
	  qpxor,3	%r40, %b[0], %r40
	}
	{
	  qpaddw,0	%r25, %r15, %r60
	  qpxor,1	%r27, %r62, %r27
	  qpaddw,3	%r40, %r49, %r62
	}
	{
	  qpaddw,0	%r24, %r14, %b[0]
	  qpxor,1	%r58, %r63, %r58
	  qpsrcw,3	%r62, %r10, %r62
	}
	{
	  qpaddw,0	%r27, %r22, %r63
	  qpxor,1	%r46, %r57, %r46
	  qpxor,3	%r25, %r61, %r25
	}
	{
	  qpaddw,0	%r58, %r36, %r57
	  qpsrcw,1	%r60, 0xe, %r60
	  qpaddw,3	%r25, %r41, %r61
	}
	{
	  qpaddw,0	%r46, %r59, %b[3]
	  qpsrcw,1	%b[0], 0xe, %b[0]
	  qpsrcw,4	%r61, %r11, %r61
	}
	{
	  qpsrcw,0	%r63, 0xe, %r63
	  qpsrcw,1	%r57, %r11, %r57
	  qpxor,4	%r14, %r61, %r14
	}
	{
	  qpsrcw,0	%b[3], %r11, %r60
	  qpxor,1	%r52, %r60, %r52
	  qpaddw,3	%r14, %r25, %r61
	}
	{
	  qpxor,0	%r55, %r63, %r55
	  qpxor,1	%r54, %b[0], %r54
	  qpaddw,3	%r51, %r46, %r63
	  qpsrcw,4	%r61, %r12, %r61
	}
	{
	  qpaddw,0	%r52, %r32, %b[0]
	  qpxor,1	%b[2], %r57, %r57
	  qpsrcw,3	%r63, %r10, %r63
	  qpxor,4	%g25, %r61, %g25
	}
	{
	  qpaddw,0	%r54, %r44, %r61
	  qpxor,1	%r42, %r60, %r42
	  qpaddw,3	%g25, %r14, %r60
	  qpxor,4	%r35, %r63, %r35
	}
	{
	  qpaddw,0	%r55, %r45, %r63
	  qpsrcw,1	%b[0], %r10, %b[0]
	  qpaddw,3	%r35, %r51, %b[2]
	  qpsrcw,4	%r60, 0xe, %r60
	}
	{
	  qpaddw,0	%r57, %r58, %b[3]
	  qpsrcw,1	%r61, %r10, %r61
	  qpsrcw,3	%b[2], %r11, %b[2]
	  qpxor,4	%r41, %r60, %r41
	}
	{
	  qpaddw,0	%r42, %r46, %r60
	  qpsrcw,1	%r63, %r10, %r63
	  qpxor,3	%r57, %b[2], %b[2]
	}
	{
	  qpsrcw,0	%b[3], %r12, %b[0]
	  qpxor,1	%r24, %b[0], %r24
	  qpaddw,3	%b[2], %r35, %b[3]
	}
	{
	  qpsrcw,0	%r60, %r12, %r60
	  qpxor,1	%r27, %r61, %r27
	  qpsrcw,3	%b[3], %r12, %r61
	}
	{
	  qpaddw,0	%r24, %r52, %r63
	  qpxor,1	%r31, %r63, %r31
	  qpxor,3	%r46, %r61, %r46
	}
	{
	  qpaddw,0	%r27, %r54, %r61
	  qpxor,1	%r33, %b[0], %r33
	  qpaddw,3	%r46, %b[2], %b[0]
	}
	{
	  qpaddw,0	%r31, %r55, %b[3]
	  qpxor,1	%r48, %r60, %r48
	  qpsrcw,3	%b[0], 0xe, %r60
	}
	{
	  qpaddw,0	%r33, %r57, %r57
	  qpsrcw,1	%r63, %r11, %r63
	  qpxor,3	%r51, %r60, %r51
	}
	{
	  qpaddw,0	%r48, %r42, %r60
	  qpsrcw,1	%r61, %r11, %r61
	  qpaddw,3	%r41, %r31, %b[0]
	}
	{
	  qpsrcw,0	%b[3], %r11, %b[3]
	  qpsrcw,1	%r57, 0xe, %r57
	  qpxor,3	%r33, %r62, %r33
	  qpsrcw,4	%b[0], %r10, %r62
	}
	{
	  qpsrcw,0	%r60, 0xe, %r60
	  qpxor,1	%r22, %r63, %r22
	  qpaddw,3	%r33, %r40, %r63
	}
	{
	  qpxor,0	%r15, %b[3], %r15
	  qpxor,1	%r38, %r61, %r38
	  qpsrcw,3	%r63, %r11, %r61
	}
	{
	  qpaddw,0	%r22, %r24, %r63
	  qpxor,1	%r36, %r57, %r36
	  qpxor,3	%r42, %r61, %r42
	}
	{
	  qpaddw,0	%r38, %r27, %r57
	  qpxor,1	%r59, %r60, %r59
	  qpaddw,3	%r42, %r33, %r60
	}
	{
	  qpaddw,0	%r15, %r31, %r61
	  qpsrcw,1	%r63, %r12, %r63
	  qpsrcw,3	%r60, %r12, %r60
	}
	{
	  qpaddw,0	%r36, %r56, %b[0]
	  qpsrcw,1	%r57, %r12, %r57
	  qpxor,3	%r49, %r60, %r49
	}
	{
	  qpaddw,0	%r59, %r58, %r60
	  qpsrcw,1	%r61, %r12, %r61
	  qpaddw,3	%r49, %r42, %b[3]
	}
	{
	  qpxor,0	%r32, %r63, %r32
	  qpsrcw,1	%b[0], %r10, %r63
	  qpsrcw,3	%b[3], 0xe, %b[0]
	}
	{
	  qpsrcw,0	%r60, %r10, %r57
	  qpxor,1	%r44, %r57, %r44
	  qpxor,3	%r40, %b[0], %r40
	}
	{
	  qpaddw,0	%r32, %r22, %r60
	  qpxor,1	%r45, %r61, %r45
	  qpaddw,3	%r40, %r35, %r61
	}
	{
	  qpaddw,0	%r44, %r38, %b[0]
	  qpxor,1	%r48, %r63, %r48
	  qpsrcw,3	%r61, %r10, %r61
	}
	{
	  qpaddw,0	%r45, %r15, %r63
	  qpxor,1	%r50, %r57, %r50
	  qpxor,3	%r32, %r62, %r32
	}
	{
	  qpaddw,0	%r48, %r36, %r57
	  qpsrcw,1	%r60, 0xe, %r60
	  qpaddw,3	%r32, %r41, %r62
	}
	{
	  qpaddw,0	%r50, %r59, %b[3]
	  qpsrcw,1	%b[0], 0xe, %b[0]
	  qpaddw,3	%g24, %r32, %g24
	  qpsrcw,4	%r62, %r11, %r62
	}
	{
	  qpsrcw,0	%r63, 0xe, %r63
	  qpsrcw,1	%r57, %r11, %r57
	  qpxor,4	%r38, %r62, %r38
	  stqp,5	%r1, _f16s,_lts0lo 0x110, %g24
	}
	{
	  qpsrcw,0	%b[3], %r11, %r52
	  qpxor,1	%r52, %r60, %g24
	  qpaddw,3	%r38, %r32, %r32
	}
	{
	  qpxor,0	%r55, %r63, %r55
	  qpxor,1	%r54, %b[0], %r54
	  qpaddw,3	%r51, %r50, %r60
	  qpsrcw,4	%r32, %r12, %r32
	}
	{
	  qpaddw,0	%g24, %r25, %r62
	  qpxor,1	%b[1], %r57, %r57
	  qpxor,3	%r31, %r32, %r31
	  qpsrcw,4	%r60, %r10, %r60
	}
	{
	  qpaddw,0	%r54, %r24, %r32
	  qpxor,1	%r53, %r52, %r52
	  qpaddw,3	%r31, %r38, %r53
	  qpxor,4	%r49, %r60, %r49
	}
	{
	  qpaddw,0	%r55, %r27, %r60
	  qpsrcw,1	%r62, %r10, %r62
	  qpaddw,3	%r49, %r51, %r63
	  qpsrcw,4	%r53, 0xe, %r53
	}
	{
	  qpaddw,0	%r57, %r48, %b[0]
	  qpsrcw,1	%r32, %r10, %r32
	  qpxor,3	%r41, %r53, %r41
	  qpsrcw,4	%r63, %r11, %r63
	}
	{
	  qpaddw,0	%r52, %r50, %r53
	  qpsrcw,1	%r60, %r10, %r60
	  qpaddw,3	%r29, %r38, %r29
	  qpxor,4	%r57, %r63, %r38
	}
	{
	  qpsrcw,0	%b[0], %r12, %r62
	  qpxor,1	%r44, %r62, %r44
	  qpaddw,3	%r21, %r31, %r21
	  stqp,5	%r1, _f16s,_lts0lo 0x120, %r29
	}
	{
	  qpsrcw,0	%r53, %r12, %r31
	  qpxor,1	%r45, %r32, %r29
	  qpaddw,3	%g16, %r41, %g16
	  stqp,5	%r1, _f16s,_lts0lo 0x130, %r21
	}
	{
	  qpaddw,0	%r44, %g24, %r21
	  qpxor,1	%g25, %r60, %g25
	  qpaddw,3	%r38, %r49, %r32
	  stqp,5	%r1, _f16s,_lts0lo 0x100, %g16
	}
	{
	  qpaddw,0	%r29, %r54, %g16
	  qpxor,1	%r56, %r62, %r41
	  qpaddw,3	%r18, %r49, %r18
	  qpsrcw,4	%r32, %r12, %r32
	}
	{
	  qpaddw,0	%g25, %r55, %r45
	  qpxor,1	%r58, %r31, %r31
	  qpaddw,3	%g22, %r44, %g22
	  qpxor,4	%r50, %r32, %r32
	  stqp,5	%r1, _f16s,_lts0lo 0x3c0, %r18
	}
	{
	  qpaddw,0	%r41, %r57, %r18
	  qpsrcw,1	%r21, %r11, %r21
	  qpaddw,3	%g20, %r29, %g20
	  stqp,5	%r1, _f16s,_lts0lo 0x160, %g22
	}
	{
	  qpaddw,0	%r31, %r52, %g22
	  qpsrcw,1	%g16, %r11, %g16
	  qpaddw,3	%g19, %g25, %g19
	  stqp,5	%r1, _f16s,_lts0lo 0x1b0, %g20
	}
	{
	  qpsrcw,0	%r45, %r11, %g20
	  qpsrcw,1	%r18, 0xe, %r18
	  qpaddw,3	%r32, %r38, %g19
	  qpxor,4	%r41, %r61, %r41
	  stqp,5	%r1, _f16s,_lts0lo 0x1c0, %g19
	}
	{
	  qpsrcw,0	%g22, 0xe, %g22
	  qpxor,1	%r15, %r21, %r15
	  qpaddw,3	%r41, %r40, %r21
	  qpsrcw,4	%g19, 0xe, %g19
	}
	{
	  qpxor,0	%r22, %g20, %g20
	  qpxor,1	%r14, %g16, %g16
	  qpxor,3	%r51, %g19, %g19
	  qpsrcw,4	%r21, %r11, %r14
	}
	{
	  qpaddw,0	%r15, %r44, %r21
	  qpxor,1	%r36, %r18, %r18
	  qpaddw,3	%r43, %r38, %r22
	  qpxor,4	%r52, %r14, %r14
	}
	{
	  qpaddw,0	%g16, %r29, %r29
	  qpxor,1	%r59, %g22, %g22
	  qpaddw,3	%r14, %r41, %r36
	  stqp,5	%r1, _f16s,_lts0lo 0x3d0, %r22
	}
	{
	  qpaddw,0	%g20, %g25, %g25
	  qpsrcw,1	%r21, %r12, %r21
	  qpaddw,3	%r28, %r15, %r22
	  qpsrcw,4	%r36, %r12, %r28
	}
	{
	  qpaddw,0	%r18, %r33, %r36
	  qpsrcw,1	%r29, %r12, %r29
	  qpaddw,3	%r17, %g16, %r17
	  qpxor,4	%r35, %r28, %r22
	  stqp,5	%r1, _f16s,_lts0lo 0x170, %r22
	}
	{
	  qpaddw,0	%g22, %r48, %r28
	  qpsrcw,1	%g25, %r12, %g25
	  qpaddw,3	%r26, %g20, %r26
	  stqp,5	%r1, _f16s,_lts0lo 0x180, %r17
	}
	{
	  qpxor,0	%r25, %r21, %r17
	  qpsrcw,1	%r36, %r10, %r21
	  qpaddw,3	%r22, %r14, %r25
	  stqp,5	%r1, _f16s,_lts0lo 0x1d0, %r26
	}
	{
	  qpsrcw,0	%r28, %r10, %r26
	  qpxor,1	%r24, %r29, %r24
	  qpaddw,3	%g29, %r32, %g29
	  qpsrcw,4	%r25, 0xe, %r25
	}
	{
	  qpaddw,0	%r17, %r15, %r15
	  qpxor,1	%r27, %g25, %g25
	  qpaddw,3	%r23, %r41, %r23
	  qpxor,4	%r40, %r25, %r25
	  stqp,5	%r1, _f16s,_lts0lo 0x3e0, %g29
	}
	{
	  qpaddw,0	%r24, %g16, %g16
	  qpxor,1	%r31, %r21, %g29
	  qpaddw,3	%g27, %g19, %g19
	  stqp,5	%r1, _f16s,_lts0lo 0x310, %r23
	}
	{
	  qpaddw,0	%g25, %g20, %g20
	  qpxor,1	%r46, %r26, %g27
	  qpaddw,3	%r20, %r17, %r17
	  stqp,5	%r1, _f16s,_lts0lo 0x3f0, %g19
	}
	{
	  qpaddw,0	%g29, %r18, %g19
	  qpsrcw,1	%r15, 0xe, %r15
	  qpaddw,3	%r19, %r24, %r19
	  stqp,5	%r1, _f16s,_lts0lo 0x140, %r17
	}
	{
	  qpaddw,0	%g27, %g22, %r17
	  qpsrcw,1	%g16, 0xe, %g16
	  qpaddw,3	%r16, %g25, %g25
	  stqp,5	%r1, _f16s,_lts0lo 0x190, %r19
	}
	{
	  qpsrcw,0	%g20, 0xe, %g20
	  qpsrcw,1	%g19, %r11, %g19
	  qpaddw,3	%r34, %r14, %g25
	  stqp,5	%r1, _f16s,_lts0lo 0x1e0, %g25
	}
	{
	  qpsrcw,0	%r17, %r11, %r14
	  qpxor,1	%g24, %r15, %g24
	  qpaddw,3	%r30, %r22, %r15
	  stqp,5	%r1, _f16s,_lts0lo 0x320, %g25
	}
	{
	  qpxor,0	%r55, %g20, %g20
	  qpxor,1	%r54, %g16, %g16
	  qpaddw,3	%g17, %r25, %g17
	  stqp,5	%r1, _f16s,_lts0lo 0x330, %r15
	}
	{
	  qpaddw,0	%g23, %g24, %g23
	  qpxor,1	%b[2], %g19, %g19
	  qpaddw,3	%g26, %g29, %g24
	  stqp,5	%r1, _f16s,_lts0lo 0x300, %g17
	}
	{
	  qpaddw,0	%g21, %g16, %g16
	  qpxor,1	%r42, %r14, %g17
	  stqp,2	%r1, _f16s,_lts0lo 0x150, %g23
	  qpaddw,3	%g30, %g27, %g21
	  stqp,5	%r1, _f16s,_lts0hi 0x360, %g24
	}
	{
	  qpaddw,0	%g18, %g20, %g18
	  stqp,2	%r1, _f16s,_lts0lo 0x1a0, %g16
	  stqp,5	%r1, _f16s,_lts0hi 0x3b0, %g21
	}
	{
	  qpaddw,0	%g19, %g29, %g16
	  stqp,2	%r1, _f16s,_lts0lo 0x1f0, %g18
	}
	{
	  qpaddw,0	%g17, %g27, %g18
	  qpsrcw,1	%g16, %r12, %g16
	  qpaddw,3	%r4, %g19, %g20
	}
	{
	  qpxor,0	%r33, %g16, %g16
	  qpsrcw,1	%g18, %r12, %g18
	  qpaddw,3	%g28, %g17, %g21
	  stqp,5	%r1, _f16s,_lts0lo 0x370, %g20
	}
	{
	  qpaddw,0	%g16, %g19, %g19
	  qpxor,1	%r48, %g18, %g18
	  stqp,5	%r1, _f16s,_lts0lo 0x380, %g21
	}
	{
	  qpaddw,0	%g18, %g17, %g17
	  qpsrcw,1	%g19, 0xe, %g19
	}
	{
	  qpxor,0	%r18, %g19, %g19
	  qpsrcw,1	%g17, 0xe, %g17
	}
	{
	  qpaddw,0	%r39, %g16, %g16
	  qpxor,1	%g22, %g17, %g17
	}
	{
	  qpaddw,0	%r47, %g18, %g18
	  stqp,2	%r1, _f16s,_lts0lo 0x340, %g16
	}
	{
	  qpaddw,0	%r37, %g19, %g16
	  stqp,2	%r1, _f16s,_lts0lo 0x390, %g18
	}
	{
	  qpaddw,0	%g31, %g17, %g17
	  stqp,2	%r1, _f16s,_lts0lo 0x350, %g16
	}
	{
	  ct	%ctpr1 ? %pred0
	  stqp,2	%r1, _f16s,_lts0lo 0x3a0, %g17
	}
	{
	  ct	%ctpr3 ? ~%pred0
	}
	.size	scrypt_1024_core_2_cycle_elway, .- scrypt_1024_core_2_cycle_elway
	.local	scrypt_1024_core_elway
	.type	scrypt_1024_core_elway, #function
	.align	8
scrypt_1024_core_elway:
	{
	  setwd	wsz = 0x2b, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0xa, rbs = 0x20, rcur = 0x7
	  disp	%ctpr1, scrypt_1024_core_1_cycle_elway
	  getsp,0	_f32s,_lts2 0xffffe3c0, %r3
	  ldqp,2	%r0, 0x0, %r6
	  ldqp,3	0x10, %r0, %r4
	  ldqp,5	%r0, _f16s,_lts1lo 0x90, %r5
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x80, %r7
	  addd,1	0x0, _f64,_lts2 0x1b1a191813121110, %r12
	  ldqp,2	%r0, _f16s,_lts0hi 0x30, %r9
	  ldqp,3	%r0, _f16s,_lts1lo 0xb0, %r10
	  addd,4,sm	0x0, %r0, %b[0]
	  ldqp,5	%r0, _f16s,_lts1hi 0x20, %r11
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0xa0, %r13
	  addd,1	0x0, _f64,_lts2 0x1f1e1d1c17161514, %r17
	  ldqp,2	%r0, _f16s,_lts0hi 0x110, %r14
	  ldqp,3	%r0, _f16s,_lts1lo 0x190, %r15
	  addd,4,sm	0x0, %r1, %b[2]
	  ldqp,5	%r0, _f16s,_lts1hi 0x100, %r16
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x180, %r18
	  qppackdl,1	%r12, _f64,_lts2 0xb0a090803020100, %r12
	  ldqp,2	%r0, _f16s,_lts0hi 0x130, %r19
	  ldqp,3	%r0, _f16s,_lts1lo 0x1b0, %r20
	  ldqp,5	%r0, _f16s,_lts1hi 0x120, %r21
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x1a0, %r22
	  qppermb,1	%r5, %r4, %r12, %r25
	  ldqp,2	%r0, _f16s,_lts0hi 0x50, %r23
	  addd,3	%r3, _f64,_lts2 0x1c40, %r2
	  ldqp,5	%r0, _f16s,_lts1lo 0xd0, %r24
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x40, %r26
	  qppackdl,1	%r17, _f64,_lts2 0xf0e0d0c07060504, %r17
	  ldqp,2	%r0, _f16s,_lts0hi 0xc0, %r27
	  ldqp,3	%r0, _f16s,_lts1lo 0x70, %r28
	  ldqp,5	%r0, _f16s,_lts1hi 0xf0, %r29
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x60, %r30
	  qppermb,1	%r7, %r6, %r12, %r34
	  ldqp,2	%r0, _f16s,_lts0hi 0xe0, %r31
	  ldqp,3	%r0, _f16s,_lts1lo 0x150, %r32
	  addd,4	%r2, _f32s,_lts2 0xfffffbe0, %r35
	  ldqp,5	%r0, _f16s,_lts1hi 0x1d0, %r33
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x140, %r36
	  qppermb,1	%r10, %r9, %r12, %r41
	  ldqp,2	%r0, _f16s,_lts0hi 0x1c0, %r37
	  ldqp,3	%r0, _f16s,_lts1lo 0x170, %r38
	  qppermb,4	%r18, %r16, %r12, %r40
	  ldqp,5	%r0, _f16s,_lts1hi 0x1f0, %r39
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x160, %r42
	  qppermb,1	%r20, %r19, %r12, %r46
	  ldqp,2	%r0, _f16s,_lts0hi 0x1e0, %r43
	  ldqp,3	%r0, _f16s,_lts1lo 0x210, %r44
	  qppermb,4	%r13, %r11, %r12, %r47
	  ldqp,5	%r0, _f16s,_lts1hi 0x290, %r45
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x200, %r48
	  qppermb,1	%r22, %r21, %r12, %r52
	  ldqp,2	%r0, _f16s,_lts0hi 0x280, %r49
	  ldqp,3	%r0, _f16s,_lts1lo 0x230, %r50
	  qppermb,4	%r15, %r14, %r12, %r53
	  ldqp,5	%r0, _f16s,_lts1hi 0x2b0, %r51
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x220, %r54
	  qppermb,1	%r10, %r9, %r17, %r9
	  ldqp,2	%r0, _f16s,_lts0hi 0x2a0, %r55
	  ldqp,3	%r0, _f16s,_lts1lo 0x310, %r56
	  qppermb,4	%r20, %r19, %r17, %r10
	  ldqp,5	%r0, _f16s,_lts1hi 0x390, %r57
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x300, %r19
	  qppermb,1	%r13, %r11, %r17, %r11
	  ldqp,2	%r0, _f16s,_lts0hi 0x380, %r20
	  ldqp,3	%r0, _f16s,_lts1lo 0x330, %r58
	  qppermb,4	%r22, %r21, %r17, %r13
	  ldqp,5	%r0, _f16s,_lts1hi 0x3b0, %r59
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x320, %r21
	  qppermb,1	%r15, %r14, %r17, %r14
	  ldqp,2	%r0, _f16s,_lts0hi 0x3a0, %r22
	  ldqp,3	%r0, _f16s,_lts1lo 0x250, %r60
	  qppermb,4	%r5, %r4, %r17, %r4
	  ldqp,5	%r0, _f16s,_lts1hi 0x2d0, %r61
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x240, %r5
	  qppermb,1	%r18, %r16, %r17, %r16
	  ldqp,2	%r0, _f16s,_lts0hi 0x2c0, %r15
	  ldqp,3	%r0, _f16s,_lts1lo 0x270, %r62
	  qppermb,4	%r7, %r6, %r17, %r6
	  ldqp,5	%r0, _f16s,_lts1hi 0x2f0, %r63
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x260, %r7
	  qppermb,1	%r24, %r23, %r12, %b[10]
	  ldqp,2	%r0, _f16s,_lts0hi 0x2e0, %r18
	  ldqp,3	%r0, _f16s,_lts1lo 0x350, %b[8]
	  qppermb,4	%r33, %r32, %r12, %b[11]
	  ldqp,5	%r0, _f16s,_lts1hi 0x3d0, %b[9]
	}
	{
	  ldqp,0	%r0, _f16s,_lts0lo 0x340, %b[12]
	  qppermb,1	%r27, %r26, %r12, %b[16]
	  ldqp,2	%r0, _f16s,_lts0hi 0x3c0, %b[13]
	  ldqp,3	%r0, _f16s,_lts1hi 0x3f0, %b[15]
	  qppermb,4	%r37, %r36, %r12, %b[17]
	  ldqp,5	%r0, _f16s,_lts1lo 0x370, %b[14]
	}
	{
	  ldqp,0	%r0, _f16s,_lts0hi 0x3e0, %b[19]
	  qppermb,1	%r29, %r28, %r12, %b[20]
	  ldqp,2	%r0, _f16s,_lts0lo 0x360, %b[18]
	  qppermb,3	%r39, %r38, %r12, %b[21]
	  qppermb,4	%r24, %r23, %r17, %r23
	  addd,5,sm	0x0, %r35, %b[1]
	}
	{
	  qppermb,0	%r33, %r32, %r17, %r24
	  qppermb,1	%r27, %r26, %r17, %r26
	  qppermb,3	%r37, %r36, %r17, %r27
	  qppermb,4	%r29, %r28, %r17, %r28
	}
	{
	  qppermb,0	%r39, %r38, %r17, %r29
	  qppermb,1	%r31, %r30, %r17, %r32
	  qppermb,3	%r43, %r42, %r17, %r33
	  qppermb,4	%r31, %r30, %r12, %r30
	}
	{
	  qppermb,0	%r43, %r42, %r12, %r31
	  qppermb,1	%r45, %r44, %r17, %r36
	  qppermb,3	%r57, %r56, %r17, %r37
	  qppermb,4	%r45, %r44, %r12, %r38
	}
	{
	  qppermb,0	%r57, %r56, %r12, %r39
	  qppermb,1	%r49, %r48, %r17, %r42
	  qppermb,3	%r20, %r19, %r17, %r43
	  qppermb,4	%r49, %r48, %r12, %r44
	}
	{
	  qppermb,0	%r20, %r19, %r12, %r19
	  qppermb,1	%r51, %r50, %r17, %r20
	  qppermb,3	%r59, %r58, %r17, %r45
	  qppermb,4	%r51, %r50, %r12, %r48
	}
	{
	  qppermb,0	%r59, %r58, %r12, %r49
	  qppermb,1	%r55, %r54, %r17, %r50
	  qppermb,3	%r22, %r21, %r17, %r51
	  qppermb,4	%r55, %r54, %r12, %r54
	}
	{
	  qppermb,0	%r22, %r21, %r12, %r21
	  qppermb,1	%r61, %r60, %r17, %r22
	  qppermb,3	%b[9], %b[8], %r17, %r55
	  qppermb,4	%r61, %r60, %r12, %r56
	}
	{
	  qppermb,0	%b[9], %b[8], %r12, %r57
	  qppermb,1	%r15, %r5, %r17, %r58
	  qppermb,3	%b[13], %b[12], %r17, %r59
	  qppermb,4	%r15, %r5, %r12, %r5
	}
	{
	  qppermb,0	%b[13], %b[12], %r12, %r15
	  qppermb,1	%r63, %r62, %r17, %r60
	  qppermb,3	%b[15], %b[14], %r17, %r61
	  qppermb,4	%r63, %r62, %r12, %r62
	}
	{
	  qppermb,0	%b[15], %b[14], %r12, %r63
	  qppermb,1	%r18, %r7, %r17, %b[8]
	  qppermb,3	%b[19], %b[18], %r17, %b[9]
	  qppermb,4	%r18, %r7, %r12, %r7
	}
	{
	  qppermb,0	%b[19], %b[18], %r12, %r18
	  qppermb,1	%r46, %r41, %r17, %b[12]
	  qppermb,3	%r46, %r41, %r12, %r41
	  qppermb,4	%r40, %r34, %r17, %r46
	}
	{
	  qppermb,0	%r40, %r34, %r12, %r34
	  qppermb,1	%r53, %r25, %r17, %r40
	  stqp,2	%r2, _f16s,_lts0lo 0xfcc0, %b[12]
	  qppermb,3	%r53, %r25, %r12, %r25
	  qppermb,4	%r52, %r47, %r17, %r53
	  stqp,5	%r2, _f16s,_lts0hi 0xfca0, %r41
	}
	{
	  qppermb,0	%r52, %r47, %r12, %r41
	  qppermb,1	%r10, %r9, %r17, %r47
	  stqp,2	%r2, _f16s,_lts0hi 0xfbe0, %r34
	  qppermb,3	%r10, %r9, %r12, %r9
	  qppermb,4	%r13, %r11, %r17, %r10
	  stqp,5	%r2, _f16s,_lts0lo 0xfc00, %r46
	}
	{
	  qppermb,0	%r13, %r11, %r12, %r11
	  qppermb,1	%r14, %r4, %r17, %r13
	  stqp,2	%r2, _f16s,_lts0lo 0xfc40, %r40
	  qppermb,3	%r14, %r4, %r12, %r4
	  qppermb,4	%r16, %r6, %r17, %r14
	  stqp,5	%r2, _f16s,_lts0hi 0xfc20, %r25
	}
	{
	  qppermb,0	%r16, %r6, %r12, %r6
	  qppermb,1	%b[11], %b[10], %r17, %r16
	  stqp,2	%r2, _f16s,_lts0lo 0xfc80, %r53
	  qppermb,3	%b[11], %b[10], %r12, %r25
	  qppermb,4	%b[17], %b[16], %r17, %r34
	  stqp,5	%r2, _f16s,_lts0hi 0xfcb0, %r9
	}
	{
	  qppermb,0	%b[17], %b[16], %r12, %r9
	  qppermb,1	%b[21], %b[20], %r17, %r40
	  stqp,2	%r2, _f16s,_lts0lo 0xfc60, %r41
	  qppermb,3	%b[21], %b[20], %r12, %r46
	  qppermb,4	%r24, %r23, %r17, %r52
	  stqp,5	%r2, _f16s,_lts0hi 0xfcd0, %r47
	}
	{
	  qppermb,0	%r24, %r23, %r12, %r23
	  qppermb,1	%r27, %r26, %r17, %r24
	  stqp,2	%r2, _f16s,_lts0lo 0xfc90, %r10
	  qppermb,3	%r27, %r26, %r12, %r26
	  qppermb,4	%r29, %r28, %r17, %r27
	  stqp,5	%r2, _f16s,_lts0hi 0xfc70, %r11
	}
	{
	  qppermb,0	%r29, %r28, %r12, %r10
	  qppermb,1	%r33, %r32, %r17, %r11
	  stqp,2	%r2, _f16s,_lts0lo 0xfc50, %r13
	  qppermb,3	%r33, %r32, %r12, %r28
	  qppermb,4	%r31, %r30, %r17, %r29
	  stqp,5	%r2, _f16s,_lts0hi 0xfc30, %r4
	}
	{
	  qppermb,0	%r31, %r30, %r12, %r4
	  qppermb,1	%r37, %r36, %r17, %r13
	  stqp,2	%r2, _f16s,_lts0lo 0xfc10, %r14
	  qppermb,3	%r37, %r36, %r12, %r30
	  qppermb,4	%r39, %r38, %r17, %r31
	  stqp,5	%r2, _f16s,_lts0hi 0xfbf0, %r6
	}
	{
	  qppermb,0	%r39, %r38, %r12, %r6
	  qppermb,1	%r43, %r42, %r17, %r14
	  stqp,2	%r2, _f16s,_lts0lo 0xfd40, %r16
	  qppermb,3	%r43, %r42, %r12, %r32
	  qppermb,4	%r19, %r44, %r17, %r33
	  stqp,5	%r2, _f16s,_lts0hi 0xfd20, %r25
	}
	{
	  qppermb,0	%r19, %r44, %r12, %r16
	  qppermb,1	%r45, %r20, %r17, %r19
	  stqp,2	%r2, _f16s,_lts0lo 0xfd00, %r34
	  qppermb,3	%r45, %r20, %r12, %r20
	  qppermb,4	%r49, %r48, %r17, %r25
	  stqp,5	%r2, _f16s,_lts0hi 0xfce0, %r9
	}
	{
	  qppermb,0	%r49, %r48, %r12, %r9
	  qppermb,1	%r51, %r50, %r17, %r34
	  stqp,2	%r2, _f16s,_lts0lo 0xfdc0, %r40
	  qppermb,3	%r51, %r50, %r12, %r36
	  qppermb,4	%r21, %r54, %r17, %r37
	  stqp,5	%r2, _f16s,_lts0hi 0xfda0, %r46
	}
	{
	  qppermb,0	%r21, %r54, %r12, %r21
	  qppermb,1	%r55, %r22, %r17, %r38
	  stqp,2	%r2, _f16s,_lts0lo 0xfd50, %r52
	  qppermb,3	%r55, %r22, %r12, %r22
	  qppermb,4	%r57, %r56, %r17, %r39
	  stqp,5	%r2, _f16s,_lts0hi 0xfd30, %r23
	}
	{
	  qppermb,0	%r57, %r56, %r12, %r23
	  qppermb,1	%r59, %r58, %r17, %r40
	  stqp,2	%r2, _f16s,_lts0lo 0xfd10, %r24
	  qppermb,3	%r59, %r58, %r12, %r41
	  qppermb,4	%r15, %r5, %r17, %r42
	  stqp,5	%r2, _f16s,_lts0hi 0xfcf0, %r26
	}
	{
	  qppermb,0	%r15, %r5, %r12, %r5
	  qppermb,1	%r61, %r60, %r17, %r15
	  stqp,2	%r2, _f16s,_lts0lo 0xfdd0, %r27
	  qppermb,3	%r61, %r60, %r12, %r24
	  qppermb,4	%r63, %r62, %r17, %r26
	  stqp,5	%r2, _f16s,_lts0hi 0xfdb0, %r10
	}
	{
	  qppermb,0	%r63, %r62, %r12, %r10
	  qppermb,1	%b[9], %b[8], %r17, %r27
	  stqp,2	%r2, _f16s,_lts0lo 0xfd90, %r11
	  qppermb,3	%b[9], %b[8], %r12, %r43
	  qppermb,4	%r18, %r7, %r17, %r44
	  stqp,5	%r2, _f16s,_lts0hi 0xfd70, %r28
	}
	{
	  qppermb,0	%r18, %r7, %r12, %r7
	  stqp,2	%r2, _f16s,_lts0lo 0xfd80, %r29
	  stqp,5	%r2, _f16s,_lts0hi 0xfd60, %r4
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xfe50, %r13
	  stqp,5	%r2, _f16s,_lts0hi 0xfe30, %r30
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xfe40, %r31
	  stqp,5	%r2, _f16s,_lts0hi 0xfe20, %r6
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xfe10, %r14
	  stqp,5	%r2, _f16s,_lts0hi 0xfdf0, %r32
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xfe00, %r33
	  stqp,5	%r2, _f16s,_lts0hi 0xfde0, %r16
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xfed0, %r19
	  stqp,5	%r2, _f16s,_lts0hi 0xfeb0, %r20
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xfec0, %r25
	  stqp,5	%r2, _f16s,_lts0hi 0xfea0, %r9
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xfe90, %r34
	  stqp,5	%r2, _f16s,_lts0hi 0xfe70, %r36
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xfe80, %r37
	  stqp,5	%r2, _f16s,_lts0hi 0xfe60, %r21
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xff50, %r38
	  stqp,5	%r2, _f16s,_lts0hi 0xff30, %r22
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xff40, %r39
	  stqp,5	%r2, _f16s,_lts0hi 0xff20, %r23
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xff10, %r40
	  stqp,5	%r2, _f16s,_lts0hi 0xfef0, %r41
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xff00, %r42
	  stqp,5	%r2, _f16s,_lts0hi 0xfee0, %r5
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xffd0, %r15
	  stqp,5	%r2, _f16s,_lts0hi 0xffb0, %r24
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xffc0, %r26
	  stqp,5	%r2, _f16s,_lts0hi 0xffa0, %r10
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xff90, %r27
	  stqp,5	%r2, _f16s,_lts0hi 0xff70, %r43
	}
	{
	  stqp,2	%r2, _f16s,_lts0lo 0xff80, %r44
	  stqp,5	%r2, _f16s,_lts0hi 0xff60, %r7
	}
.LCS.5:
	{
	  call	%ctpr1, wbs = 0x27
	}
	{
	  nop 4
	  disp	%ctpr1, scrypt_1024_core_2_cycle_elway
	  addd,0,sm	0x0, %r1, %b[2]
	  addd,1,sm	0x0, %r35, %b[1]
	  addd,2,sm	0x0, %r0, %b[0]
	}
	{
	  call	%ctpr1, wbs = 0x27
	}
	{
	  return	%ctpr3
	  ldqp,0	%r2, _f16s,_lts0lo 0xffc0, %g16
	  ldqp,2	%r2, _f16s,_lts0hi 0xffd0, %g17
	  ldqp,3	%r2, _f16s,_lts1lo 0xffa0, %g18
	  ldqp,5	%r2, _f16s,_lts1hi 0xffb0, %g19
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xff80, %g20
	  ldqp,2	%r2, _f16s,_lts0hi 0xff90, %g21
	  ldqp,3	%r2, _f16s,_lts1lo 0xff60, %g22
	  ldqp,5	%r2, _f16s,_lts1hi 0xff70, %g23
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xff40, %g24
	  ldqp,2	%r2, _f16s,_lts0hi 0xff50, %g25
	  ldqp,3	%r2, _f16s,_lts1lo 0xff20, %g26
	  ldqp,5	%r2, _f16s,_lts1hi 0xff30, %g27
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xff00, %g28
	  qppermb,1	%g17, %g16, %r17, %r1
	  ldqp,2	%r2, _f16s,_lts0hi 0xff10, %g29
	  ldqp,3	%r2, _f16s,_lts1lo 0xfee0, %g30
	  qppermb,4	%g19, %g18, %r17, %r4
	  ldqp,5	%r2, _f16s,_lts1hi 0xfef0, %g31
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfec0, %r5
	  qppermb,1	%g17, %g16, %r12, %g16
	  ldqp,2	%r2, _f16s,_lts0hi 0xfed0, %r6
	  ldqp,3	%r2, _f16s,_lts1lo 0xfea0, %r7
	  qppermb,4	%g19, %g18, %r12, %g17
	  ldqp,5	%r2, _f16s,_lts1hi 0xfeb0, %r9
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfe80, %g18
	  qppermb,1	%g21, %g20, %r17, %r13
	  ldqp,2	%r2, _f16s,_lts0hi 0xfe90, %g19
	  ldqp,3	%r2, _f16s,_lts1lo 0xfe60, %r10
	  qppermb,4	%g23, %g22, %r17, %r14
	  ldqp,5	%r2, _f16s,_lts1hi 0xfe70, %r11
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfe40, %r15
	  qppermb,1	%g21, %g20, %r12, %g20
	  ldqp,2	%r2, _f16s,_lts0hi 0xfe50, %r16
	  ldqp,3	%r2, _f16s,_lts1lo 0xfe20, %r18
	  qppermb,4	%g23, %g22, %r12, %g21
	  ldqp,5	%r2, _f16s,_lts1hi 0xfe30, %r19
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfe00, %g22
	  qppermb,1	%g27, %g26, %r17, %r23
	  ldqp,2	%r2, _f16s,_lts0hi 0xfe10, %g23
	  ldqp,3	%r2, _f16s,_lts1lo 0xfde0, %r20
	  qppermb,4	%g25, %g24, %r17, %r22
	  ldqp,5	%r2, _f16s,_lts1hi 0xfdf0, %r21
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfdc0, %r24
	  qppermb,1	%g27, %g26, %r12, %g25
	  ldqp,2	%r2, _f16s,_lts0hi 0xfdd0, %r25
	  ldqp,3	%r2, _f16s,_lts1lo 0xfda0, %r26
	  qppermb,4	%g25, %g24, %r12, %g24
	  ldqp,5	%r2, _f16s,_lts1hi 0xfdb0, %r27
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfd80, %g26
	  qppermb,1	%g31, %g30, %r17, %r31
	  ldqp,2	%r2, _f16s,_lts0hi 0xfd90, %g27
	  ldqp,3	%r2, _f16s,_lts1lo 0xfd60, %r28
	  qppermb,4	%g29, %g28, %r17, %r30
	  ldqp,5	%r2, _f16s,_lts1hi 0xfd70, %r29
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfd40, %r32
	  qppermb,1	%g31, %g30, %r12, %g29
	  ldqp,2	%r2, _f16s,_lts0hi 0xfd50, %r33
	  ldqp,3	%r2, _f16s,_lts1lo 0xfd20, %r34
	  qppermb,4	%g29, %g28, %r12, %g28
	  ldqp,5	%r2, _f16s,_lts1hi 0xfd30, %r35
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfd00, %g30
	  qppermb,1	%r9, %r7, %r17, %r39
	  ldqp,2	%r2, _f16s,_lts0hi 0xfd10, %g31
	  ldqp,3	%r2, _f16s,_lts1lo 0xfce0, %r36
	  qppermb,4	%r6, %r5, %r17, %r38
	  ldqp,5	%r2, _f16s,_lts1hi 0xfcf0, %r37
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfcc0, %r40
	  qppermb,1	%r9, %r7, %r12, %r6
	  ldqp,2	%r2, _f16s,_lts0hi 0xfcd0, %r41
	  ldqp,3	%r2, _f16s,_lts1lo 0xfca0, %r42
	  qppermb,4	%r6, %r5, %r12, %r5
	  ldqp,5	%r2, _f16s,_lts1hi 0xfcb0, %r43
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfc80, %r7
	  qppermb,1	%r11, %r10, %r17, %r47
	  ldqp,2	%r2, _f16s,_lts0hi 0xfc90, %r9
	  ldqp,3	%r2, _f16s,_lts1lo 0xfc60, %r44
	  qppermb,4	%g19, %g18, %r17, %r46
	  ldqp,5	%r2, _f16s,_lts1hi 0xfc70, %r45
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfc40, %r48
	  qppermb,1	%r11, %r10, %r12, %g19
	  ldqp,2	%r2, _f16s,_lts0hi 0xfc50, %r49
	  ldqp,3	%r2, _f16s,_lts1lo 0xfc20, %r50
	  qppermb,4	%g19, %g18, %r12, %g18
	  ldqp,5	%r2, _f16s,_lts1hi 0xfc30, %r51
	}
	{
	  ldqp,0	%r2, _f16s,_lts0lo 0xfc10, %r11
	  qppermb,1	%r19, %r18, %r17, %r55
	  ldqp,2	%r2, _f16s,_lts0hi 0xfc00, %r10
	  ldqp,3	%r2, _f16s,_lts1hi 0xfbf0, %r53
	  qppermb,4	%r16, %r15, %r17, %r54
	  ldqp,5	%r2, _f16s,_lts1lo 0xfbe0, %r52
	}
	{
	  qppermb,0	%r16, %r15, %r12, %r15
	  qppermb,1	%r19, %r18, %r12, %r16
	  qppermb,3	%g23, %g22, %r17, %r18
	  qppermb,4	%r21, %r20, %r17, %r19
	}
	{
	  qppermb,0	%g23, %g22, %r12, %g22
	  qppermb,1	%r21, %r20, %r12, %g23
	  qppermb,3	%r25, %r24, %r17, %r20
	  qppermb,4	%r27, %r26, %r17, %r21
	}
	{
	  qppermb,0	%r25, %r24, %r12, %r24
	  qppermb,1	%r27, %r26, %r12, %r25
	  qppermb,3	%g27, %g26, %r17, %r26
	  qppermb,4	%r29, %r28, %r17, %r27
	}
	{
	  qppermb,0	%g27, %g26, %r12, %g26
	  qppermb,1	%r29, %r28, %r12, %g27
	  qppermb,3	%r33, %r32, %r17, %r28
	  qppermb,4	%r35, %r34, %r17, %r29
	}
	{
	  qppermb,0	%r33, %r32, %r12, %r32
	  qppermb,1	%r35, %r34, %r12, %r33
	  qppermb,3	%g31, %g30, %r17, %r34
	  qppermb,4	%r37, %r36, %r17, %r35
	}
	{
	  qppermb,0	%g31, %g30, %r12, %g30
	  qppermb,1	%r37, %r36, %r12, %g31
	  qppermb,3	%r41, %r40, %r17, %r36
	  qppermb,4	%r43, %r42, %r17, %r37
	}
	{
	  qppermb,0	%r41, %r40, %r12, %r40
	  qppermb,1	%r43, %r42, %r12, %r41
	  qppermb,3	%r9, %r7, %r17, %r42
	  qppermb,4	%r45, %r44, %r17, %r43
	}
	{
	  qppermb,0	%r9, %r7, %r12, %r7
	  qppermb,1	%r45, %r44, %r12, %r9
	  qppermb,3	%r49, %r48, %r17, %r44
	  qppermb,4	%r51, %r50, %r17, %r45
	}
	{
	  qppermb,0	%r49, %r48, %r12, %r48
	  qppermb,1	%r51, %r50, %r12, %r49
	  qppermb,3	%r11, %r10, %r17, %r50
	  qppermb,4	%r53, %r52, %r17, %r51
	}
	{
	  qppermb,0	%r11, %r10, %r12, %r10
	  qppermb,1	%r53, %r52, %r12, %r11
	  qppermb,3	%r1, %r4, %r17, %r52
	  qppermb,4	%r1, %r4, %r12, %r1
	}
	{
	  qppermb,0	%g16, %g17, %r17, %r4
	  qppermb,1	%g16, %g17, %r12, %g16
	  qppermb,3	%r13, %r14, %r17, %g17
	  qppermb,4	%r13, %r14, %r12, %r13
	  stqp,5	%r0, _f16s,_lts0lo 0x3f0, %r52
	}
	{
	  qppermb,0	%g20, %g21, %r17, %r14
	  qppermb,1	%g20, %g21, %r12, %g20
	  stqp,2	%r0, _f16s,_lts0hi 0x370, %r4
	  qppermb,3	%r22, %r23, %r17, %g21
	  qppermb,4	%r22, %r23, %r12, %r22
	  stqp,5	%r0, _f16s,_lts0lo 0x2f0, %r1
	}
	{
	  qppermb,0	%g24, %g25, %r17, %r1
	  qppermb,1	%g24, %g25, %r12, %g24
	  stqp,2	%r0, _f16s,_lts0lo 0x270, %g16
	  qppermb,3	%r30, %r31, %r17, %g25
	  qppermb,4	%r30, %r31, %r12, %r4
	  stqp,5	%r0, _f16s,_lts0hi 0x3e0, %g17
	}
	{
	  qppermb,0	%g28, %g29, %r17, %g16
	  qppermb,1	%g28, %g29, %r12, %g17
	  stqp,2	%r0, _f16s,_lts0lo 0x2e0, %r13
	  qppermb,3	%r38, %r39, %r17, %g28
	  qppermb,4	%r38, %r39, %r12, %g29
	  stqp,5	%r0, _f16s,_lts0hi 0x3d0, %g21
	}
	{
	  qppermb,0	%r5, %r6, %r17, %g21
	  qppermb,1	%r5, %r6, %r12, %r5
	  stqp,2	%r0, _f16s,_lts0lo 0x360, %r14
	  qppermb,3	%r46, %r47, %r17, %r6
	  qppermb,4	%r46, %r47, %r12, %r13
	  stqp,5	%r0, _f16s,_lts0hi 0x260, %g20
	}
	{
	  qppermb,0	%r15, %r16, %r17, %g20
	  qppermb,1	%r15, %r16, %r12, %r14
	  stqp,2	%r0, _f16s,_lts0lo 0x2d0, %r22
	  qppermb,3	%r18, %r19, %r17, %r15
	  qppermb,4	%r18, %r19, %r12, %r16
	  stqp,5	%r0, _f16s,_lts0hi 0x350, %r1
	}
	{
	  qppermb,0	%g18, %g19, %r17, %r1
	  qppermb,1	%g18, %g19, %r12, %g18
	  stqp,2	%r0, _f16s,_lts0lo 0x250, %g24
	  qppermb,3	%g22, %g23, %r17, %g19
	  qppermb,4	%g22, %g23, %r12, %g22
	  stqp,5	%r0, _f16s,_lts0hi 0x3c0, %g25
	}
	{
	  qppermb,0	%r20, %r21, %r17, %g23
	  qppermb,1	%r20, %r21, %r12, %g24
	  stqp,2	%r0, _f16s,_lts0lo 0x2c0, %r4
	  qppermb,3	%r54, %r55, %r17, %g25
	  qppermb,4	%r54, %r55, %r12, %r18
	  stqp,5	%r0, _f16s,_lts0hi 0x340, %g16
	}
	{
	  qppermb,0	%r24, %r25, %r17, %g16
	  qppermb,1	%r24, %r25, %r12, %r4
	  stqp,2	%r0, _f16s,_lts0lo 0x240, %g17
	  qppermb,3	%r26, %r27, %r17, %r19
	  qppermb,4	%r26, %r27, %r12, %r20
	  stqp,5	%r0, _f16s,_lts0hi 0x3b0, %g28
	}
	{
	  qppermb,0	%g26, %g27, %r17, %g17
	  qppermb,1	%g26, %g27, %r12, %g26
	  stqp,2	%r0, _f16s,_lts0lo 0x2b0, %g29
	  qppermb,3	%r28, %r29, %r17, %g27
	  qppermb,4	%r28, %r29, %r12, %g28
	  stqp,5	%r0, _f16s,_lts0hi 0x330, %g21
	}
	{
	  qppermb,0	%r32, %r33, %r17, %g21
	  qppermb,1	%r32, %r33, %r12, %g29
	  stqp,2	%r0, _f16s,_lts0lo 0x230, %r5
	  qppermb,3	%r34, %r35, %r17, %r21
	  qppermb,4	%r34, %r35, %r12, %r22
	  stqp,5	%r0, _f16s,_lts0hi 0x3a0, %r6
	}
	{
	  qppermb,0	%g30, %g31, %r17, %r5
	  qppermb,1	%g30, %g31, %r12, %g30
	  stqp,2	%r0, _f16s,_lts0lo 0x2a0, %r13
	  qppermb,3	%r36, %r37, %r17, %g31
	  qppermb,4	%r36, %r37, %r12, %r6
	  stqp,5	%r0, _f16s,_lts0hi 0x310, %g20
	}
	{
	  qppermb,0	%r40, %r41, %r17, %g20
	  qppermb,1	%r40, %r41, %r12, %r13
	  stqp,2	%r0, _f16s,_lts0lo 0x210, %r14
	  qppermb,3	%r42, %r43, %r17, %r23
	  qppermb,4	%r42, %r43, %r12, %r24
	  stqp,5	%r0, _f16s,_lts0hi 0x380, %r15
	}
	{
	  qppermb,0	%r7, %r9, %r17, %r14
	  qppermb,1	%r7, %r9, %r12, %r7
	  stqp,2	%r0, _f16s,_lts0lo 0x280, %r16
	  qppermb,3	%r44, %r45, %r17, %r9
	  qppermb,4	%r44, %r45, %r12, %r15
	  stqp,5	%r0, _f16s,_lts0hi 0x320, %r1
	}
	{
	  qppermb,0	%r48, %r49, %r17, %r1
	  qppermb,1	%r48, %r49, %r12, %r16
	  stqp,2	%r0, _f16s,_lts0lo 0x220, %g18
	  qppermb,3	%r50, %r51, %r17, %r25
	  qppermb,4	%r50, %r51, %r12, %r26
	  stqp,5	%r0, _f16s,_lts0hi 0x300, %g19
	}
	{
	  qppermb,0	%r10, %r11, %r17, %g18
	  qppermb,1	%r10, %r11, %r12, %g19
	  stqp,2	%r0, _f16s,_lts0lo 0x200, %g22
	  stqp,5	%r0, _f16s,_lts0hi 0x1f0, %g23
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0xf0, %g24
	  stqp,5	%r0, _f16s,_lts0hi 0x390, %g25
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x290, %r18
	  stqp,5	%r0, _f16s,_lts0hi 0x170, %g16
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x70, %r4
	  stqp,5	%r0, _f16s,_lts0hi 0x1e0, %r19
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0xe0, %r20
	  stqp,5	%r0, _f16s,_lts0hi 0x160, %g17
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x60, %g26
	  stqp,5	%r0, _f16s,_lts0hi 0x1d0, %g27
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0xd0, %g28
	  stqp,5	%r0, _f16s,_lts0hi 0x150, %g21
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x50, %g29
	  stqp,5	%r0, _f16s,_lts0hi 0x1c0, %r21
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0xc0, %r22
	  stqp,5	%r0, _f16s,_lts0hi 0x140, %r5
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x40, %g30
	  stqp,5	%r0, _f16s,_lts0hi 0x1b0, %g31
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0xb0, %r6
	  stqp,5	%r0, _f16s,_lts0hi 0x130, %g20
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x30, %r13
	  stqp,5	%r0, _f16s,_lts0hi 0x1a0, %r23
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0xa0, %r24
	  stqp,5	%r0, _f16s,_lts0hi 0x120, %r14
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x20, %r7
	  stqp,5	%r0, _f16s,_lts0hi 0x190, %r9
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x90, %r15
	  stqp,5	%r0, _f16s,_lts0hi 0x110, %r1
	}
	{
	  stqp,2	0x10, %r0, %r16
	  stqp,5	%r0, _f16s,_lts0lo 0x180, %r25
	}
	{
	  stqp,2	%r0, _f16s,_lts0lo 0x80, %r26
	  stqp,5	%r0, _f16s,_lts0hi 0x100, %g18
	}
	{
	  ct	%ctpr3
	  stqp,2	%r0, 0x0, %g19
	}
.LCS.6:
	.size	scrypt_1024_core_elway, .- scrypt_1024_core_elway
	.global	scrypt_1024_1_1_256_elway
	.type	scrypt_1024_1_1_256_elway, #function
	.align	8
scrypt_1024_1_1_256_elway:
	{
	  setwd	wsz = 0x25, nfx = 0x0, dbl = 0x0
	  setbn	rsz = 0x4, rbs = 0x20, rcur = 0x1
	  disp	%ctpr2, HMAC_SHA256_80_init
	  getsp,0	_f32s,_lts2 0xfffff720, %r6
	  adds,1	0x0, _f16s,_lts1hi 0x208, %r16
	  ldw,2	%r2, 0x4, %r14
	  ldw,3	%r2, 0xc, %r12
	  adds,4	0x0, _f16s,_lts1lo 0x210, %r15
	  ldw,5	%r2, 0x8, %r13
	}
	{
	  ldw,0	%r2, 0x0, %r17
	  scls,1	0x1, 0x9, %r32
	  ldw,2	0x1c, %r2, %r18
	  ldw,3	0x18, %r2, %r19
	  adds,4	0x0, _f16s,_lts0lo 0x218, %r33
	  ldw,5	0x14, %r2, %r31
	}
	{
	  addd,0	%r6, _f64,_lts2 0x8e0, %r5
	  addd,1,sm	0x0, %r0, %b[0]
	  ldw,2	0x10, %r2, %r6
	  addd,3	%r0, _f16s,_lts0lo 0x50, %r34
	  addd,4	%r0, _f16s,_lts0hi 0xa0, %r35
	  addd,5	%r0, _f16s,_lts1lo 0xf0, %r36
	}
	{
	  getfs,0,sm	%r14, %r15, %r40
	  getfs,1,sm	%r14, %r33, %r41
	  getfs,2,sm	%r14, %r16, %r42
	  getfs,3,sm	%r12, %r15, %r37
	  getfs,4,sm	%r12, %r33, %r38
	  getfs,5,sm	%r13, %r15, %r39
	}
	{
	  getfs,0,sm	%r13, %r33, %r43
	  getfs,1,sm	%r13, %r16, %r44
	  getfs,2,sm	%r13, %r32, %r45
	  getfs,3,sm	%r12, %r16, %r46
	  getfs,4,sm	%r12, %r32, %r47
	  getfs,5,sm	%r14, %r32, %r48
	}
	{
	  getfs,0,sm	%r17, %r15, %r49
	  getfs,1,sm	%r17, %r33, %r50
	  getfs,2,sm	%r17, %r16, %r51
	  getfs,3,sm	%r17, %r32, %r52
	  getfs,4,sm	%r18, %r15, %r53
	  getfs,5,sm	%r18, %r33, %r54
	}
	{
	  getfs,0,sm	%r18, %r16, %r55
	  getfs,1,sm	%r18, %r32, %r56
	  getfs,2,sm	%r19, %r15, %r57
	  getfs,3,sm	%r19, %r33, %r58
	  getfs,4,sm	%r19, %r16, %r59
	  getfs,5,sm	%r19, %r32, %r60
	}
	{
	  getfs,0,sm	%r31, %r15, %r61
	  getfs,1,sm	%r31, %r33, %r62
	  getfs,2,sm	%r31, %r16, %r63
	  getfs,3,sm	%r31, %r32, %b[8]
	  getfs,4,sm	%r6, %r16, %r16
	  getfs,5,sm	%r6, %r32, %r32
	}
	{
	  getfs,0,sm	%r6, %r15, %r15
	  insfs,1	%r38, _f16s,_lts0lo 0x218, %r37, %r37
	  getfs,2,sm	%r6, %r33, %r33
	  insfs,3	%r46, _lit16_ref,_lts0lo 0x218, %r47, %r38
	  insfs,4	%r41, _lit16_ref,_lts0lo 0x218, %r40, %r40
	  addd,5	%r5, _f16s,_lts0hi 0xff00, %r7
	}
	{
	  insfs,0	%r42, _f16s,_lts0lo 0x218, %r48, %r41
	  insfs,1	%r43, _lit16_ref,_lts0lo 0x218, %r39, %r39
	  addd,2	%r5, _f16s,_lts0hi 0xfe00, %r2
	  insfs,3	%r44, _lit16_ref,_lts0lo 0x218, %r45, %r42
	  insfs,4	%r50, _lit16_ref,_lts0lo 0x218, %r49, %r43
	  addd,5,sm	0x0, %r7, %b[1]
	}
	{
	  insfs,0	%r51, _f16s,_lts0lo 0x218, %r17, %r44
	  insfs,1	%r51, _lit16_ref,_lts0lo 0x218, %r52, %r45
	  addd,2,sm	0x0, %r2, %b[2]
	  insfs,3	%r54, _lit16_ref,_lts0lo 0x218, %r53, %r46
	  insfs,4	%r55, _lit16_ref,_lts0lo 0x218, %r56, %r47
	  addd,5	%r5, _f16s,_lts0hi 0xfe20, %r30
	}
	{
	  insfs,0	%r59, _f16s,_lts0lo 0x218, %r60, %r48
	  insfs,1	%r58, _lit16_ref,_lts0lo 0x218, %r57, %r49
	  addd,2	%r5, _f16s,_lts0hi 0xff20, %r52
	  insfs,3	%r62, _lit16_ref,_lts0lo 0x218, %r61, %r50
	  insfs,4	%r63, _lit16_ref,_lts0lo 0x218, %b[8], %r51
	  addd,5	%r5, _f16s,_lts1lo 0xfe40, %r25
	}
	{
	  insfs,0	%r16, _f16s,_lts0lo 0x218, %r32, %r16
	  insfs,1	%r33, _lit16_ref,_lts0lo 0x218, %r15, %r15
	  addd,2	%r5, _f16s,_lts0hi 0xff40, %r37
	  insfs,3	%r37, _f16s,_lts1lo 0x410, %r38, %r32
	  insfs,4	%r39, _lit16_ref,_lts1lo 0x410, %r42, %r33
	  addd,5	%r5, _f16s,_lts1hi 0xff60, %r38
	}
	{
	  insfs,0	%r40, _f16s,_lts0lo 0x410, %r41, %r39
	  insfs,1	%r43, _lit16_ref,_lts0lo 0x410, %r44, %r40
	  addd,2	%r5, _f16s,_lts0hi 0xfe60, %r24
	  insfs,3	%r43, _lit16_ref,_lts0lo 0x410, %r45, %r41
	  insfs,4	%r46, _lit16_ref,_lts0lo 0x410, %r47, %r42
	  addd,5	%r0, _f16s,_lts1lo 0x140, %r43
	}
	{
	  insfs,0	%r49, _f16s,_lts0lo 0x410, %r48, %r44
	  insfs,1	%r50, _lit16_ref,_lts0lo 0x410, %r51, %r45
	  addd,2	%r5, _f16s,_lts0hi 0xfe80, %r23
	  insfs,3	%r15, _lit16_ref,_lts0lo 0x410, %r16, %r15
	  insfd,4	%r12, _f32s,_lts2 0xa820, %r13, %r12
	  addd,5	%r5, _f16s,_lts1lo 0xff80, %r13
	}
	{
	  insfd,0	%r14, _f32s,_lts2 0xa820, %r17, %r14
	  insfd,1	%r18, _lit32_ref,_lts2 0xa820, %r19, %r16
	  std,2	%r5, _f16s,_lts0lo 0xff08, %r12
	  insfd,3	%r31, _lit32_ref,_lts2 0xa820, %r6, %r6
	  addd,4	%r0, _f16s,_lts0hi 0x190, %r12
	  addd,5	%r5, _f16s,_lts1lo 0xfea0, %r28
	}
	{
	  insfd,0	%r32, _f32s,_lts2 0xa820, %r33, %r17
	  addd,1	%r5, _f16s,_lts0lo 0xffa0, %r29
	  std,2	%r5, _f16s,_lts0hi 0xff00, %r14
	  addd,3	%r0, _f16s,_lts1lo 0x1e0, %r14
	  addd,4	%r5, _f32s,_lts3 0xfffffec0, %r27
	  std,5	%r5, _f16s,_lts1hi 0xff18, %r16
	}
	{
	  insfd,0	%r39, _f32s,_lts2 0xa820, %r40, %r16
	  insfd,1	%r39, _lit32_ref,_lts2 0xa820, %r41, %r18
	  std,2	%r5, _f16s,_lts0lo 0xff10, %r6
	  addd,3	%r5, _f16s,_lts0hi 0xffc0, %r6
	  addd,4	%r0, _f16s,_lts1hi 0x230, %r19
	  std,5	%r5, _f16s,_lts1lo 0xffc8, %r17
	}
	{
	  insfd,0	%r42, _f32s,_lts2 0xa820, %r44, %r31
	  insfd,1	%r45, _lit32_ref,_lts2 0xa820, %r15, %r15
	  std,2	%r5, _f16s,_lts0lo 0xff88, %r17
	  addd,3	%r5, _f16s,_lts1lo 0xfee0, %r22
	  addd,4,sm	0x0, %r3, %r26
	  std,5	%r5, _f16s,_lts0hi 0xffe8, %r17
	}
	{
	  addd,0	%r5, _f16s,_lts0lo 0xfa00, %r3
	  addd,1	0x0, [ _f64,_lts2 outerpad +32 ], %r32
	  std,2	%r5, _f16s,_lts0hi 0xff48, %r17
	  addd,3	%r5, _f16s,_lts1hi 0xf760, %r33
	  std,5	%r5, _f16s,_lts1lo 0xffa8, %r17
	}
	{
	  addd,0	0x0, [ _f64,_lts2 innerpad +44 ], %r17
	  addd,1	%r5, _f16s,_lts0lo 0xf7c0, %r20
	  std,2	%r5, _f16s,_lts0hi 0xff28, %r17
	  addd,3	%r5, _f16s,_lts1hi 0xf794, %r10
	  std,5	%r5, _f16s,_lts1lo 0xff68, %r17
	}
	{
	  addd,0	%r5, _f16s,_lts1lo 0xf780, %r21
	  cmpledb,1	%r32, %r33, %pred0
	  std,2	%r5, _f16s,_lts0lo 0xff20, %r16
	  cmpledb,3	%r32, %r10, %pred1
	  std,5	%r5, _f16s,_lts0hi 0xffa0, %r18
	}
	{
	  cmpledb,0	%r17, %r33, %pred2
	  cmpledb,1	%r21, [ _f64,_lts1 innerpad ], %pred3
	  std,2	%r5, _f16s,_lts0lo 0xffe0, %r18
	  cmpledb,3	%r20, %r33, %pred4
	  cmpledb,4	%r20, _lit64_ref,_lts1 0x0, %pred5
	  std,5	%r5, _f16s,_lts0hi 0xff60, %r18
	}
	{
	  cmpledb,0	%r21, %r10, %pred6
	  cmpledb,1	%r20, [ _f64,_lts1 outerpad ], %pred7
	  std,2	%r5, _f16s,_lts0lo 0xffc0, %r18
	  cmpledb,3	%r21, _lit64_ref,_lts1 0x0, %pred8
	  cmpledb,4	%r17, %r10, %pred3
	  std,5	%r5, _f16s,_lts0hi 0xff40, %r18
	  pass	%pred2, @p0
	  pass	%pred3, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred2
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xff80, %r18
	  std,5	%r5, _f16s,_lts0hi 0xffb8, %r31
	  pass	%pred4, @p0
	  pass	%pred6, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred4
	  pass	%pred0, @p2
	  pass	%pred8, @p3
	  landp	~@p2, ~@p3, @p5
	  pass	@p5, %pred0
	  landp	~@p5, ~@p4, @p6
	  pass	@p6, %pred6
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xfff8, %r31
	  std,5	%r5, _f16s,_lts0hi 0xff78, %r31
	  pass	%pred7, @p0
	  pass	%pred1, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred0
	  pass	%pred2, @p2
	  landp	~@p4, ~@p2, @p5
	  pass	@p5, %pred1
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xffd8, %r31
	  std,5	%r5, _f16s,_lts0hi 0xff38, %r31
	  pass	%pred3, @p0
	  pass	%pred5, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred0
	  pass	%pred6, @p2
	  pass	%pred1, @p3
	  landp	@p2, @p3, @p5
	  pass	@p5, %pred1
	  landp	@p5, ~@p4, @p6
	  pass	@p6, %pred2
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xff98, %r31
	  std,5	%r5, _f16s,_lts0hi 0xff58, %r31
	}
	{
	  addd,0,sm	%r5, _f16s,_lts0lo 0xf740, %r11 ? %pred2
	  addd,1,sm	%r5, _f16s,_lts1hi 0xfd80, %r9 ? %pred2
	  std,2	%r5, _f16s,_lts0hi 0xffd0, %r15
	  std,5	%r5, _f16s,_lts1lo 0xff90, %r15
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xfff0, %r15
	  std,5	%r5, _f16s,_lts0hi 0xff50, %r15
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xffb0, %r15
	  std,5	%r5, _f16s,_lts0hi 0xff30, %r15
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xff70, %r15
	}
.LCS.7:
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr1, HMAC_SHA256_80_init
	  addd,0,sm	0x0, %r30, %b[2]
	  addd,1,sm	0x0, %r52, %b[1]
	  addd,2,sm	0x0, %r34, %b[0]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, HMAC_SHA256_80_init
	  addd,0,sm	0x0, %r25, %b[2]
	  addd,1,sm	0x0, %r37, %b[1]
	  addd,2,sm	0x0, %r35, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr2, HMAC_SHA256_80_init
	  addd,0,sm	0x0, %r24, %b[2]
	  addd,1,sm	0x0, %r38, %b[1]
	  addd,2,sm	0x0, %r36, %b[0]
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr1, HMAC_SHA256_80_init
	  addd,0,sm	0x0, %r23, %b[2]
	  addd,1,sm	0x0, %r13, %b[1]
	  addd,2,sm	0x0, %r43, %b[0]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, HMAC_SHA256_80_init
	  addd,0,sm	0x0, %r28, %b[2]
	  addd,1,sm	0x0, %r29, %b[1]
	  addd,2,sm	0x0, %r12, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr2, HMAC_SHA256_80_init
	  addd,0,sm	0x0, %r27, %b[2]
	  addd,1,sm	0x0, %r6, %b[1]
	  addd,2,sm	0x0, %r14, %b[0]
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr1, HMAC_SHA256_80_init
	  addd,0,sm	0x0, %r22, %b[2]
	  addd,1,sm	0x0, %r19, %b[0]
	  addd,2	%r5, _f16s,_lts0lo 0xffe0, %b[1]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, PBKDF2_SHA256_80_128
	  addd,0,sm	0x0, %r3, %b[3]
	  addd,1,sm	0x0, %r0, %b[2]
	  addd,2,sm	0x0, %r2, %b[1]
	  addd,3,sm	0x0, %r7, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr2, PBKDF2_SHA256_80_128
	  addd,0,sm	0x0, %r34, %b[2]
	  addd,1,sm	0x0, %r30, %b[1]
	  addd,2,sm	0x0, %r52, %b[0]
	  addd,3	%r5, _f16s,_lts0lo 0xfa80, %b[3]
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr1, PBKDF2_SHA256_80_128
	  addd,0,sm	0x0, %r35, %b[2]
	  addd,1,sm	0x0, %r25, %b[1]
	  addd,2,sm	0x0, %r37, %b[0]
	  addd,3	%r5, _f16s,_lts0lo 0xfb00, %b[3]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, PBKDF2_SHA256_80_128
	  addd,0,sm	0x0, %r36, %b[2]
	  addd,1,sm	0x0, %r24, %b[1]
	  addd,2,sm	0x0, %r38, %b[0]
	  addd,3	%r5, _f16s,_lts0lo 0xfb80, %b[3]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr2, PBKDF2_SHA256_80_128
	  addd,0,sm	0x0, %r43, %b[2]
	  addd,1,sm	0x0, %r23, %b[1]
	  addd,2,sm	0x0, %r13, %b[0]
	  addd,3	%r5, _f16s,_lts0lo 0xfc00, %b[3]
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr1, PBKDF2_SHA256_80_128
	  addd,0,sm	0x0, %r12, %b[2]
	  addd,1,sm	0x0, %r28, %b[1]
	  addd,2,sm	0x0, %r29, %b[0]
	  addd,3	%r5, _f16s,_lts0lo 0xfc80, %b[3]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, PBKDF2_SHA256_80_128
	  addd,0,sm	0x0, %r14, %b[2]
	  addd,1,sm	0x0, %r27, %b[1]
	  addd,2,sm	0x0, %r6, %b[0]
	  addd,3	%r5, _f16s,_lts0lo 0xfd00, %b[3]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  nop 3
	  disp	%ctpr2, sha256_transform
	  ldqp,0	%r5, _f16s,_lts0lo 0xfff0, %r6
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldqp,2	%r5, _f16s,_lts0hi 0xffe0, %r12
	  addd,3,sm	0x0, %r19, %b[1]
	  addd,4	%r5, _f16s,_lts1lo 0xf7e0, %b[0]
	}
	{
	  stqp,2	%r5, _f16s,_lts0lo 0xf7f0, %r6
	  stqp,5	%r5, _f16s,_lts0hi 0xf7e0, %r12
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  disp	%ctpr1, .L94180
	  ldw,0	%r0, _f16s,_lts0lo 0x27c, %g16
	  adds,1	0x0, 0x0, %r4 ? %pred2
	  ldw,2	%r0, _f16s,_lts0hi 0x278, %g17
	  ldw,3	%r0, _f16s,_lts1lo 0x274, %g18
	  ldw,5	%r0, _f16s,_lts1hi 0x270, %g19
	}
	{
	  ldqp,0,sm	0x0, [ _f64,_lts0 innerpad +16 ], %g20
	  ldqp,2,sm	0x0, [ _f64,_lts2 innerpad ], %g21
	}
	{
	  ldw,0,sm	0x0, [ _f64,_lts0 innerpad +32 ], %g22
	  ldb,2,sm	0x0, [ _f64,_lts2 innerpad +40 ], %g23
	}
	{
	  ldw,0,sm	0x0, [ _f64,_lts1 innerpad +36 ], %g18
	  insfd,1	%g16, _f32s,_lts0 0xa820, %g17, %g16
	  insfd,4	%g18, _lit32_ref,_lts0 0xa820, %g19, %g17
	}
	{
	  qpswitchd,0,sm	%g21, %g24
	  qpswitchd,1,sm	%g20, %g19
	  ldb,2,sm	0x0, [ _f64,_lts0 innerpad +42 ], %g25
	  ldb,3,sm	0x0, [ _f64,_lts2 innerpad +41 ], %g26
	}
	{
	  ldb,0,sm	0x0, [ _f64,_lts0 innerpad +43 ], %g17
	  qppackdl,1	%g16, %g17, %g16
	  ldd,2,sm	0x0, [ _f64,_lts2 outerpad +8 ], %g27
	}
	{
	  ldd,0,sm	0x0, [ _f64,_lts0 outerpad ], %g28
	  ldd,3,sm	0x0, [ _f64,_lts2 outerpad +24 ], %g29
	}
	{
	  ct	%ctpr1 ? ~%pred2
	  ldd,0,sm	0x0, [ _f64,_lts1 outerpad +16 ], %g30
	  getfd,1,sm	%g20, _f16s,_lts0lo 0x820, %g16
	  stqp,2	%r5, _f16s,_lts0hi 0xf780, %g16
	  getfd,3,sm	%g21, _lit16_ref,_lts0lo 0x820, %g31
	}
	{
	  getfd,0,sm	%g19, _f16s,_lts0lo 0x820, %r0
	  getfd,1,sm	%g24, _lit16_ref,_lts0lo 0x820, %r6
	  stw,2	%r5, _f16s,_lts0hi 0xf7a4, %g20 ? %pred2
	  stw,5	%r5, _f16s,_lts1lo 0xf794, %g21 ? %pred2
	}
	{
	  stw,2	%r5, _f16s,_lts0lo 0xf7ac, %g19 ? %pred2
	  stw,5	%r5, _f16s,_lts0hi 0xf79c, %g24 ? %pred2
	}
	{
	  stw,2	%r5, _f16s,_lts0lo 0xf7b4, %g22 ? %pred2
	  stb,5	%r5, _f16s,_lts0hi 0xf7bc, %g23 ? %pred2
	}
	{
	  stw,2	%r5, _f16s,_lts0lo 0xf7b8, %g18 ? %pred2
	  stb,5	%r5, _f16s,_lts0hi 0xf7be, %g25 ? %pred2
	}
	{
	  stb,2	%r5, _f16s,_lts0lo 0xf7bd, %g26 ? %pred2
	  stw,5	%r5, _f16s,_lts0hi 0xf7a8, %g16 ? %pred2
	}
	{
	  stw,2	%r5, _f16s,_lts0lo 0xf798, %g31 ? %pred2
	  stb,5	%r5, _f16s,_lts0hi 0xf7bf, %g17 ? %pred2
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf768, %g27 ? %pred2
	  stw,5	%r5, _f16s,_lts0hi 0xf7b0, %r0 ? %pred2
	}
	{
	  stw,2	%r5, _f16s,_lts0lo 0xf7a0, %r6 ? %pred2
	  std,5	%r5, _f16s,_lts0hi 0xf760, %g28 ? %pred2
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf778, %g29 ? %pred2
	  std,5	%r5, _f16s,_lts0hi 0xf770, %g30 ? %pred2
	}
.L94379:
	{
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	%r9, _f16s,_lts0lo 0x18, %r16
	  addd,1,sm	%r9, _f16s,_lts0hi 0x14, %r17
	  addd,2,sm	%r9, _f16s,_lts1lo 0x10, %r18
	  addd,3	0x0, _f16s,_lts1hi 0x820, %r19
	  addd,4,sm	0x0, 0x0, %r0
	  addd,5,sm	%r9, _f32s,_lts2 0x1c, %r15
	}
	{
	  addd,0,sm	%r9, 0x4, %r14
	  addd,1,sm	%r9, 0xc, %r12
	  addd,2,sm	%r9, 0x8, %r13
	}
.L84259:
	{
	  ldd,0	%r5, _f16s,_lts0lo 0xf7e0, %r31
	  adds,1	%r4, 0x1, %r35
	  ldd,2	%r5, _f16s,_lts0hi 0xf7e8, %r32
	  ldd,3	%r5, _f16s,_lts1lo 0xf7f0, %r33
	  addd,4,sm	0x0, %r21, %b[1]
	  ldd,5	%r5, _f16s,_lts1hi 0xf7f8, %r34
	}
	{
	  nop 2
	  addd,0,sm	0x0, 0x0, %b[2]
	  cmplsb,1	%r35, 0x4, %pred0
	  stw,2	%r5, _f16s,_lts0lo 0xf790, %r35
	  addd,3,sm	%r2, _f16s,_lts0hi 0x20, %r6
	  addd,4,sm	%r1, _lit16_ref,_lts0hi 0x20, %r10
	  addd,5,sm	0x0, %r11, %b[0]
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf740, %r31
	  std,5	%r5, _f16s,_lts0hi 0xf748, %r32
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf750, %r33
	  std,5	%r5, _f16s,_lts0hi 0xf758, %r34
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  disp	%ctpr1, sha256_transform
	  ldd,0	%r5, _f16s,_lts0lo 0xfee0, %r31
	  addd,1,sm	0x0, %r20, %b[0]
	  ldd,2	%r5, _f16s,_lts0hi 0xfee8, %r32
	  ldd,3	%r5, _f16s,_lts1lo 0xfef0, %r33
	  addd,4,sm	0x0, 0x0, %b[2]
	  ldd,5	%r5, _f16s,_lts1hi 0xfef8, %r34
	}
	{
	  nop 2
	  addd,0,sm	0x0, %r11, %b[1]
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf7c0, %r31
	  std,5	%r5, _f16s,_lts0hi 0xf7c8, %r32
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf7d0, %r33
	  std,5	%r5, _f16s,_lts0hi 0xf7d8, %r34
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  disp	%ctpr3, .L84259
	  ldd,0	%r5, _f16s,_lts0lo 0xf7c0, %g16
	  adds,1	%r4, 0x1, %r4
	  ldd,2	%r5, _f16s,_lts0hi 0xf7c8, %g17
	  ldd,3	%r5, _f16s,_lts1lo 0xf7d0, %g18
	  ldd,5	%r5, _f16s,_lts1hi 0xf7d8, %g19
	}
	{
	  disp	%ctpr1, sha256_transform
	}
	{
	  disp	%ctpr2, scrypt_1024_core_elway
	}
	{
	  getfd,0	%g16, %r19, %g20
	  getfd,1	%g17, %r19, %g21
	  getfd,3	%g18, %r19, %g22
	  getfd,4	%g19, %r19, %g23
	}
	{
	  stw,2	%r9, %r0, %g16, mas=0x8
	  stw,5	%r14, %r0, %g20, mas=0x8
	}
	{
	  stw,2	%r13, %r0, %g17, mas=0x8
	  stw,5	%r12, %r0, %g21, mas=0x8
	}
	{
	  stw,2	%r18, %r0, %g18, mas=0x8
	  stw,5	%r17, %r0, %g22, mas=0x8
	}
	{
	  ct	%ctpr3 ? %pred0
	  addd,0,sm	%r0, _f16s,_lts0lo 0x20, %r0
	  stw,2	%r16, %r0, %g19, mas=0x8
	  stw,5	%r15, %r0, %g23, mas=0x8
	}
	{
	  cmpledb,0	%r6, %r1, %pred1
	  cmpledb,1	%r10, %r2, %pred2
	  addd,2,sm	0x0, %r26, %b[1]
	  cmpledb,3,sm	%r25, %r10, %pred0
	  addd,4,sm	%r1, _f16s,_lts0lo 0x40, %r4
	  addd,5,sm	0x0, %r3, %b[0]
	}
	{
	  call	%ctpr2, wbs = 0x21
	  addd,0,sm	%r7, _f16s,_lts0lo 0x20, %r11
	  pass	%pred1, @p0
	  pass	%pred2, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred1
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r3, %b[1]
	  addd,2,sm	0x0, %r7, %b[0]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r7, %b[0]
	  addd,2	%r3, _f16s,_lts0lo 0x40, %b[1]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr2, sha256_transform
	  addd,0,sm	0x0, 0x0, %b[2]
	  addd,1,sm	0x0, [ _f64,_lts0 finalblk ], %b[1]
	  addd,2,sm	0x0, %r7, %b[0]
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  disp	%ctpr1, sha256_transform
	  ldqp,0	0x0, [ _f64,_lts2 outerpad ], %r0
	  addd,1	%r5, _f16s,_lts1lo 0xf980, %b[1]
	  ldqp,2	%r5, _f16s,_lts0lo 0xff00, %r9
	  ldqp,3	%r5, _f16s,_lts0hi 0xff10, %r12
	  addd,4,sm	0x0, 0x0, %b[2]
	  addd,5,sm	0x0, %r2, %b[0]
	}
	{
	  nop 2
	  ldqp,0	0x0, [ _f64,_lts0 outerpad +16 ], %r13
	}
	{
	  stqp,2	%r5, _f16s,_lts0lo 0xf980, %r9
	  stqp,5	%r5, _f16s,_lts0hi 0xf990, %r12
	}
	{
	  stqp,2	%r5, _f16s,_lts0lo 0xf9a0, %r0
	  stqp,5	%r5, _f16s,_lts0hi 0xf9b0, %r13
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  disp	%ctpr3, .L94101
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe00, %g16, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe04, %g17, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe08, %g18, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe0c, %g19, mas=0x8
	}
	{
	  disp	%ctpr2, .L94098
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe10, %g20, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe14, %g21, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe18, %g22, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe1c, %g23, mas=0x8
	}
	{
	  ct	%ctpr3 ? %pred1
	}
	{
	  disp	%ctpr3, sha256_transform
	}
	{
	  stw,2	%r1, 0x0, %g16 ? ~%pred1
	  stw,5	%r1, 0x4, %g17 ? ~%pred1
	}
	{
	  stw,2	%r1, 0x8, %g18 ? ~%pred1
	  stw,5	%r1, 0xc, %g19 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x10, %g20 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x14, %g21 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x18, %g22 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x1c, %g23 ? ~%pred1
	}
.L94098:
	{
	  addd,0	%r3, _f16s,_lts0lo 0x80, %b[1]
	  cmpledb,1	%r4, %r30, %pred1
	  addd,2,sm	0x0, %r11, %b[0]
	  addd,3,sm	%r7, _f16s,_lts0hi 0x40, %r9
	  addd,4,sm	%r1, _f16s,_lts1lo 0x60, %r0
	  addd,5,sm	0x1, 0x0, %b[2]
	}
	{
	  call	%ctpr3, wbs = 0x21
	  cmpledb,0,sm	%r24, %r4, %pred0
	  pass	%pred0, @p0
	  pass	%pred1, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred1
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r11, %b[0]
	  addd,2	%r3, _f16s,_lts0lo 0xc0, %b[1]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, sha256_transform
	  addd,0,sm	0x0, 0x0, %b[2]
	  addd,1,sm	0x0, [ _f64,_lts0 finalblk ], %b[1]
	  addd,2,sm	0x0, %r11, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldb,0	0x0, [ _f64,_lts0 outerpad +31 ], %r10
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldb,2	0x0, [ _f64,_lts2 outerpad +30 ], %r11
	  addd,3,sm	0x0, %r6, %b[0]
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +29 ], %r6
	  ldb,2	0x0, [ _f64,_lts2 outerpad +28 ], %r12
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +27 ], %r13
	  ldb,2	0x0, [ _f64,_lts2 outerpad +26 ], %r14
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +25 ], %r15
	  ldb,2	0x0, [ _f64,_lts2 outerpad +24 ], %r16
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +23 ], %r17
	  ldb,2	0x0, [ _f64,_lts2 outerpad +22 ], %r18
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +21 ], %r19
	  ldb,2	0x0, [ _f64,_lts2 outerpad +20 ], %r20
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +19 ], %r21
	  ldb,2	0x0, [ _f64,_lts2 outerpad +18 ], %r26
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +17 ], %r30
	  ldb,2	0x0, [ _f64,_lts2 outerpad +16 ], %r31
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +15 ], %r32
	  ldb,2	0x0, [ _f64,_lts2 outerpad +14 ], %r33
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +13 ], %r34
	  ldb,2	0x0, [ _f64,_lts2 outerpad +12 ], %r35
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +11 ], %r36
	  ldb,2	0x0, [ _f64,_lts2 outerpad +10 ], %r37
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +9 ], %r38
	  ldb,2	0x0, [ _f64,_lts2 outerpad +8 ], %r39
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +7 ], %r40
	  ldb,2	0x0, [ _f64,_lts2 outerpad +6 ], %r41
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +5 ], %r42
	  ldb,2	0x0, [ _f64,_lts2 outerpad +4 ], %r43
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad +2 ], %r45
	  ldb,2	0x0, [ _f64,_lts0 outerpad +3 ], %r44
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad ], %r47
	  ldb,2	0x0, [ _f64,_lts0 outerpad +1 ], %r46
	}
	{
	  insfs,0	%r10, _f16s,_lts0lo 0x218, %r11, %r10
	  insfs,1	%r6, _lit16_ref,_lts0lo 0x218, %r12, %r6
	  ldd,2	%r5, _f16s,_lts0hi 0xff38, %r13
	  insfs,3	%r13, _lit16_ref,_lts0lo 0x218, %r14, %r11
	  insfs,4	%r15, _lit16_ref,_lts0lo 0x218, %r16, %r12
	  ldd,5	%r5, _f16s,_lts1lo 0xff30, %r14
	}
	{
	  insfs,0	%r17, _f16s,_lts0lo 0x218, %r18, %r15
	  insfs,1	%r19, _lit16_ref,_lts0lo 0x218, %r20, %r16
	  ldd,2	%r5, _f16s,_lts0hi 0xff28, %r19
	  insfs,3	%r21, _lit16_ref,_lts0lo 0x218, %r26, %r17
	  insfs,4	%r30, _lit16_ref,_lts0lo 0x218, %r31, %r18
	  ldd,5	%r5, _f16s,_lts1lo 0xff20, %r20
	}
	{
	  insfs,0	%r32, _f16s,_lts0lo 0x218, %r33, %r21
	  insfs,1	%r34, _lit16_ref,_lts0lo 0x218, %r35, %r26
	  addd,2	%r5, _f16s,_lts0hi 0xf880, %b[1]
	  insfs,3	%r36, _lit16_ref,_lts0lo 0x218, %r37, %r30
	  insfs,4	%r38, _lit16_ref,_lts0lo 0x218, %r39, %r31
	}
	{
	  insfs,0	%r40, _f16s,_lts0lo 0x218, %r41, %r32
	  insfs,1	%r42, _lit16_ref,_lts0lo 0x218, %r43, %r33
	  insfs,3	%r44, _lit16_ref,_lts0lo 0x218, %r45, %r34
	  insfs,4	%r46, _lit16_ref,_lts0lo 0x218, %r47, %r35
	}
	{
	  insfs,0	%r10, _f16s,_lts0lo 0x410, %r6, %r6
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x410, %r12, %r10
	  std,2	%r5, _f16s,_lts0hi 0xf898, %r13
	  insfs,3	%r15, _lit16_ref,_lts0lo 0x410, %r16, %r11
	  insfs,4	%r17, _lit16_ref,_lts0lo 0x410, %r18, %r12
	  std,5	%r5, _f16s,_lts1lo 0xf890, %r14
	}
	{
	  nop 2
	  insfs,0	%r21, _f16s,_lts0lo 0x410, %r26, %r13
	  insfs,1	%r30, _lit16_ref,_lts0lo 0x410, %r31, %r14
	  std,2	%r5, _f16s,_lts0hi 0xf888, %r19
	  insfs,3	%r32, _lit16_ref,_lts0lo 0x410, %r33, %r15
	  insfs,4	%r34, _lit16_ref,_lts0lo 0x410, %r35, %r16
	  std,5	%r5, _f16s,_lts1lo 0xf880, %r20
	}
	{
	  insfd,0	%r6, _f32s,_lts0 0xa820, %r10, %r6
	  insfd,1	%r11, _lit32_ref,_lts0 0xa820, %r12, %r10
	}
	{
	  insfd,0	%r13, _f32s,_lts1 0xa820, %r14, %r11
	  insfd,1	%r15, _lit32_ref,_lts1 0xa820, %r16, %r12
	  std,2	%r5, _f16s,_lts0lo 0xf8b8, %r6
	  std,5	%r5, _f16s,_lts0hi 0xf8b0, %r10
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf8a8, %r11
	  std,5	%r5, _f16s,_lts0hi 0xf8a0, %r12
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  disp	%ctpr1, .L94048
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe3c, %g16, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe38, %g17, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe34, %g18, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe30, %g19, mas=0x8
	}
	{
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe2c, %g20, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe28, %g21, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe24, %g22, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe20, %g23, mas=0x8
	}
	{
	  ct	%ctpr1 ? %pred1
	}
	{
	  disp	%ctpr2, sha256_transform
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x3c, %g16 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x38, %g17 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x34, %g18 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x30, %g19 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x2c, %g20 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x28, %g21 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x24, %g22 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x20, %g23 ? ~%pred1
	}
.L94045:
	{
	  addd,0	%r3, _f16s,_lts0lo 0x100, %b[1]
	  cmpledb,1	%r0, %r25, %pred1
	  addd,2,sm	0x0, %r9, %b[0]
	  addd,3,sm	%r7, _f16s,_lts0hi 0x60, %r6
	  addd,4,sm	%r1, _f16s,_lts1lo 0x80, %r4
	  addd,5,sm	0x1, 0x0, %b[2]
	}
	{
	  call	%ctpr2, wbs = 0x21
	  cmpledb,0,sm	%r23, %r0, %pred0
	  pass	%pred0, @p0
	  pass	%pred1, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred1
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r9, %b[0]
	  addd,2	%r3, _f16s,_lts0lo 0x140, %b[1]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, sha256_transform
	  addd,0,sm	0x0, 0x0, %b[2]
	  addd,1,sm	0x0, [ _f64,_lts0 finalblk ], %b[1]
	  addd,2,sm	0x0, %r9, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldb,0	0x0, [ _f64,_lts0 outerpad +31 ], %r9
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldb,2	0x0, [ _f64,_lts2 outerpad +30 ], %r10
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +29 ], %r11
	  ldb,2	0x0, [ _f64,_lts2 outerpad +28 ], %r12
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +27 ], %r13
	  ldb,2	0x0, [ _f64,_lts2 outerpad +26 ], %r14
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +25 ], %r15
	  ldb,2	0x0, [ _f64,_lts2 outerpad +24 ], %r16
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +23 ], %r17
	  ldb,2	0x0, [ _f64,_lts2 outerpad +22 ], %r18
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +21 ], %r19
	  ldb,2	0x0, [ _f64,_lts2 outerpad +20 ], %r20
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +19 ], %r21
	  ldb,2	0x0, [ _f64,_lts2 outerpad +18 ], %r25
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +17 ], %r26
	  ldb,2	0x0, [ _f64,_lts2 outerpad +16 ], %r30
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +15 ], %r31
	  ldb,2	0x0, [ _f64,_lts2 outerpad +14 ], %r32
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +13 ], %r33
	  ldb,2	0x0, [ _f64,_lts2 outerpad +12 ], %r34
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +11 ], %r35
	  ldb,2	0x0, [ _f64,_lts2 outerpad +10 ], %r36
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +9 ], %r37
	  ldb,2	0x0, [ _f64,_lts2 outerpad +8 ], %r38
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +7 ], %r39
	  ldb,2	0x0, [ _f64,_lts2 outerpad +6 ], %r40
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +5 ], %r41
	  ldb,2	0x0, [ _f64,_lts2 outerpad +4 ], %r42
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad +2 ], %r44
	  ldb,2	0x0, [ _f64,_lts0 outerpad +3 ], %r43
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad ], %r46
	  ldb,2	0x0, [ _f64,_lts0 outerpad +1 ], %r45
	}
	{
	  insfs,0	%r9, _f16s,_lts0lo 0x218, %r10, %r9
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x218, %r12, %r10
	  ldd,2	%r5, _f16s,_lts0hi 0xff58, %r13
	  insfs,3	%r13, _lit16_ref,_lts0lo 0x218, %r14, %r11
	  insfs,4	%r15, _lit16_ref,_lts0lo 0x218, %r16, %r12
	  ldd,5	%r5, _f16s,_lts1lo 0xff50, %r14
	}
	{
	  insfs,0	%r17, _f16s,_lts0lo 0x218, %r18, %r15
	  insfs,1	%r19, _lit16_ref,_lts0lo 0x218, %r20, %r16
	  ldd,2	%r5, _f16s,_lts0hi 0xff48, %r19
	  insfs,3	%r21, _lit16_ref,_lts0lo 0x218, %r25, %r17
	  insfs,4	%r26, _lit16_ref,_lts0lo 0x218, %r30, %r18
	  ldd,5	%r5, _f16s,_lts1lo 0xff40, %r20
	}
	{
	  insfs,0	%r31, _f16s,_lts0lo 0x218, %r32, %r21
	  insfs,1	%r33, _lit16_ref,_lts0lo 0x218, %r34, %r25
	  addd,2	%r5, _f16s,_lts0hi 0xf900, %b[1]
	  insfs,3	%r35, _lit16_ref,_lts0lo 0x218, %r36, %r26
	  insfs,4	%r37, _lit16_ref,_lts0lo 0x218, %r38, %r30
	  addd,5	%r2, _f16s,_lts1lo 0x40, %b[0]
	}
	{
	  insfs,0	%r39, _f16s,_lts0lo 0x218, %r40, %r31
	  insfs,1	%r41, _lit16_ref,_lts0lo 0x218, %r42, %r32
	  insfs,3	%r43, _lit16_ref,_lts0lo 0x218, %r44, %r33
	  insfs,4	%r45, _lit16_ref,_lts0lo 0x218, %r46, %r34
	}
	{
	  insfs,0	%r9, _f16s,_lts0lo 0x410, %r10, %r9
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x410, %r12, %r10
	  std,2	%r5, _f16s,_lts0hi 0xf918, %r13
	  insfs,3	%r15, _lit16_ref,_lts0lo 0x410, %r16, %r11
	  insfs,4	%r17, _lit16_ref,_lts0lo 0x410, %r18, %r12
	  std,5	%r5, _f16s,_lts1lo 0xf910, %r14
	}
	{
	  nop 2
	  insfs,0	%r21, _f16s,_lts0lo 0x410, %r25, %r13
	  insfs,1	%r26, _lit16_ref,_lts0lo 0x410, %r30, %r14
	  std,2	%r5, _f16s,_lts0hi 0xf908, %r19
	  insfs,3	%r31, _lit16_ref,_lts0lo 0x410, %r32, %r15
	  insfs,4	%r33, _lit16_ref,_lts0lo 0x410, %r34, %r16
	  std,5	%r5, _f16s,_lts1lo 0xf900, %r20
	}
	{
	  insfd,0	%r9, _f32s,_lts0 0xa820, %r10, %r9
	  insfd,1	%r11, _lit32_ref,_lts0 0xa820, %r12, %r10
	}
	{
	  insfd,0	%r13, _f32s,_lts1 0xa820, %r14, %r11
	  insfd,1	%r15, _lit32_ref,_lts1 0xa820, %r16, %r12
	  std,2	%r5, _f16s,_lts0lo 0xf938, %r9
	  std,5	%r5, _f16s,_lts0hi 0xf930, %r10
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf928, %r11
	  std,5	%r5, _f16s,_lts0hi 0xf920, %r12
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  disp	%ctpr1, .L93995
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe5c, %g16, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe58, %g17, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe54, %g18, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe50, %g19, mas=0x8
	}
	{
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe4c, %g20, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe48, %g21, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe44, %g22, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe40, %g23, mas=0x8
	}
	{
	  ct	%ctpr1 ? %pred1
	}
	{
	  disp	%ctpr3, sha256_transform
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x5c, %g16 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x58, %g17 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x54, %g18 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x50, %g19 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x4c, %g20 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x48, %g21 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x44, %g22 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0x40, %g23 ? ~%pred1
	}
.L93992:
	{
	  addd,0	%r3, _f16s,_lts0lo 0x180, %b[1]
	  cmpledb,1	%r4, %r24, %pred1
	  addd,2,sm	0x0, %r6, %b[0]
	  addd,3,sm	%r1, _f16s,_lts0hi 0xa0, %r0
	  addd,5,sm	0x1, 0x0, %b[2]
	}
	{
	  call	%ctpr3, wbs = 0x21
	  pass	%pred0, @p0
	  pass	%pred1, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred0
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r6, %b[0]
	  addd,2	%r3, _f16s,_lts0lo 0x1c0, %b[1]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, sha256_transform
	  addd,0,sm	0x0, 0x0, %b[2]
	  addd,1,sm	0x0, [ _f64,_lts1 finalblk ], %b[1]
	  addd,2,sm	0x0, %r6, %b[0]
	  addd,3,sm	%r7, _f16s,_lts0lo 0x80, %r6
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldb,0	0x0, [ _f64,_lts0 outerpad +31 ], %r9
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldb,2	0x0, [ _f64,_lts2 outerpad +30 ], %r10
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +29 ], %r11
	  ldb,2	0x0, [ _f64,_lts2 outerpad +28 ], %r12
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +27 ], %r13
	  ldb,2	0x0, [ _f64,_lts2 outerpad +26 ], %r14
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +25 ], %r15
	  ldb,2	0x0, [ _f64,_lts2 outerpad +24 ], %r16
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +23 ], %r17
	  ldb,2	0x0, [ _f64,_lts2 outerpad +22 ], %r18
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +21 ], %r19
	  ldb,2	0x0, [ _f64,_lts2 outerpad +20 ], %r20
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +19 ], %r21
	  ldb,2	0x0, [ _f64,_lts2 outerpad +18 ], %r24
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +17 ], %r25
	  ldb,2	0x0, [ _f64,_lts2 outerpad +16 ], %r26
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +15 ], %r30
	  ldb,2	0x0, [ _f64,_lts2 outerpad +14 ], %r31
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +13 ], %r32
	  ldb,2	0x0, [ _f64,_lts2 outerpad +12 ], %r33
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +11 ], %r34
	  ldb,2	0x0, [ _f64,_lts2 outerpad +10 ], %r35
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +9 ], %r36
	  ldb,2	0x0, [ _f64,_lts2 outerpad +8 ], %r37
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +7 ], %r38
	  ldb,2	0x0, [ _f64,_lts2 outerpad +6 ], %r39
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +5 ], %r40
	  ldb,2	0x0, [ _f64,_lts2 outerpad +4 ], %r41
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad +2 ], %r43
	  ldb,2	0x0, [ _f64,_lts0 outerpad +3 ], %r42
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad ], %r45
	  ldb,2	0x0, [ _f64,_lts0 outerpad +1 ], %r44
	}
	{
	  insfs,0	%r9, _f16s,_lts0lo 0x218, %r10, %r9
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x218, %r12, %r10
	  ldd,2	%r5, _f16s,_lts0hi 0xff78, %r13
	  insfs,3	%r13, _lit16_ref,_lts0lo 0x218, %r14, %r11
	  insfs,4	%r15, _lit16_ref,_lts0lo 0x218, %r16, %r12
	  ldd,5	%r5, _f16s,_lts1lo 0xff70, %r14
	}
	{
	  insfs,0	%r17, _f16s,_lts0lo 0x218, %r18, %r15
	  insfs,1	%r19, _lit16_ref,_lts0lo 0x218, %r20, %r16
	  ldd,2	%r5, _f16s,_lts0hi 0xff68, %r19
	  insfs,3	%r21, _lit16_ref,_lts0lo 0x218, %r24, %r17
	  insfs,4	%r25, _lit16_ref,_lts0lo 0x218, %r26, %r18
	  ldd,5	%r5, _f16s,_lts1lo 0xff60, %r20
	}
	{
	  insfs,0	%r30, _f16s,_lts0lo 0x218, %r31, %r21
	  insfs,1	%r32, _lit16_ref,_lts0lo 0x218, %r33, %r24
	  addd,2	%r5, _f16s,_lts0hi 0xf800, %b[1]
	  insfs,3	%r34, _lit16_ref,_lts0lo 0x218, %r35, %r25
	  insfs,4	%r36, _lit16_ref,_lts0lo 0x218, %r37, %r26
	  addd,5	%r2, _f16s,_lts1lo 0x60, %b[0]
	}
	{
	  insfs,0	%r38, _f16s,_lts0lo 0x218, %r39, %r30
	  insfs,1	%r40, _lit16_ref,_lts0lo 0x218, %r41, %r31
	  insfs,3	%r42, _lit16_ref,_lts0lo 0x218, %r43, %r32
	  insfs,4	%r44, _lit16_ref,_lts0lo 0x218, %r45, %r33
	}
	{
	  insfs,0	%r9, _f16s,_lts0lo 0x410, %r10, %r9
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x410, %r12, %r10
	  std,2	%r5, _f16s,_lts0hi 0xf818, %r13
	  insfs,3	%r15, _lit16_ref,_lts0lo 0x410, %r16, %r11
	  insfs,4	%r17, _lit16_ref,_lts0lo 0x410, %r18, %r12
	  std,5	%r5, _f16s,_lts1lo 0xf810, %r14
	}
	{
	  nop 2
	  insfs,0	%r21, _f16s,_lts0lo 0x410, %r24, %r13
	  insfs,1	%r25, _lit16_ref,_lts0lo 0x410, %r26, %r14
	  std,2	%r5, _f16s,_lts0hi 0xf808, %r19
	  insfs,3	%r30, _lit16_ref,_lts0lo 0x410, %r31, %r15
	  insfs,4	%r32, _lit16_ref,_lts0lo 0x410, %r33, %r16
	  std,5	%r5, _f16s,_lts1lo 0xf800, %r20
	}
	{
	  insfd,0	%r9, _f32s,_lts0 0xa820, %r10, %r9
	  insfd,1	%r11, _lit32_ref,_lts0 0xa820, %r12, %r10
	}
	{
	  insfd,0	%r13, _f32s,_lts1 0xa820, %r14, %r11
	  insfd,1	%r15, _lit32_ref,_lts1 0xa820, %r16, %r12
	  std,2	%r5, _f16s,_lts0lo 0xf838, %r9
	  std,5	%r5, _f16s,_lts0hi 0xf830, %r10
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf828, %r11
	  std,5	%r5, _f16s,_lts0hi 0xf820, %r12
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  disp	%ctpr1, .L93942
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe7c, %g16, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe78, %g17, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe74, %g18, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe70, %g19, mas=0x8
	}
	{
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe6c, %g20, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe68, %g21, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe64, %g22, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe60, %g23, mas=0x8
	}
	{
	  ct	%ctpr1 ? %pred0
	}
	{
	  disp	%ctpr2, sha256_transform
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x7c, %g16 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0x78, %g17 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x74, %g18 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0x70, %g19 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x6c, %g20 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0x68, %g21 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x64, %g22 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0x60, %g23 ? ~%pred0
	}
.L93939:
	{
	  addd,0	%r3, _f16s,_lts0lo 0x200, %b[1]
	  cmpledb,1	%r0, %r23, %pred0
	  addd,2,sm	0x0, %r6, %b[0]
	  cmpledb,3	%r28, %r4, %pred1
	  addd,5,sm	0x1, 0x0, %b[2]
	}
	{
	  call	%ctpr2, wbs = 0x21
	  pass	%pred1, @p0
	  pass	%pred0, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred0
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r6, %b[0]
	  addd,2	%r3, _f16s,_lts0lo 0x240, %b[1]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, sha256_transform
	  addd,0,sm	0x0, 0x0, %b[2]
	  addd,1,sm	0x0, [ _f64,_lts0 finalblk ], %b[1]
	  addd,2,sm	0x0, %r6, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldb,0	0x0, [ _f64,_lts0 outerpad +31 ], %r4
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldb,2	0x0, [ _f64,_lts2 outerpad +30 ], %r6
	  addd,3,sm	0x0, %r23, %b[0]
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +29 ], %r9
	  ldb,2	0x0, [ _f64,_lts2 outerpad +28 ], %r10
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +27 ], %r11
	  ldb,2	0x0, [ _f64,_lts2 outerpad +26 ], %r12
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +25 ], %r13
	  ldb,2	0x0, [ _f64,_lts2 outerpad +24 ], %r14
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +23 ], %r15
	  ldb,2	0x0, [ _f64,_lts2 outerpad +22 ], %r16
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +21 ], %r17
	  ldb,2	0x0, [ _f64,_lts2 outerpad +20 ], %r18
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +19 ], %r19
	  ldb,2	0x0, [ _f64,_lts2 outerpad +18 ], %r20
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +17 ], %r21
	  ldb,2	0x0, [ _f64,_lts2 outerpad +16 ], %r23
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +15 ], %r24
	  ldb,2	0x0, [ _f64,_lts2 outerpad +14 ], %r25
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +13 ], %r26
	  ldb,2	0x0, [ _f64,_lts2 outerpad +12 ], %r30
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +11 ], %r31
	  ldb,2	0x0, [ _f64,_lts2 outerpad +10 ], %r32
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +9 ], %r33
	  ldb,2	0x0, [ _f64,_lts2 outerpad +8 ], %r34
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +7 ], %r35
	  ldb,2	0x0, [ _f64,_lts2 outerpad +6 ], %r36
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +5 ], %r37
	  ldb,2	0x0, [ _f64,_lts2 outerpad +4 ], %r38
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad +2 ], %r40
	  ldb,2	0x0, [ _f64,_lts0 outerpad +3 ], %r39
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad ], %r42
	  ldb,2	0x0, [ _f64,_lts0 outerpad +1 ], %r41
	}
	{
	  insfs,0	%r4, _f16s,_lts0lo 0x218, %r6, %r4
	  insfs,1	%r9, _lit16_ref,_lts0lo 0x218, %r10, %r6
	  ldd,2	%r5, _f16s,_lts0hi 0xff98, %r11
	  insfs,3	%r11, _lit16_ref,_lts0lo 0x218, %r12, %r9
	  insfs,4	%r13, _lit16_ref,_lts0lo 0x218, %r14, %r10
	  ldd,5	%r5, _f16s,_lts1lo 0xff90, %r12
	}
	{
	  insfs,0	%r15, _f16s,_lts0lo 0x218, %r16, %r13
	  insfs,1	%r17, _lit16_ref,_lts0lo 0x218, %r18, %r14
	  ldd,2	%r5, _f16s,_lts0hi 0xff88, %r17
	  insfs,3	%r19, _lit16_ref,_lts0lo 0x218, %r20, %r15
	  insfs,4	%r21, _lit16_ref,_lts0lo 0x218, %r23, %r16
	  ldd,5	%r5, _f16s,_lts1lo 0xff80, %r18
	}
	{
	  insfs,0	%r24, _f16s,_lts0lo 0x218, %r25, %r19
	  insfs,1	%r26, _lit16_ref,_lts0lo 0x218, %r30, %r20
	  addd,2	%r5, _f16s,_lts0hi 0xf940, %b[1]
	  insfs,3	%r31, _lit16_ref,_lts0lo 0x218, %r32, %r21
	  insfs,4	%r33, _lit16_ref,_lts0lo 0x218, %r34, %r23
	}
	{
	  insfs,0	%r35, _f16s,_lts0lo 0x218, %r36, %r24
	  insfs,1	%r37, _lit16_ref,_lts0lo 0x218, %r38, %r25
	  insfs,3	%r39, _lit16_ref,_lts0lo 0x218, %r40, %r26
	  insfs,4	%r41, _lit16_ref,_lts0lo 0x218, %r42, %r30
	}
	{
	  insfs,0	%r4, _f16s,_lts0lo 0x410, %r6, %r4
	  insfs,1	%r9, _lit16_ref,_lts0lo 0x410, %r10, %r6
	  std,2	%r5, _f16s,_lts0hi 0xf958, %r11
	  insfs,3	%r13, _lit16_ref,_lts0lo 0x410, %r14, %r9
	  insfs,4	%r15, _lit16_ref,_lts0lo 0x410, %r16, %r10
	  std,5	%r5, _f16s,_lts1lo 0xf950, %r12
	}
	{
	  nop 2
	  insfs,0	%r19, _f16s,_lts0lo 0x410, %r20, %r11
	  insfs,1	%r21, _lit16_ref,_lts0lo 0x410, %r23, %r12
	  std,2	%r5, _f16s,_lts0hi 0xf948, %r17
	  insfs,3	%r24, _lit16_ref,_lts0lo 0x410, %r25, %r13
	  insfs,4	%r26, _lit16_ref,_lts0lo 0x410, %r30, %r14
	  std,5	%r5, _f16s,_lts1lo 0xf940, %r18
	}
	{
	  insfd,0	%r4, _f32s,_lts0 0xa820, %r6, %r4
	  insfd,1	%r9, _lit32_ref,_lts0 0xa820, %r10, %r6
	}
	{
	  insfd,0	%r11, _f32s,_lts1 0xa820, %r12, %r9
	  insfd,1	%r13, _lit32_ref,_lts1 0xa820, %r14, %r10
	  std,2	%r5, _f16s,_lts0lo 0xf978, %r4
	  std,5	%r5, _f16s,_lts0hi 0xf970, %r6
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf968, %r9
	  std,5	%r5, _f16s,_lts0hi 0xf960, %r10
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  disp	%ctpr1, .L93889
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe9c, %g16, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe98, %g17, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe94, %g18, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe90, %g19, mas=0x8
	}
	{
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfe8c, %g20, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfe88, %g21, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfe84, %g22, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfe80, %g23, mas=0x8
	}
	{
	  ct	%ctpr1 ? %pred0
	}
	{
	  disp	%ctpr3, sha256_transform
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x9c, %g16 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0x98, %g17 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x94, %g18 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0x90, %g19 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x8c, %g20 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0x88, %g21 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x84, %g22 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0x80, %g23 ? ~%pred0
	}
.L93886:
	{
	  addd,0	%r3, _f16s,_lts0lo 0x280, %b[1]
	  addd,1	%r1, _f16s,_lts0hi 0xc0, %r6
	  addd,2,sm	0x1, 0x0, %b[2]
	  cmpledb,3	%r27, %r0, %pred1
	  addd,4,sm	%r7, _lit16_ref,_lts0hi 0xc0, %r4
	  addd,5,sm	0x0, %r29, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	  cmpledb,0	%r6, %r28, %pred2
	  cmpledb,1,sm	%r22, %r6, %pred0
	  addd,2,sm	%r1, _f16s,_lts0lo 0xe0, %r0
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r29, %b[0]
	  addd,2	%r3, _f16s,_lts0lo 0x2c0, %b[1]
	  pass	%pred1, @p0
	  pass	%pred2, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred1
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, sha256_transform
	  addd,0,sm	0x0, 0x0, %b[2]
	  addd,1,sm	0x0, [ _f64,_lts0 finalblk ], %b[1]
	  addd,2,sm	0x0, %r29, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldb,0	0x0, [ _f64,_lts0 outerpad +31 ], %r9
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldb,2	0x0, [ _f64,_lts2 outerpad +30 ], %r10
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +29 ], %r11
	  ldb,2	0x0, [ _f64,_lts2 outerpad +28 ], %r12
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +27 ], %r13
	  ldb,2	0x0, [ _f64,_lts2 outerpad +26 ], %r14
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +25 ], %r15
	  ldb,2	0x0, [ _f64,_lts2 outerpad +24 ], %r16
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +23 ], %r17
	  ldb,2	0x0, [ _f64,_lts2 outerpad +22 ], %r18
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +21 ], %r19
	  ldb,2	0x0, [ _f64,_lts2 outerpad +20 ], %r20
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +19 ], %r21
	  ldb,2	0x0, [ _f64,_lts2 outerpad +18 ], %r23
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +17 ], %r24
	  ldb,2	0x0, [ _f64,_lts2 outerpad +16 ], %r25
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +15 ], %r26
	  ldb,2	0x0, [ _f64,_lts2 outerpad +14 ], %r28
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +13 ], %r29
	  ldb,2	0x0, [ _f64,_lts2 outerpad +12 ], %r30
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +11 ], %r31
	  ldb,2	0x0, [ _f64,_lts2 outerpad +10 ], %r32
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +9 ], %r33
	  ldb,2	0x0, [ _f64,_lts2 outerpad +8 ], %r34
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +7 ], %r35
	  ldb,2	0x0, [ _f64,_lts2 outerpad +6 ], %r36
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +5 ], %r37
	  ldb,2	0x0, [ _f64,_lts2 outerpad +4 ], %r38
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad +2 ], %r40
	  ldb,2	0x0, [ _f64,_lts0 outerpad +3 ], %r39
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad ], %r42
	  ldb,2	0x0, [ _f64,_lts0 outerpad +1 ], %r41
	}
	{
	  insfs,0	%r9, _f16s,_lts0lo 0x218, %r10, %r9
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x218, %r12, %r10
	  ldd,2	%r5, _f16s,_lts0hi 0xffb8, %r13
	  insfs,3	%r13, _lit16_ref,_lts0lo 0x218, %r14, %r11
	  insfs,4	%r15, _lit16_ref,_lts0lo 0x218, %r16, %r12
	  ldd,5	%r5, _f16s,_lts1lo 0xffb0, %r14
	}
	{
	  insfs,0	%r17, _f16s,_lts0lo 0x218, %r18, %r15
	  insfs,1	%r19, _lit16_ref,_lts0lo 0x218, %r20, %r16
	  ldd,2	%r5, _f16s,_lts0hi 0xffa8, %r19
	  insfs,3	%r21, _lit16_ref,_lts0lo 0x218, %r23, %r17
	  insfs,4	%r24, _lit16_ref,_lts0lo 0x218, %r25, %r18
	  ldd,5	%r5, _f16s,_lts1lo 0xffa0, %r20
	}
	{
	  insfs,0	%r26, _f16s,_lts0lo 0x218, %r28, %r21
	  insfs,1	%r29, _lit16_ref,_lts0lo 0x218, %r30, %r23
	  addd,2	%r5, _f16s,_lts0hi 0xf840, %b[1]
	  insfs,3	%r31, _lit16_ref,_lts0lo 0x218, %r32, %r24
	  insfs,4	%r33, _lit16_ref,_lts0lo 0x218, %r34, %r25
	  addd,5	%r2, _f16s,_lts1lo 0xa0, %b[0]
	}
	{
	  insfs,0	%r35, _f16s,_lts0lo 0x218, %r36, %r26
	  insfs,1	%r37, _lit16_ref,_lts0lo 0x218, %r38, %r28
	  insfs,3	%r39, _lit16_ref,_lts0lo 0x218, %r40, %r29
	  insfs,4	%r41, _lit16_ref,_lts0lo 0x218, %r42, %r30
	}
	{
	  insfs,0	%r9, _f16s,_lts0lo 0x410, %r10, %r9
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x410, %r12, %r10
	  std,2	%r5, _f16s,_lts0hi 0xf858, %r13
	  insfs,3	%r15, _lit16_ref,_lts0lo 0x410, %r16, %r11
	  insfs,4	%r17, _lit16_ref,_lts0lo 0x410, %r18, %r12
	  std,5	%r5, _f16s,_lts1lo 0xf850, %r14
	}
	{
	  nop 2
	  insfs,0	%r21, _f16s,_lts0lo 0x410, %r23, %r13
	  insfs,1	%r24, _lit16_ref,_lts0lo 0x410, %r25, %r14
	  std,2	%r5, _f16s,_lts0hi 0xf848, %r19
	  insfs,3	%r26, _lit16_ref,_lts0lo 0x410, %r28, %r15
	  insfs,4	%r29, _lit16_ref,_lts0lo 0x410, %r30, %r16
	  std,5	%r5, _f16s,_lts1lo 0xf840, %r20
	}
	{
	  insfd,0	%r9, _f32s,_lts0 0xa820, %r10, %r9
	  insfd,1	%r11, _lit32_ref,_lts0 0xa820, %r12, %r10
	}
	{
	  insfd,0	%r13, _f32s,_lts1 0xa820, %r14, %r11
	  insfd,1	%r15, _lit32_ref,_lts1 0xa820, %r16, %r12
	  std,2	%r5, _f16s,_lts0lo 0xf878, %r9
	  std,5	%r5, _f16s,_lts0hi 0xf870, %r10
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf868, %r11
	  std,5	%r5, _f16s,_lts0hi 0xf860, %r12
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  disp	%ctpr1, .L93836
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfebc, %g16, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfeb8, %g17, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfeb4, %g18, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfeb0, %g19, mas=0x8
	}
	{
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfeac, %g20, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfea8, %g21, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfea4, %g22, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfea0, %g23, mas=0x8
	}
	{
	  ct	%ctpr1 ? %pred1
	}
	{
	  disp	%ctpr2, sha256_transform
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xbc, %g16 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0xb8, %g17 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xb4, %g18 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0xb0, %g19 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xac, %g20 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0xa8, %g21 ? ~%pred1
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xa4, %g22 ? ~%pred1
	  stw,5	%r1, _f16s,_lts0hi 0xa0, %g23 ? ~%pred1
	}
.L93833:
	{
	  addd,0	%r3, _f16s,_lts0lo 0x300, %b[1]
	  cmpledb,1	%r0, %r27, %pred1
	  addd,2,sm	0x0, %r4, %b[0]
	  addd,3,sm	%r7, _f16s,_lts0hi 0xe0, %r6
	  addd,5,sm	0x1, 0x0, %b[2]
	}
	{
	  call	%ctpr2, wbs = 0x21
	  pass	%pred0, @p0
	  pass	%pred1, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred0
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r4, %b[0]
	  addd,2	%r3, _f16s,_lts0lo 0x340, %b[1]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, sha256_transform
	  addd,0,sm	0x0, 0x0, %b[2]
	  addd,1,sm	0x0, [ _f64,_lts1 finalblk ], %b[1]
	  addd,2,sm	0x0, %r4, %b[0]
	  addd,3,sm	%r1, _f16s,_lts0lo 0x100, %r4
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldb,0	0x0, [ _f64,_lts0 outerpad +31 ], %r9
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldb,2	0x0, [ _f64,_lts2 outerpad +30 ], %r10
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +29 ], %r11
	  ldb,2	0x0, [ _f64,_lts2 outerpad +28 ], %r12
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +27 ], %r13
	  ldb,2	0x0, [ _f64,_lts2 outerpad +26 ], %r14
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +25 ], %r15
	  ldb,2	0x0, [ _f64,_lts2 outerpad +24 ], %r16
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +23 ], %r17
	  ldb,2	0x0, [ _f64,_lts2 outerpad +22 ], %r18
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +21 ], %r19
	  ldb,2	0x0, [ _f64,_lts2 outerpad +20 ], %r20
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +19 ], %r21
	  ldb,2	0x0, [ _f64,_lts2 outerpad +18 ], %r23
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +17 ], %r24
	  ldb,2	0x0, [ _f64,_lts2 outerpad +16 ], %r25
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +15 ], %r26
	  ldb,2	0x0, [ _f64,_lts2 outerpad +14 ], %r27
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +13 ], %r28
	  ldb,2	0x0, [ _f64,_lts2 outerpad +12 ], %r29
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +11 ], %r30
	  ldb,2	0x0, [ _f64,_lts2 outerpad +10 ], %r31
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +9 ], %r32
	  ldb,2	0x0, [ _f64,_lts2 outerpad +8 ], %r33
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +7 ], %r34
	  ldb,2	0x0, [ _f64,_lts2 outerpad +6 ], %r35
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +5 ], %r36
	  ldb,2	0x0, [ _f64,_lts2 outerpad +4 ], %r37
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad +2 ], %r39
	  ldb,2	0x0, [ _f64,_lts0 outerpad +3 ], %r38
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad ], %r41
	  ldb,2	0x0, [ _f64,_lts0 outerpad +1 ], %r40
	}
	{
	  insfs,0	%r9, _f16s,_lts0lo 0x218, %r10, %r9
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x218, %r12, %r10
	  ldd,2	%r5, _f16s,_lts0hi 0xffd8, %r13
	  insfs,3	%r13, _lit16_ref,_lts0lo 0x218, %r14, %r11
	  insfs,4	%r15, _lit16_ref,_lts0lo 0x218, %r16, %r12
	  ldd,5	%r5, _f16s,_lts1lo 0xffd0, %r14
	}
	{
	  insfs,0	%r17, _f16s,_lts0lo 0x218, %r18, %r15
	  insfs,1	%r19, _lit16_ref,_lts0lo 0x218, %r20, %r16
	  ldd,2	%r5, _f16s,_lts0hi 0xffc8, %r19
	  insfs,3	%r21, _lit16_ref,_lts0lo 0x218, %r23, %r17
	  insfs,4	%r24, _lit16_ref,_lts0lo 0x218, %r25, %r18
	  ldd,5	%r5, _f16s,_lts1lo 0xffc0, %r20
	}
	{
	  insfs,0	%r26, _f16s,_lts0lo 0x218, %r27, %r21
	  insfs,1	%r28, _lit16_ref,_lts0lo 0x218, %r29, %r23
	  addd,2	%r5, _f16s,_lts0hi 0xf8c0, %b[1]
	  insfs,3	%r30, _lit16_ref,_lts0lo 0x218, %r31, %r24
	  insfs,4	%r32, _lit16_ref,_lts0lo 0x218, %r33, %r25
	  addd,5	%r2, _f16s,_lts1lo 0xc0, %b[0]
	}
	{
	  insfs,0	%r34, _f16s,_lts0lo 0x218, %r35, %r26
	  insfs,1	%r36, _lit16_ref,_lts0lo 0x218, %r37, %r27
	  insfs,3	%r38, _lit16_ref,_lts0lo 0x218, %r39, %r28
	  insfs,4	%r40, _lit16_ref,_lts0lo 0x218, %r41, %r29
	}
	{
	  insfs,0	%r9, _f16s,_lts0lo 0x410, %r10, %r9
	  insfs,1	%r11, _lit16_ref,_lts0lo 0x410, %r12, %r10
	  std,2	%r5, _f16s,_lts0hi 0xf8d8, %r13
	  insfs,3	%r15, _lit16_ref,_lts0lo 0x410, %r16, %r11
	  insfs,4	%r17, _lit16_ref,_lts0lo 0x410, %r18, %r12
	  std,5	%r5, _f16s,_lts1lo 0xf8d0, %r14
	}
	{
	  nop 2
	  insfs,0	%r21, _f16s,_lts0lo 0x410, %r23, %r13
	  insfs,1	%r24, _lit16_ref,_lts0lo 0x410, %r25, %r14
	  std,2	%r5, _f16s,_lts0hi 0xf8c8, %r19
	  insfs,3	%r26, _lit16_ref,_lts0lo 0x410, %r27, %r15
	  insfs,4	%r28, _lit16_ref,_lts0lo 0x410, %r29, %r16
	  std,5	%r5, _f16s,_lts1lo 0xf8c0, %r20
	}
	{
	  insfd,0	%r9, _f32s,_lts0 0xa820, %r10, %r9
	  insfd,1	%r11, _lit32_ref,_lts0 0xa820, %r12, %r10
	}
	{
	  insfd,0	%r13, _f32s,_lts1 0xa820, %r14, %r11
	  insfd,1	%r15, _lit32_ref,_lts1 0xa820, %r16, %r12
	  std,2	%r5, _f16s,_lts0lo 0xf8f8, %r9
	  std,5	%r5, _f16s,_lts0hi 0xf8f0, %r10
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf8e8, %r11
	  std,5	%r5, _f16s,_lts0hi 0xf8e0, %r12
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  disp	%ctpr1, .L93783
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfedc, %g16, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfed8, %g17, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfed4, %g18, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfed0, %g19, mas=0x8
	}
	{
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfecc, %g20, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfec8, %g21, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfec4, %g22, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfec0, %g23, mas=0x8
	}
	{
	  ct	%ctpr1 ? %pred0
	}
	{
	  disp	%ctpr3, sha256_transform
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xdc, %g16 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0xd8, %g17 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xd4, %g18 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0xd0, %g19 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xcc, %g20 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0xc8, %g21 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xc4, %g22 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0xc0, %g23 ? ~%pred0
	}
.L93780:
	{
	  addd,0	%r3, _f16s,_lts0lo 0x380, %b[1]
	  cmpledb,1	%r4, %r22, %pred0
	  addd,2,sm	0x0, %r6, %b[0]
	  cmpledb,3	%r7, %r0, %pred1
	  addd,5,sm	0x1, 0x0, %b[2]
	}
	{
	  call	%ctpr3, wbs = 0x21
	  pass	%pred1, @p0
	  pass	%pred0, @p1
	  landp	~@p0, ~@p1, @p4
	  pass	@p4, %pred0
	}
	{
	  nop 4
	  disp	%ctpr1, sha256_transform
	  addd,0,sm	0x1, 0x0, %b[2]
	  addd,1,sm	0x0, %r6, %b[0]
	  addd,2	%r3, _f16s,_lts0lo 0x3c0, %b[1]
	}
	{
	  call	%ctpr1, wbs = 0x21
	}
	{
	  nop 4
	  disp	%ctpr3, sha256_transform
	  addd,0,sm	0x0, 0x0, %b[2]
	  addd,1,sm	0x0, [ _f64,_lts0 finalblk ], %b[1]
	  addd,2,sm	0x0, %r6, %b[0]
	}
	{
	  call	%ctpr3, wbs = 0x21
	}
	{
	  disp	%ctpr2, sha256_transform
	  ldb,0	0x0, [ _f64,_lts0 outerpad +31 ], %r0
	  addd,1,sm	0x0, 0x0, %b[2]
	  ldb,2	0x0, [ _f64,_lts2 outerpad +30 ], %r3
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +29 ], %r4
	  ldb,2	0x0, [ _f64,_lts2 outerpad +28 ], %r6
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +27 ], %r7
	  ldb,2	0x0, [ _f64,_lts2 outerpad +26 ], %r9
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +25 ], %r10
	  ldb,2	0x0, [ _f64,_lts2 outerpad +24 ], %r11
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +23 ], %r12
	  ldb,2	0x0, [ _f64,_lts2 outerpad +22 ], %r13
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +21 ], %r14
	  ldb,2	0x0, [ _f64,_lts2 outerpad +20 ], %r15
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +19 ], %r16
	  ldb,2	0x0, [ _f64,_lts2 outerpad +18 ], %r17
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +17 ], %r18
	  ldb,2	0x0, [ _f64,_lts2 outerpad +16 ], %r19
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +15 ], %r20
	  ldb,2	0x0, [ _f64,_lts2 outerpad +14 ], %r21
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +13 ], %r22
	  ldb,2	0x0, [ _f64,_lts2 outerpad +12 ], %r23
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +11 ], %r24
	  ldb,2	0x0, [ _f64,_lts2 outerpad +10 ], %r25
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +9 ], %r26
	  ldb,2	0x0, [ _f64,_lts2 outerpad +8 ], %r27
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +7 ], %r28
	  ldb,2	0x0, [ _f64,_lts2 outerpad +6 ], %r29
	}
	{
	  ldb,0	0x0, [ _f64,_lts0 outerpad +5 ], %r30
	  ldb,2	0x0, [ _f64,_lts2 outerpad +4 ], %r31
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad +2 ], %r33
	  ldb,2	0x0, [ _f64,_lts0 outerpad +3 ], %r32
	}
	{
	  ldb,0	0x0, [ _f64,_lts2 outerpad ], %r35
	  ldb,2	0x0, [ _f64,_lts0 outerpad +1 ], %r34
	}
	{
	  insfs,0	%r0, _f16s,_lts0lo 0x218, %r3, %r0
	  insfs,1	%r4, _lit16_ref,_lts0lo 0x218, %r6, %r3
	  ldd,2	%r5, _f16s,_lts0hi 0xfff8, %r7
	  insfs,3	%r7, _lit16_ref,_lts0lo 0x218, %r9, %r4
	  insfs,4	%r10, _lit16_ref,_lts0lo 0x218, %r11, %r6
	  ldd,5	%r5, _f16s,_lts1lo 0xfff0, %r9
	}
	{
	  insfs,0	%r12, _f16s,_lts0lo 0x218, %r13, %r10
	  insfs,1	%r14, _lit16_ref,_lts0lo 0x218, %r15, %r11
	  ldd,2	%r5, _f16s,_lts0hi 0xffe8, %r14
	  insfs,3	%r16, _lit16_ref,_lts0lo 0x218, %r17, %r12
	  insfs,4	%r18, _lit16_ref,_lts0lo 0x218, %r19, %r13
	  ldd,5	%r5, _f16s,_lts1lo 0xffe0, %r15
	}
	{
	  insfs,0	%r20, _f16s,_lts0lo 0x218, %r21, %r16
	  insfs,1	%r22, _lit16_ref,_lts0lo 0x218, %r23, %r17
	  addd,2	%r5, _f16s,_lts0hi 0xf9c0, %b[1]
	  insfs,3	%r24, _lit16_ref,_lts0lo 0x218, %r25, %r18
	  insfs,4	%r26, _lit16_ref,_lts0lo 0x218, %r27, %r19
	  addd,5	%r2, _f16s,_lts1lo 0xe0, %b[0]
	}
	{
	  insfs,0	%r28, _f16s,_lts0lo 0x218, %r29, %r2
	  insfs,1	%r30, _lit16_ref,_lts0lo 0x218, %r31, %r20
	  insfs,3	%r32, _lit16_ref,_lts0lo 0x218, %r33, %r21
	  insfs,4	%r34, _lit16_ref,_lts0lo 0x218, %r35, %r22
	}
	{
	  insfs,0	%r0, _f16s,_lts0lo 0x410, %r3, %r0
	  insfs,1	%r4, _lit16_ref,_lts0lo 0x410, %r6, %r3
	  std,2	%r5, _f16s,_lts0hi 0xf9d8, %r7
	  insfs,3	%r10, _lit16_ref,_lts0lo 0x410, %r11, %r4
	  insfs,4	%r12, _lit16_ref,_lts0lo 0x410, %r13, %r6
	  std,5	%r5, _f16s,_lts1lo 0xf9d0, %r9
	}
	{
	  nop 2
	  insfs,0	%r16, _f16s,_lts0lo 0x410, %r17, %r7
	  insfs,1	%r18, _lit16_ref,_lts0lo 0x410, %r19, %r9
	  std,2	%r5, _f16s,_lts0hi 0xf9c8, %r14
	  insfs,3	%r2, _lit16_ref,_lts0lo 0x410, %r20, %r2
	  insfs,4	%r21, _lit16_ref,_lts0lo 0x410, %r22, %r10
	  std,5	%r5, _f16s,_lts1lo 0xf9c0, %r15
	}
	{
	  insfd,0	%r0, _f32s,_lts0 0xa820, %r3, %r0
	  insfd,1	%r4, _lit32_ref,_lts0 0xa820, %r6, %r3
	}
	{
	  insfd,0	%r7, _f32s,_lts1 0xa820, %r9, %r4
	  insfd,1	%r2, _lit32_ref,_lts1 0xa820, %r10, %r2
	  std,2	%r5, _f16s,_lts0lo 0xf9f8, %r0
	  std,5	%r5, _f16s,_lts0hi 0xf9f0, %r3
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf9e8, %r4
	  std,5	%r5, _f16s,_lts0hi 0xf9e0, %r2
	}
	{
	  call	%ctpr2, wbs = 0x21
	}
	{
	  return	%ctpr3
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfefc, %g16, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfef8, %g17, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfef4, %g18, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfef0, %g19, mas=0x8
	}
	{
	  nop 1
	  disp	%ctpr1, .L93730
	  ldw,0,sm	%r5, _f16s,_lts0lo 0xfeec, %g20, mas=0x8
	  ldw,2,sm	%r5, _f16s,_lts0hi 0xfee8, %g21, mas=0x8
	  ldw,3,sm	%r5, _f16s,_lts1lo 0xfee4, %g22, mas=0x8
	  ldw,5,sm	%r5, _f16s,_lts1hi 0xfee0, %g23, mas=0x8
	}
	{
	  ct	%ctpr1 ? %pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xfc, %g16 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0xf8, %g17 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xf4, %g18 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0xf0, %g19 ? ~%pred0
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xec, %g20 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0xe8, %g21 ? ~%pred0
	}
	{
	  ct	%ctpr3 ? ~%pred0
	  stw,2	%r1, _f16s,_lts0lo 0xe4, %g22 ? ~%pred0
	  stw,5	%r1, _f16s,_lts0hi 0xe0, %g23 ? ~%pred0
	}
.L93730:
	{
	  return	%ctpr3
	  ldw,0	%r5, _f16s,_lts0lo 0xfef0, %g16, mas=0x8
	  ldw,2	%r5, _f16s,_lts0hi 0xfef4, %g17, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfef8, %g18, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfefc, %g19, mas=0x8
	}
	{
	  nop 2
	  ldw,0	%r5, _f16s,_lts0lo 0xfee0, %g20, mas=0x8
	  ldw,2	%r5, _f16s,_lts0hi 0xfee4, %g21, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfee8, %g22, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfeec, %g23, mas=0x8
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xf0, %g16
	  stw,5	%r1, _f16s,_lts0hi 0xf4, %g17
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xf8, %g18
	  stw,5	%r1, _f16s,_lts0hi 0xfc, %g19
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xe0, %g20
	  stw,5	%r1, _f16s,_lts0hi 0xe4, %g21
	}
	{
	  ct	%ctpr3
	  stw,2	%r1, _f16s,_lts0lo 0xe8, %g22
	  stw,5	%r1, _f16s,_lts0hi 0xec, %g23
	}
.L93783:
	{
	  disp	%ctpr1, .L93780
	  ldw,0	%r5, _f16s,_lts0lo 0xfed0, %g16, mas=0x8
	  addd,1	%r1, _f32s,_lts2 0x100, %r4
	  ldw,2	%r5, _f16s,_lts0hi 0xfed4, %g17, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfec0, %g18, mas=0x8
	  addd,4	%r7, _f32s,_lts3 0xe0, %r6
	  ldw,5	%r5, _f16s,_lts1hi 0xfed8, %g19, mas=0x8
	}
	{
	  nop 2
	  disp	%ctpr3, sha256_transform
	  ldw,0	%r5, _f16s,_lts0lo 0xfedc, %g20, mas=0x8
	  ldw,2	%r5, _f16s,_lts0hi 0xfec4, %g21, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfec8, %g22, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfecc, %g23, mas=0x8
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xd0, %g16
	  stw,5	%r1, _f16s,_lts0hi 0xd4, %g17
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xc0, %g18
	  stw,5	%r1, _f16s,_lts0hi 0xd8, %g19
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xdc, %g20
	  stw,5	%r1, _f16s,_lts0hi 0xc4, %g21
	}
	{
	  ct	%ctpr1
	  stw,2	%r1, _f16s,_lts0lo 0xc8, %g22
	  stw,5	%r1, _f16s,_lts0hi 0xcc, %g23
	}
.L93836:
	{
	  disp	%ctpr1, .L93833
	  ldw,0	%r5, _f16s,_lts0lo 0xfeb0, %g16, mas=0x8
	  cmpledb,1	%r22, %r6, %pred0
	  ldw,2	%r5, _f16s,_lts0hi 0xfeb4, %g17, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfeb8, %g18, mas=0x8
	  addd,4	%r1, _f32s,_lts2 0xe0, %r0
	  ldw,5	%r5, _f16s,_lts1hi 0xfea0, %g19, mas=0x8
	}
	{
	  nop 2
	  disp	%ctpr2, sha256_transform
	  ldw,0	%r5, _f16s,_lts0lo 0xfea4, %g20, mas=0x8
	  addd,1	%r7, _f32s,_lts2 0xc0, %r4
	  ldw,2	%r5, _f16s,_lts0hi 0xfebc, %g21, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfea8, %g22, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfeac, %g23, mas=0x8
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xb0, %g16
	  stw,5	%r1, _f16s,_lts0hi 0xb4, %g17
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xb8, %g18
	  stw,5	%r1, _f16s,_lts0hi 0xa0, %g19
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0xa4, %g20
	  stw,5	%r1, _f16s,_lts0hi 0xbc, %g21
	}
	{
	  ct	%ctpr1
	  stw,2	%r1, _f16s,_lts0lo 0xa8, %g22
	  stw,5	%r1, _f16s,_lts0hi 0xac, %g23
	}
.L93889:
	{
	  disp	%ctpr1, .L93886
	  ldw,0	%r5, _f16s,_lts0lo 0xfe90, %g16, mas=0x8
	  ldw,2	%r5, _f16s,_lts0hi 0xfe94, %g17, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe98, %g18, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfe80, %g19, mas=0x8
	}
	{
	  nop 2
	  disp	%ctpr3, sha256_transform
	  ldw,0	%r5, _f16s,_lts0lo 0xfe84, %g20, mas=0x8
	  ldw,2	%r5, _f16s,_lts0hi 0xfe9c, %g21, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe88, %g22, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfe8c, %g23, mas=0x8
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x90, %g16
	  stw,5	%r1, _f16s,_lts0hi 0x94, %g17
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x98, %g18
	  stw,5	%r1, _f16s,_lts0hi 0x80, %g19
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x84, %g20
	  stw,5	%r1, _f16s,_lts0hi 0x9c, %g21
	}
	{
	  ct	%ctpr1
	  stw,2	%r1, _f16s,_lts0lo 0x88, %g22
	  stw,5	%r1, _f16s,_lts0hi 0x8c, %g23
	}
.L93942:
	{
	  disp	%ctpr1, .L93939
	  ldw,0	%r5, _f16s,_lts0lo 0xfe70, %g16, mas=0x8
	  addd,1	%r1, _f32s,_lts2 0xa0, %r0
	  ldw,2	%r5, _f16s,_lts0hi 0xfe74, %g17, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe60, %g18, mas=0x8
	  addd,4	%r7, _f32s,_lts3 0x80, %r6
	  ldw,5	%r5, _f16s,_lts1hi 0xfe78, %g19, mas=0x8
	}
	{
	  nop 2
	  disp	%ctpr2, sha256_transform
	  ldw,0	%r5, _f16s,_lts0lo 0xfe7c, %g20, mas=0x8
	  ldw,2	%r5, _f16s,_lts0hi 0xfe64, %g21, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe68, %g22, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfe6c, %g23, mas=0x8
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x70, %g16
	  stw,5	%r1, _f16s,_lts0hi 0x74, %g17
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x60, %g18
	  stw,5	%r1, _f16s,_lts0hi 0x78, %g19
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x7c, %g20
	  stw,5	%r1, _f16s,_lts0hi 0x64, %g21
	}
	{
	  ct	%ctpr1
	  stw,2	%r1, _f16s,_lts0lo 0x68, %g22
	  stw,5	%r1, _f16s,_lts0hi 0x6c, %g23
	}
.L93995:
	{
	  disp	%ctpr1, .L93992
	  ldw,0	%r5, _f16s,_lts0lo 0xfe50, %g16, mas=0x8
	  cmpledb,1	%r23, %r0, %pred0
	  ldw,2	%r5, _f16s,_lts0hi 0xfe54, %g17, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe58, %g18, mas=0x8
	  addd,4	%r1, _f32s,_lts2 0x80, %r4
	  ldw,5	%r5, _f16s,_lts1hi 0xfe40, %g19, mas=0x8
	}
	{
	  nop 2
	  disp	%ctpr3, sha256_transform
	  ldw,0	%r5, _f16s,_lts0lo 0xfe44, %g20, mas=0x8
	  addd,1	%r7, _f32s,_lts2 0x60, %r6
	  ldw,2	%r5, _f16s,_lts0hi 0xfe5c, %g21, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe48, %g22, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfe4c, %g23, mas=0x8
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x50, %g16
	  stw,5	%r1, _f16s,_lts0hi 0x54, %g17
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x58, %g18
	  stw,5	%r1, _f16s,_lts0hi 0x40, %g19
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x44, %g20
	  stw,5	%r1, _f16s,_lts0hi 0x5c, %g21
	}
	{
	  ct	%ctpr1
	  stw,2	%r1, _f16s,_lts0lo 0x48, %g22
	  stw,5	%r1, _f16s,_lts0hi 0x4c, %g23
	}
.L94048:
	{
	  disp	%ctpr1, .L94045
	  ldw,0	%r5, _f16s,_lts0lo 0xfe30, %g16, mas=0x8
	  cmpledb,1	%r24, %r4, %pred0
	  ldw,2	%r5, _f16s,_lts0hi 0xfe34, %g17, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe38, %g18, mas=0x8
	  addd,4	%r1, _f32s,_lts2 0x60, %r0
	  ldw,5	%r5, _f16s,_lts1hi 0xfe20, %g19, mas=0x8
	}
	{
	  nop 2
	  disp	%ctpr2, sha256_transform
	  ldw,0	%r5, _f16s,_lts0lo 0xfe24, %g20, mas=0x8
	  addd,1	%r7, _f32s,_lts2 0x40, %r9
	  ldw,2	%r5, _f16s,_lts0hi 0xfe3c, %g21, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe28, %g22, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfe2c, %g23, mas=0x8
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x30, %g16
	  stw,5	%r1, _f16s,_lts0hi 0x34, %g17
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x38, %g18
	  stw,5	%r1, _f16s,_lts0hi 0x20, %g19
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x24, %g20
	  stw,5	%r1, _f16s,_lts0hi 0x3c, %g21
	}
	{
	  ct	%ctpr1
	  stw,2	%r1, _f16s,_lts0lo 0x28, %g22
	  stw,5	%r1, _f16s,_lts0hi 0x2c, %g23
	}
.L94101:
	{
	  disp	%ctpr3, sha256_transform
	  ldw,0	%r5, _f16s,_lts0lo 0xfe10, %g16, mas=0x8
	  cmpledb,1	%r25, %r10, %pred0
	  ldw,2	%r5, _f16s,_lts0hi 0xfe14, %g17, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe18, %g18, mas=0x8
	  addd,4	%r1, _f32s,_lts2 0x40, %r4
	  ldw,5	%r5, _f16s,_lts1hi 0xfe00, %g19, mas=0x8
	}
	{
	  nop 2
	  ldw,0	%r5, _f16s,_lts0lo 0xfe04, %g20, mas=0x8
	  addd,1	%r7, _f32s,_lts2 0x20, %r11
	  ldw,2	%r5, _f16s,_lts0hi 0xfe1c, %g21, mas=0x8
	  ldw,3	%r5, _f16s,_lts1lo 0xfe08, %g22, mas=0x8
	  ldw,5	%r5, _f16s,_lts1hi 0xfe0c, %g23, mas=0x8
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x10, %g16
	  stw,5	%r1, _f16s,_lts0hi 0x14, %g17
	}
	{
	  stw,2	%r1, _f16s,_lts0lo 0x18, %g18
	  stw,5	%r1, 0x0, %g19
	}
	{
	  stw,2	%r1, 0x4, %g20
	  stw,5	%r1, _f16s,_lts0lo 0x1c, %g21
	}
	{
	  ct	%ctpr2
	  stw,2	%r1, 0x8, %g22
	  stw,5	%r1, 0xc, %g23
	}
.L94180:
	{
	  disp	%ctpr1, .L94379
	  ldqp,0	0x0, [ _f64,_lts0 innerpad ], %g16
	  adds,1	0x0, 0x0, %r4
	  ldqp,2	0x0, [ _f64,_lts2 innerpad +16 ], %g17
	}
	{
	  ldd,0	0x0, [ _f64,_lts0 outerpad +16 ], %g18
	  ldd,2	0x0, [ _f64,_lts2 outerpad +24 ], %g19
	}
	{
	  ldd,0	0x0, [ _f64,_lts0 outerpad ], %g20
	  ldd,2	0x0, [ _f64,_lts2 outerpad +8 ], %g21
	}
	{
	  qpswitchd,0	%g17, %g23
	  qpswitchd,1	%g16, %g22
	  getfd,2	%g16, _f16s,_lts0lo 0x820, %g24
	  ldb,3	0x0, [ _f64,_lts2 innerpad +42 ], %g25
	  addd,4,sm	%r5, _f16s,_lts0hi 0xfd80, %r9
	  addd,5,sm	%r5, _f16s,_lts1lo 0xf740, %r11
	}
	{
	  getfd,0	%g17, _f16s,_lts0lo 0x820, %g26
	  stw,2	%r5, _f16s,_lts0hi 0xf794, %g16
	  stw,5	%r5, _f16s,_lts1lo 0xf798, %g24
	}
	{
	  stw,2	%r5, _f16s,_lts0lo 0xf79c, %g22
	  stw,5	%r10, _f16s,_lts0hi 0x10, %g17
	}
	{
	  stw,2	%r10, _f16s,_lts0lo 0x14, %g26
	  stw,5	%r10, _f16s,_lts0hi 0x18, %g23
	}
	{
	  ldb,0	0x0, [ _f64,_lts1 innerpad +40 ], %g18
	  getfd,1	%g22, _f16s,_lts0lo 0x820, %g16
	  std,2	%r5, _f16s,_lts0hi 0xf770, %g18
	  getfd,4	%g23, _lit16_ref,_lts0lo 0x820, %g17
	}
	{
	  stw,2	%r10, 0xc, %g16
	  stw,5	%r10, _f16s,_lts0lo 0x1c, %g17
	}
	{
	  ldb,0	0x0, [ _f64,_lts1 innerpad +43 ], %g16
	  std,2	%r5, _f16s,_lts0lo 0xf778, %g19
	}
	{
	  ldw,0	0x0, [ _f64,_lts0 innerpad +32 ], %g17
	  ldb,3	0x0, [ _f64,_lts2 innerpad +41 ], %g19
	}
	{
	  std,2	%r5, _f16s,_lts0lo 0xf760, %g20
	  std,5	%r5, _f16s,_lts0hi 0xf768, %g21
	}
	{
	  ldw,0	0x0, [ _f64,_lts1 innerpad +36 ], %g20
	  stb,2	%r10, _f16s,_lts0lo 0x2a, %g25
	}
	{
	  stb,2	%r10, _f16s,_lts0lo 0x28, %g18
	  stb,5	%r10, _f16s,_lts0hi 0x2b, %g16
	}
	{
	  nop 1
	  stw,2	%r10, _f16s,_lts0lo 0x20, %g17
	  stb,5	%r10, _f16s,_lts0hi 0x29, %g19
	}
	{
	  ct	%ctpr1
	  stw,2	%r10, _f16s,_lts0lo 0x24, %g20
	}
.LCS.8:
	.size	scrypt_1024_1_1_256_elway, .- scrypt_1024_1_1_256_elway
	.section .rodata
	.local	keypad
	.type	keypad, #object
	.size	keypad, 0x30
	.align	16
keypad:
	.uadword	0x80000000
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x28000000000
	.local	innerpad
	.type	innerpad, #object
	.size	innerpad, 0x2c
	.align	16
innerpad:
	.uadword	0x80000000
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uaword	0x4a0
	.local	outerpad
	.type	outerpad, #object
	.size	outerpad, 0x20
	.align	16
outerpad:
	.uadword	0x80000000
	.uadword	0x0
	.uadword	0x0
	.uadword	0x30000000000
	.local	finalblk
	.type	finalblk, #object
	.size	finalblk, 0x40
	.align	16
finalblk:
	.uadword	0x8000000000000001
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x0
	.uadword	0x62000000000
	.local	.LCO.1
	.type	.LCO.1, #object
	.size	.LCO.1, 0x10
	.align	16
.LCO.1:
	.uadword	0xb0a090803020100
	.uadword	0x1b1a191813121110
	.local	.LCO.2
	.type	.LCO.2, #object
	.size	.LCO.2, 0x10
	.align	16
.LCO.2:
	.uadword	0xf0e0d0c07060504
	.uadword	0x1f1e1d1c17161514
	.local	.LCO.3
	.type	.LCO.3, #object
	.size	.LCO.3, 0x10
	.align	16
.LCO.3:
	.uadword	0xb0a090803020100
	.uadword	0x1b1a191813121110
	.local	.LCO.4
	.type	.LCO.4, #object
	.size	.LCO.4, 0x10
	.align	16
.LCO.4:
	.uadword	0xf0e0d0c07060504
	.uadword	0x1f1e1d1c17161514
	.local	.LCO.5
	.type	.LCO.5, #object
	.size	.LCO.5, 0x10
	.align	16
.LCO.5:
	.uadword	0x3ff000003ff
	.uadword	0x3ff000003ff
	.local	.LCO.6
	.type	.LCO.6, #object
	.size	.LCO.6, 0x10
	.align	16
.LCO.6:
	.uadword	0xb0a090803020100
	.uadword	0x1b1a191813121110
	.local	.LCO.7
	.type	.LCO.7, #object
	.size	.LCO.7, 0x10
	.align	16
.LCO.7:
	.uadword	0xf0e0d0c07060504
	.uadword	0x1f1e1d1c17161514
	.weak	elbrus_optimizing_compiler_v1.24.11_May_26_2020
	elbrus_optimizing_compiler_v1.24.11_May_26_2020 = 0x0
