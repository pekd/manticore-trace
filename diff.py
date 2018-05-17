#!/bin/python
# vim:set ts=8 sts=8 sw=8 tw=80 cc=80 noet:
import sys

CF = 0
PF = 2
AF = 4
ZF = 6
SF = 7
TF = 8
IF = 9
DF = 10
OF = 11
NT = 14
RF = 16
VM = 17
AC = 18
VIF = 19
VIP = 20
ID = 21

def get_flag(rfl, flag, name):
	if rfl & (1 << flag):
		return name;
	else:
		return "-";

def get_flags(rfl):
	buf = ""
	buf += get_flag(rfl, OF, 'O')
	buf += get_flag(rfl, DF, 'D')
	buf += get_flag(rfl, SF, 'S')
	buf += get_flag(rfl, ZF, 'Z')
	buf += get_flag(rfl, AF, 'A')
	buf += get_flag(rfl, PF, 'P')
	buf += get_flag(rfl, CF, 'C')
	return buf

def get_flag_mask():
	#return (1 << OF) | (1 << DF) | (1 << SF) | (1 << ZF) | (1 << AF) | \
	#		(1 << PF) | (1 << CF)
	return (1 << OF) | (1 << DF) | (1 << SF) | (1 << ZF) | (1 << CF)

def parse_insn(insn):
	parts = insn.split("\t")
	mnemonic = parts[0]
	if len(parts) > 1:
		args = insn.split("\t")[1].split(",")
		return [ mnemonic, args ]
	else:
		return [ mnemonic ]

"""
----------------
IN: _start
0x00001130:     mov     rdi,rsp

RAX=0000000000000000 RBX=0000000000000000 RCX=0000000000000000 RDX=0000000000000000
RSI=0000000000000000 RDI=0000000000000000 RBP=0000000000000000 RSP=00007fff6c843c20
R8 =0000000000000000 R9 =0000000000000000 R10=0000000000000000 R11=0000000000000000
R12=0000000000000000 R13=0000000000000000 R14=0000000000000000 R15=0000000000000000
RIP=0000000000001130 RFL=00000202 [-------]
FS =0000 0000000000000000 00000000 00000000
GS =0000 0000000000000000 00000000 00000000
"""

class CpuState(object):
	def __init__(self, lines):
		if lines[0] != "----------------" or \
				not lines[1].startswith("IN:"):
			raise Exception("Not a cpu state!")
		self.disasm = ":".join(lines[2].split(":")[1:]).strip()
		self.mnemonic = self.disasm.split("\t")[0]
		self.asm = parse_insn(self.disasm)

		self.rax = int(lines[4][ 4:20], 16)
		self.rbx = int(lines[4][25:41], 16)
		self.rcx = int(lines[4][46:62], 16)
		self.rdx = int(lines[4][67:83], 16)
		self.rsi = int(lines[5][ 4:20], 16)
		self.rdi = int(lines[5][25:41], 16)
		self.rbp = int(lines[5][46:62], 16)
		self.rsp = int(lines[5][67:83], 16)
		self.r8  = int(lines[6][ 4:20], 16)
		self.r9  = int(lines[6][25:41], 16)
		self.r10 = int(lines[6][46:62], 16)
		self.r11 = int(lines[6][67:83], 16)
		self.r12 = int(lines[7][ 4:20], 16)
		self.r13 = int(lines[7][25:41], 16)
		self.r14 = int(lines[7][46:62], 16)
		self.r15 = int(lines[7][67:83], 16)
		self.rip = int(lines[8][ 4:20], 16)
		self.rfl = int(lines[8][25:33], 16)
		self.fs  = int(lines[9][ 9:25], 16)
		self.gs  = int(lines[10][9:25], 16)
		self.xmm0  = int(lines[11][ 6:38], 16)
		self.xmm1  = int(lines[11][45:77], 16)
		self.xmm2  = int(lines[12][ 6:38], 16)
		self.xmm3  = int(lines[12][45:77], 16)
		self.xmm4  = int(lines[13][ 6:38], 16)
		self.xmm5  = int(lines[13][45:77], 16)
		self.xmm6  = int(lines[14][ 6:38], 16)
		self.xmm7  = int(lines[14][45:77], 16)
		self.xmm8  = int(lines[15][ 6:38], 16)
		self.xmm9  = int(lines[15][45:77], 16)
		self.xmm10 = int(lines[16][ 6:38], 16)
		self.xmm11 = int(lines[16][45:77], 16)
		self.xmm12 = int(lines[17][ 6:38], 16)
		self.xmm13 = int(lines[17][45:77], 16)
		self.xmm14 = int(lines[18][ 6:38], 16)
		self.xmm15 = int(lines[18][45:77], 16)

	def format_state(self):
		rfl_dec = get_flags(self.rfl)
		return("""RAX=%016x RBX=%016x RCX=%016x RDX=%016x
RSI=%016x RDI=%016x RBP=%016x RSP=%016x
R8 =%016x R9 =%016x R10=%016x R11=%016x
R12=%016x R13=%016x R14=%016x R15=%016x
RIP=%016x RFL=%08x [%s]
FS =0000 %016x 00000000 00000000
GS =0000 %016x 00000000 00000000
""" % (self.rax, self.rbx, self.rcx, self.rdx, self.rsi, self.rdi, self.rbp, \
	self.rsp, self.r8, self.r9, self.r10, self.r11, self.r12, self.r13, \
	self.r14, self.r15, self.rip, self.rfl, rfl_dec, self.fs, self.gs))

	def diff(self, other, use_color=True):
		rfl_dec = get_flags(self.rfl)
		rfl_dec_other = get_flags(other.rfl)
		flag_mask = get_flag_mask()
		rfl_eq = (self.rfl & flag_mask) == (other.rfl & flag_mask)
		rfl_match = ' ' if rfl_eq else '!'
		rax_match = ' ' if self.rax == other.rax else '!'
		rbx_match = ' ' if self.rbx == other.rbx else '!'
		rcx_match = ' ' if self.rcx == other.rcx else '!'
		rdx_match = ' ' if self.rdx == other.rdx else '!'
		rsi_match = ' ' if self.rsi == other.rsi else '!'
		rdi_match = ' ' if self.rdi == other.rdi else '!'
		rbp_match = ' ' if self.rbp == other.rbp else '!'
		rsp_match = ' ' if self.rsp == other.rsp else '!'
		r8_match  = ' ' if self.r8  == other.r8  else '!'
		r9_match  = ' ' if self.r9  == other.r9  else '!'
		r10_match = ' ' if self.r10 == other.r10 else '!'
		r11_match = ' ' if self.r11 == other.r11 else '!'
		r12_match = ' ' if self.r12 == other.r12 else '!'
		r13_match = ' ' if self.r13 == other.r13 else '!'
		r14_match = ' ' if self.r14 == other.r14 else '!'
		r15_match = ' ' if self.r15 == other.r15 else '!'
		xmm0_match  = ' ' if self.xmm0  == other.xmm0  else '!'
		xmm1_match  = ' ' if self.xmm1  == other.xmm1  else '!'
		xmm2_match  = ' ' if self.xmm2  == other.xmm2  else '!'
		xmm3_match  = ' ' if self.xmm3  == other.xmm3  else '!'
		xmm4_match  = ' ' if self.xmm4  == other.xmm4  else '!'
		xmm5_match  = ' ' if self.xmm5  == other.xmm5  else '!'
		xmm6_match  = ' ' if self.xmm6  == other.xmm6  else '!'
		xmm7_match  = ' ' if self.xmm7  == other.xmm7  else '!'
		xmm8_match  = ' ' if self.xmm8  == other.xmm8  else '!'
		xmm9_match  = ' ' if self.xmm9  == other.xmm9  else '!'
		xmm10_match = ' ' if self.xmm10 == other.xmm10 else '!'
		xmm11_match = ' ' if self.xmm11 == other.xmm11 else '!'
		xmm12_match = ' ' if self.xmm12 == other.xmm12 else '!'
		xmm13_match = ' ' if self.xmm13 == other.xmm13 else '!'
		xmm14_match = ' ' if self.xmm14 == other.xmm14 else '!'
		xmm15_match = ' ' if self.xmm15 == other.xmm15 else '!'

		if use_color:
			red = '\x1b[31m'
			rst = '\x1b[0m'
			rfl_color = '' if rfl_eq else red
			rax_color = '' if self.rax == other.rax else red
			rbx_color = '' if self.rbx == other.rbx else red
			rcx_color = '' if self.rcx == other.rcx else red
			rdx_color = '' if self.rdx == other.rdx else red
			rsi_color = '' if self.rsi == other.rsi else red
			rdi_color = '' if self.rdi == other.rdi else red
			rbp_color = '' if self.rbp == other.rbp else red
			rsp_color = '' if self.rsp == other.rsp else red
			r8_color  = '' if self.r8  == other.r8  else red
			r9_color  = '' if self.r9  == other.r9  else red
			r10_color = '' if self.r10 == other.r10 else red
			r11_color = '' if self.r11 == other.r11 else red
			r12_color = '' if self.r12 == other.r12 else red
			r13_color = '' if self.r13 == other.r13 else red
			r14_color = '' if self.r14 == other.r14 else red
			r15_color = '' if self.r15 == other.r15 else red
			xmm0_color  = '' if self.xmm0  == other.xmm0  else red
			xmm1_color  = '' if self.xmm1  == other.xmm1  else red
			xmm2_color  = '' if self.xmm2  == other.xmm2  else red
			xmm3_color  = '' if self.xmm3  == other.xmm3  else red
			xmm4_color  = '' if self.xmm4  == other.xmm4  else red
			xmm5_color  = '' if self.xmm5  == other.xmm5  else red
			xmm6_color  = '' if self.xmm6  == other.xmm6  else red
			xmm7_color  = '' if self.xmm7  == other.xmm7  else red
			xmm8_color  = '' if self.xmm8  == other.xmm8  else red
			xmm9_color  = '' if self.xmm9  == other.xmm9  else red
			xmm10_color = '' if self.xmm10 == other.xmm10 else red
			xmm11_color = '' if self.xmm11 == other.xmm11 else red
			xmm12_color = '' if self.xmm12 == other.xmm12 else red
			xmm13_color = '' if self.xmm13 == other.xmm13 else red
			xmm14_color = '' if self.xmm14 == other.xmm14 else red
			xmm15_color = '' if self.xmm15 == other.xmm15 else red
			return("""RAX=%s%016x%s%sRBX=%s%016x%s%sRCX=%s%016x%s%sRDX=%s%016x%s%s    RAX=%s%016x%s%sRBX=%s%016x%s%sRCX=%s%016x%s%sRDX=%s%016x%s%s
RSI=%s%016x%s%sRDI=%s%016x%s%sRBP=%s%016x%s%sRSP=%s%016x%s%s    RSI=%s%016x%s%sRDI=%s%016x%s%sRBP=%s%016x%s%sRSP=%s%016x%s%s
R8 =%s%016x%s%sR9 =%s%016x%s%sR10=%s%016x%s%sR11=%s%016x%s%s    R8 =%s%016x%s%sR9 =%s%016x%s%sR10=%s%016x%s%sR11=%s%016x%s%s
R12=%s%016x%s%sR13=%s%016x%s%sR14=%s%016x%s%sR15=%s%016x%s%s    R12=%s%016x%s%sR13=%s%016x%s%sR14=%s%016x%s%sR15=%s%016x%s%s
RIP=%016x RFL=%s%08x%s%s[%s]                                             RIP=%016x RFL=%s%08x%s%s[%s]
FS =0000 %016x 00000000 00000000                                             FS =0000 %016x 00000000 00000000
GS =0000 %016x 00000000 00000000                                             GS =0000 %016x 00000000 00000000
XMM0 =%s%032x%s%sXMM1 =%s%032x%s%s          XMM0 =%s%032x%s%sXMM1 =%s%032x%s%s
XMM2 =%s%032x%s%sXMM3 =%s%032x%s%s          XMM2 =%s%032x%s%sXMM3 =%s%032x%s%s
XMM4 =%s%032x%s%sXMM5 =%s%032x%s%s          XMM4 =%s%032x%s%sXMM5 =%s%032x%s%s
XMM6 =%s%032x%s%sXMM7 =%s%032x%s%s          XMM6 =%s%032x%s%sXMM7 =%s%032x%s%s
XMM8 =%s%032x%s%sXMM9 =%s%032x%s%s          XMM8 =%s%032x%s%sXMM9 =%s%032x%s%s
XMM10=%s%032x%s%sXMM11=%s%032x%s%s          XMM10=%s%032x%s%sXMM11=%s%032x%s%s
XMM12=%s%032x%s%sXMM13=%s%032x%s%s          XMM12=%s%032x%s%sXMM13=%s%032x%s%s
XMM14=%s%032x%s%sXMM15=%s%032x%s%s          XMM14=%s%032x%s%sXMM15=%s%032x%s%s""" % \
			(rax_color, self.rax, rst, rax_match, rbx_color, self.rbx, rst, rbx_match, rcx_color, self.rcx, rst, rcx_match, rdx_color, self.rdx, rst, rdx_match,
			rax_color, other.rax, rst, rax_match, rbx_color, other.rbx, rst, rbx_match, rcx_color, other.rcx, rst, rcx_match, rdx_color, other.rdx, rst, rdx_match,
			rsi_color, self.rsi, rst, rsi_match, rdi_color, self.rdi, rst, rdi_match, rbp_color, self.rbp, rst, rbp_match, rsp_color, self.rsp, rst, rsp_match,
			rsi_color, other.rsi, rst, rsi_match, rdi_color, other.rdi, rst, rdi_match, rbp_color, other.rbp, rst, rbp_match, rsp_color, other.rsp, rst, rsp_match,
			r8_color, self.r8, rst, r8_match, r9_color, self.r9, rst, r9_match, r10_color, self.r10, rst, r10_match, r11_color, self.r11, rst, r11_match,
			r8_color, other.r8, rst, r8_match, r9_color, other.r9, rst, r9_match, r10_color, other.r10, rst, r10_match, r11_color, other.r11, rst, r11_match,
			r12_color, self.r12, rst, r12_match, r13_color, self.r13, rst, r13_match, r14_color, self.r14, rst, r14_match, r15_color, self.r15, rst, r15_match,
			r12_color, other.r12, rst, r12_match, r13_color, other.r13, rst, r13_match, r14_color, other.r14, rst, r14_match, r15_color, other.r15, rst, r15_match,
			self.rip, rfl_color, self.rfl, rst, rfl_match, rfl_dec, other.rip, rfl_color, other.rfl, rst, rfl_match, rfl_dec_other,
			self.fs, other.fs, self.gs, other.gs,
			xmm0_color, self.xmm0, rst, xmm0_match, xmm1_color, self.xmm1, rst, xmm1_match, xmm0_color, other.xmm0, rst, xmm0_match, xmm1_color, other.xmm1, rst, xmm1_match,
			xmm2_color, self.xmm2, rst, xmm2_match, xmm3_color, self.xmm3, rst, xmm3_match, xmm2_color, other.xmm2, rst, xmm2_match, xmm3_color, other.xmm3, rst, xmm3_match,
			xmm4_color, self.xmm4, rst, xmm4_match, xmm5_color, self.xmm5, rst, xmm5_match, xmm4_color, other.xmm4, rst, xmm4_match, xmm5_color, other.xmm5, rst, xmm5_match,
			xmm6_color, self.xmm6, rst, xmm6_match, xmm7_color, self.xmm7, rst, xmm7_match, xmm6_color, other.xmm6, rst, xmm6_match, xmm7_color, other.xmm7, rst, xmm7_match,
			xmm8_color, self.xmm8, rst, xmm8_match, xmm9_color, self.xmm9, rst, xmm9_match, xmm8_color, other.xmm8, rst, xmm8_match, xmm9_color, other.xmm9, rst, xmm9_match,
			xmm10_color, self.xmm10, rst, xmm10_match, xmm11_color, self.xmm11, rst, xmm11_match, xmm10_color, other.xmm10, rst, xmm10_match, xmm11_color, other.xmm11, rst, xmm11_match,
			xmm12_color, self.xmm12, rst, xmm12_match, xmm13_color, self.xmm13, rst, xmm13_match, xmm12_color, other.xmm12, rst, xmm12_match, xmm13_color, other.xmm13, rst, xmm13_match,
			xmm14_color, self.xmm14, rst, xmm14_match, xmm15_color, self.xmm15, rst, xmm15_match, xmm14_color, other.xmm14, rst, xmm14_match, xmm15_color, other.xmm15, rst, xmm15_match))
		else:
			return("""RAX=%016x%sRBX=%016x%sRCX=%016x%sRDX=%016x%s    RAX=%016x%sRBX=%016x%sRCX=%016x%sRDX=%016x%s
RSI=%016x%sRDI=%016x%sRBP=%016x%sRSP=%016x%s    RSI=%016x%sRDI=%016x%sRBP=%016x%sRSP=%016x%s
R8 =%016x%sR9 =%016x%sR10=%016x%sR11=%016x%s    R8 =%016x%sR9 =%016x%sR10=%016x%sR11=%016x%s
R12=%016x%sR13=%016x%sR14=%016x%sR15=%016x%s    R12=%016x%sR13=%016x%sR14=%016x%sR15=%016x%s
RIP=%016x RFL=%08x [%s]                                             RIP=%016x RFL=%08x [%s]
FS =0000 %016x 00000000 00000000                                             FS =0000 %016x 00000000 00000000
GS =0000 %016x 00000000 00000000                                             GS =0000 %016x 00000000 00000000
XMM0 =%032x%sXMM1 =%032x%s          XMM0 =%032x%sXMM1 =%032x%s
XMM2 =%032x%sXMM3 =%032x%s          XMM2 =%032x%sXMM3 =%032x%s
XMM4 =%032x%sXMM5 =%032x%s          XMM4 =%032x%sXMM5 =%032x%s
XMM6 =%032x%sXMM7 =%032x%s          XMM6 =%032x%sXMM7 =%032x%s
XMM8 =%032x%sXMM9 =%032x%s          XMM8 =%032x%sXMM9 =%032x%s
XMM10=%032x%sXMM11=%032x%s          XMM10=%032x%sXMM11=%032x%s
XMM12=%032x%sXMM13=%032x%s          XMM12=%032x%sXMM13=%032x%s
XMM14=%032x%sXMM15=%032x%s          XMM14=%032x%sXMM15=%032x%s""" % \
			(self.rax, rax_match, self.rbx, rbx_match, self.rcx, rcx_match, self.rdx, rdx_match,
			other.rax, rax_match, other.rbx, rbx_match, other.rcx, rcx_match, other.rdx, rdx_match,
			self.rsi, rsi_match, self.rdi, rdi_match, self.rbp, rbp_match, self.rsp, rsp_match,
			other.rsi, rsi_match, other.rdi, rdi_match, other.rbp, rbp_match, other.rsp, rsp_match,
			self.r8, r8_match, self.r9, r9_match, self.r10, r10_match, self.r11, r11_match,
			other.r8, r8_match, other.r9, r9_match, other.r10, r10_match, other.r11, r11_match,
			self.r12, r12_match, self.r13, r13_match, self.r14, r14_match, self.r15, r15_match,
			other.r12, r12_match, other.r13, r13_match, other.r14, r14_match, other.r15, r15_match,
			self.rip, self.rfl, rfl_dec, other.rip, other.rfl, rfl_dec_other,
			self.fs, other.fs, self.gs, other.gs,
			self.xmm0, xmm0_match, self.xmm1, xmm1_match, other.xmm0, xmm0_match, other.xmm1, xmm1_match,
			self.xmm2, xmm2_match, self.xmm3, xmm3_match, other.xmm2, xmm2_match, other.xmm3, xmm3_match,
			self.xmm4, xmm4_match, self.xmm5, xmm5_match, other.xmm4, xmm4_match, other.xmm5, xmm5_match,
			self.xmm6, xmm6_match, self.xmm7, xmm7_match, other.xmm6, xmm6_match, other.xmm7, xmm7_match,
			self.xmm8, xmm8_match, self.xmm9, xmm9_match, other.xmm8, xmm8_match, other.xmm9, xmm9_match,
			self.xmm10, xmm10_match, self.xmm11, xmm11_match, other.xmm10, xmm10_match, other.xmm11, xmm11_match,
			self.xmm12, xmm12_match, self.xmm13, xmm13_match, other.xmm12, xmm12_match, other.xmm13, xmm13_match,
			self.xmm14, xmm14_match, self.xmm15, xmm15_match, other.xmm14, xmm14_match, other.xmm15, xmm15_match))

	def full_diff(self, other, use_color=True):
		loc = ""
		disas = ("0x%08x:\t%s" % (self.rip, self.disasm)).expandtabs(8)
		space_cnt = 88 - len(disas)
		spaces = " " * space_cnt if space_cnt > 0 else " "
		disas_other = ("0x%08x:\t%s" % (other.rip, other.disasm)) \
				.expandtabs(8)
		return """----------------
IN: %s
0x%08x:\t%s%s%s

%s
""" % (loc, self.rip, self.disasm, spaces, disas_other, self.diff(other,
		use_color))

	def __str__(self):
		loc = ""
		return """----------------
IN: %s
0x%08x:\t%s

%s
""" % (loc, self.rip, self.disasm, self.format_state())

def get_base(rip):
	return rip & ~0xFFF

def parse(log):
	result = []
	i = 0
	while i < len(log):
		if log[i] != "----------------":
			i += 1
			continue
		if not log[i + 1].startswith("IN:"):
			i += 1
			continue
		result += [ CpuState(log[i:(i + 19)]) ]
		i += 1
	return result

def compare(states_ref, states_vm, skip=0):
	base_ref = get_base(states_ref[0].rip)
	base_vm = get_base(states_vm[0].rip)
	print("base(ref): 0x%016x, base(vm): 0x%016x" % (base_ref, base_vm))

	flag_mask = get_flag_mask()

	stack_ref = states_ref[0].rsp
	stack_vm = states_vm[0].rsp

	for i in range(len(states_ref)):
		if i < skip:
			continue
		if len(states_vm) < i:
			print("error: vm trace too short")
			break
		state_ref = states_ref[i]
		state_vm = states_vm[i]

		offset_ref = state_ref.rip - base_ref
		offset_vm = state_vm.rip - base_vm

		def error(msg):
			print("[%d] error at 0x%08x: %s" % \
					(i, state_vm.rip, msg))
			print(state_vm.full_diff(state_ref))

		if offset_ref != offset_vm:
			error("0x%x (ref) vs 0x%x (vm)" % \
					(offset_ref, offset_vm))
			break
		elif state_ref.mnemonic != state_vm.mnemonic:
			error("%s (ref) vs %s (vm)" % \
					(state_ref.mnemonic, state_vm.mnemonic))
			break
		#elif (state_ref.rfl & flag_mask) != (state_vm.rfl & flag_mask):
		#	error("flags %08x [%s] (ref) vs %08x [%s] (vm)" % \
		#			(state_ref.rfl & flag_mask,
		#				get_flags(state_ref.rfl),
		#				state_vm.rfl & flag_mask,
		#				get_flags(state_vm.rfl)))
		#	break
		else:
			#print("ref:")
			#print(state_ref)
			#print("vm:")
			#print(state_vm)
			print("[0x%x]" % i)
			print(state_vm.full_diff(state_ref))

if __name__ == "__main__":
	filename = sys.argv[1]
	skip = 0
	if len(sys.argv) > 2:
		skip = int(sys.argv[2])
	with open("%s.mant" % filename, "r") as manticore:
		with open("%s.vmx86" % filename, "r") as vmx86:
			print("loading logs...")
			ref = [ x.strip() for x in manticore.readlines() ]
			vm = [ x.strip() for x in vmx86.readlines() ]

			print("parsing logs...")
			states_ref = parse(ref)
			states_vm = parse(vm)

			print("comparing...")
			compare(states_ref, states_vm, skip)
