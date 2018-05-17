#!/usr/bin/env python2

import os
import sys

# use local git version of manticore
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), 'manticore-git'))

from manticore import Manticore

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
    if rfl & (1L << flag):
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

def format_arg(arg):
    if arg.startswith("byte ptr "):
        arg = arg[9:]
    elif arg.startswith("word ptr "):
        arg = arg[9:]
    elif arg.startswith("dword ptr "):
        arg = arg[10:]
    elif arg.startswith("qword ptr "):
        arg = arg[10:]
    arg = arg.replace(" + ", "+")
    arg = arg.replace(" - ", "-")
    return arg

def format_insn(insn):
    mnemonic = insn.mnemonic
    args = insn.op_str.split(", ")
    args = [ format_arg(arg) for arg in args ]
    if mnemonic == "repe cmpsb":
        mnemonic = "repz"
        args = ["cmpsb"]
    return "%s\t%s" % (mnemonic, ",".join(args))

def format_state(cpu):
    rfl_dec = get_flags(cpu.EFLAGS)
    return("""RAX=%016x RBX=%016x RCX=%016x RDX=%016x
RSI=%016x RDI=%016x RBP=%016x RSP=%016x
R8 =%016x R9 =%016x R10=%016x R11=%016x
R12=%016x R13=%016x R14=%016x R15=%016x
RIP=%016x RFL=%08x [%s]
FS =0000 %016x 00000000 00000000
GS =0000 %016x 00000000 00000000
XMM0 =%032x XMM1 =%032x
XMM2 =%032x XMM3 =%032x
XMM4 =%032x XMM5 =%032x
XMM6 =%032x XMM7 =%032x
XMM8 =%032x XMM9 =%032x
XMM10=%032x XMM11=%032x
XMM12=%032x XMM13=%032x
XMM14=%032x XMM15=%032x
""" % (cpu.RAX, cpu.RBX, cpu.RCX, cpu.RDX, cpu.RSI, cpu.RDI, cpu.RBP, cpu.RSP, cpu.R8, cpu.R9, cpu.R10, cpu.R11, cpu.R12, cpu.R13, cpu.R14, cpu.R15, cpu.RIP, cpu.EFLAGS, rfl_dec, cpu.FS, cpu.GS,
            cpu.XMM0, cpu.XMM1, cpu.XMM2, cpu.XMM3, cpu.XMM4, cpu.XMM5, cpu.XMM6, cpu.XMM7, cpu.XMM8, cpu.XMM9, cpu.XMM10, cpu.XMM11, cpu.XMM12, cpu.XMM13, cpu.XMM14, cpu.XMM15))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [binary]\n" % (sys.argv[0],))
        sys.exit(2)

    m = Manticore(sys.argv[1], sys.argv[2:])
    #with m.locked_context() as context:
    #    context['count'] = 0

    last_rip = None
    rep = [ "repz", "repnz", "repe", "repne" ]

    @m.hook(None)
    def explore(state):
        global last_rip
        rip = state.cpu.RIP
        pc = state.cpu.PC
        ins = state.cpu.instruction
        if rip == last_rip and ins.mnemonic.split(" ")[0] in rep:
            return
        last_rip = rip
        loc = ""
        disasm = format_insn(ins)
        print("""----------------
IN: %s
0x%08x:\t%s

%s""" % (loc, rip, disasm, format_state(state.cpu)))

    #m.run(procs=3)
    m.run()

    #print("Executed " + m.context['count'] + " instructions.")
