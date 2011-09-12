// Free Disassembler and Assembler -- Disassembler
//
// Copyright (C) 2001 Oleh Yuschuk
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Disassembler
{

	#region Helpers

	public class ByteStream
	{
		private byte[] bytes;
		private int offset;

		public int SizeLeft { get { return bytes.Length - offset; } }

		public void AdjustOffset(int o) { offset = offset + o; }

		public ByteStream(byte[] bytes, int offset)
		{
			this.bytes = bytes;
			this.offset = offset;
		}

		public ByteStream(byte[] bytes)
		{
			this.bytes = bytes;
			this.offset = 0;
		}

		public ByteStream(ByteStream byteStream, int offset)
		{
			this.bytes = byteStream.bytes;
			this.offset = byteStream.offset + offset;
		}

		public byte this[int position]
		{
			get { return this.bytes[offset + position]; }
		}

		public byte GetByte(int index)
		{
			return (byte)(this[index]);
		}

		public sbyte GetSByte(int index)
		{
			return (sbyte)(this[index]);
		}

		public ushort GetUShort(int index)
		{
			return (ushort)(this[index] + (this[index] << 8));
		}

		public short GetShort(int index)
		{
			return (short)this.GetUShort(index);
		}

		public uint GetUInt(int index)
		{
			return (uint)(this.GetUShort(index) + (this.GetUShort(index + 2) << 16));
		}

		public ulong GetULong(int index)
		{
			return (ulong)(this.GetUInt(index) + (this.GetUInt(index + 4) << 32));
		}

		public long GetLong(int index)
		{
			return (long)(this.GetUInt(index) + (this.GetUInt(index + 4) << 32));
		}
	}

	#endregion // Helpers

	public class Disassemble
	{

		#region Data

		////////////////////////////////////////////////////////////////////////////////
		//////////////////////////// DISASSEMBLER FUNCTIONS ////////////////////////////

		// Work variables of disassembler
		int datasize;           // Size of data (1,2,4 bytes)
		int addrsize;           // Size of address (2 or 4 bytes)
		int segprefix;            // Segment override prefix or SEG_UNDEF
		bool hasrm;                // Command has ModR/M byte
		bool hassib;               // Command has SIB byte
		int dispsize;             // Size of displacement (if any)
		int immsize;              // Size of immediate data (if any)
		int softerror;            // Noncritical disassembler error
		int ndump;                // Current length of command dump
		bool addcomment = true;           // Comment value of operand

		// Copy of input parameters of function Disasm()	
		ByteStream cmd;		// Pointer to binary data
		int pfixup = -1;	// Pointer to possible fixups or NULL (-1)	
		int size;			// Remaining size of the command buffer
		t_disasm da;		// Pointer to disassembly results	
		int mode;			// Disassembly mode (DISASM_xxx)

		// Global Variables
		bool ideal = true;			// Force IDEAL decoding mode
		bool showmemsize = true;	// Always show memory size
		bool putdefseg = false;		// Display default segments in listing
		bool shownear = true;             // Show NEAR modifiers
		bool shortstringcmds = true;      // Use short form of string commands
		int sizesens = 0;             // How to decode size-sensitive mnemonics
		bool symbolic = true;             // Show symbolic addresses in disasm
		bool farcalls = true;             // Accept far calls, returns & addresses
		bool decodevxd = true;            // Decode VxD calls (Win95/98)
		bool privileged = true;           // Accept privileged commands
		bool iocommand = true;            // Accept I/O commands
		bool badshift = false;             // Accept shift out of range 1..31
		bool extraprefix = false;         // Accept superfluous prefixes
		bool lockedbus = true;            // Accept LOCK prefixes
		bool stackalign = true;           // Accept unaligned stack operations
		bool iswindowsnt = false;         // When checking for dangers, assume NT
		//bool tabarguments = false;         // Tab between mnemonic and arguments

		#endregion // Data

		#region Constants

		const int NEGLIMIT = (-16384);   // Limit to display constants as signed
		const int PSEUDOOP = 128;   // Base for pseudooperands

		// Special command features.
		const int WW = 0x01;   // Bit W (size of operand)
		const int SS = 0x02;   // Bit S (sign extention of immediate)
		const int WS = 0x03;   // Bits W and S
		const int W3 = 0x08;   // Bit W at position 3
		const int CC = 0x10;   // Conditional jump
		const int FF = 0x20;   // Forced 16-bit size
		const int LL = 0x40;   // Conditional loop
		const int PR = 0x80;   // Protected command
		const int WP = 0x81;   // I/O command with bit W

		// All possible types of operands in 80x86. A bit more than you expected, he?
		const int NNN = 0;   // No operand
		const int REG = 1;   // Integer register in Reg field
		const int RCM = 2;   // Integer register in command byte
		const int RG4 = 3;   // Integer 4-byte register in Reg field
		const int RAC = 4;   // Accumulator (AL/AX/EAX, implicit)
		const int RAX = 5;   // AX (2-byte, implicit)
		const int RDX = 6;   // DX (16-bit implicit port address)
		const int RCL = 7;   // Implicit CL register (for shifts)
		const int RS0 = 8;   // Top of FPU stack (ST(0), implicit)
		const int RST = 9;   // FPU register (ST(i)) in command byte
		const int RMX = 10;   // MMX register MMx
		const int R3D = 11;   // 3DNow! register MMx
		const int MRG = 12;   // Memory/register in ModRM byte
		const int MR1 = 13;   // 1-byte memory/register in ModRM byte
		const int MR2 = 14;   // 2-byte memory/register in ModRM byte
		const int MR4 = 15;   // 4-byte memory/register in ModRM byte
		const int RR4 = 16;   // 4-byte memory/register (register only)
		const int MR8 = 17;   // 8-byte memory/MMX register in ModRM
		const int RR8 = 18;   // 8-byte MMX register only in ModRM
		const int MRD = 19;   // 8-byte memory/3DNow! register in ModRM
		const int RRD = 20;   // 8-byte memory/3DNow! (register only)
		const int MRJ = 21;   // Memory/reg in ModRM as JUMP target
		const int MMA = 22;   // Memory address in ModRM byte for LEA
		const int MML = 23;   // Memory in ModRM byte (for LES)
		const int MMS = 24;   // Memory in ModRM byte (as SEG:OFFS)
		const int MM6 = 25;   // Memory in ModRm (6-byte descriptor)
		const int MMB = 26;   // Two adjacent memory locations (BOUND)
		const int MD2 = 27;   // Memory in ModRM (16-bit integer)
		const int MB2 = 28;   // Memory in ModRM (16-bit binary)
		const int MD4 = 29;   // Memory in ModRM byte (32-bit integer)
		const int MD8 = 30;   // Memory in ModRM byte (64-bit integer)
		const int MDA = 31;   // Memory in ModRM byte (80-bit BCD)
		const int MF4 = 32;   // Memory in ModRM byte (32-bit float)
		const int MF8 = 33;   // Memory in ModRM byte (64-bit float)
		const int MFA = 34;   // Memory in ModRM byte (80-bit float)
		const int MFE = 35;   // Memory in ModRM byte (FPU environment)
		const int MFS = 36;   // Memory in ModRM byte (FPU state)
		const int MFX = 37;   // Memory in ModRM byte (ext. FPU state)
		const int MSO = 38;   // Source in string op's ([ESI])
		const int MDE = 39;   // Destination in string op's ([EDI])
		const int MXL = 40;   // XLAT operand ([EBX+AL])
		const int IMM = 41;   // Immediate data (8 or 16/32)
		const int IMU = 42;   // Immediate unsigned data (8 or 16/32)
		const int VXD = 43;   // VxD service
		const int IMX = 44;   // Immediate sign-extendable byte
		const int C01 = 45;   // Implicit constant 1 (for shifts)
		const int IMS = 46;   // Immediate byte (for shifts)
		const int IM1 = 47;   // Immediate byte
		const int IM2 = 48;   // Immediate word (ENTER/RET)
		const int IMA = 49;   // Immediate absolute near data address
		const int JOB = 50;   // Immediate byte offset (for jumps)
		const int JOW = 51;   // Immediate full offset (for jumps)
		const int JMF = 52;   // Immediate absolute far jump/call addr
		const int SGM = 53;   // Segment register in ModRM byte
		const int SCM = 54;   // Segment register in command byte
		const int CRX = 55;   // Control register CRx
		const int DRX = 56;   // Debug register DRx

		// Pseudooperands (implicit operands, never appear in assembler commands). Must
		// have index equal to or exceeding PSEUDOOP.
		const int PRN = (PSEUDOOP + 0);   // Near return address
		const int PRF = (PSEUDOOP + 1);   // Far return address
		const int PAC = (PSEUDOOP + 2);   // Accumulator (AL/AX/EAX)
		const int PAH = (PSEUDOOP + 3);   // AH (in LAHF/SAHF commands)
		const int PFL = (PSEUDOOP + 4);   // Lower byte of flags (in LAHF/SAHF)
		const int PS0 = (PSEUDOOP + 5);   // Top of FPU stack (ST(0))
		const int PS1 = (PSEUDOOP + 6);   // ST(1)
		const int PCX = (PSEUDOOP + 7);   // CX/ECX
		const int PDI = (PSEUDOOP + 8);   // EDI (in MMX extentions)

		// Errors detected during command disassembling.
		const int DAE_NOERR = 0;   // No error
		const int DAE_BADCMD = 1;   // Unrecognized command
		const int DAE_CROSS = 2;   // Command crosses end of memory block
		const int DAE_BADSEG = 3;   // Undefined segment register
		const int DAE_MEMORY = 4;   // Register where only memory allowed
		const int DAE_REGISTER = 5;   // Memory where only register allowed
		const int DAE_INTERN = 6;   // Internal error


		////////////////////////////////////////////////////////////////////////////////
		//////////////////// ASSEMBLER, DISASSEMBLER AND EXPRESSIONS ///////////////////

		const int MAXCMDSIZE = 16; // Maximal length of 80x86 command
		const int MAXCALSIZE = 8; // Max length of CALL without prefixes
		const int NMODELS = 8; // Number of assembler search models

		const int INT3 = 0xCC; // Code of 1-byte breakpoint
		const int NOP = 0x90; // Code of 1-byte NOP command
		const int TRAPFLAG = 0x00000100; // Trap flag in CPU flag register

		const int REG_EAX = 0; // Indexes of general-purpose registers
		const int REG_ECX = 1; // in t_reg.
		const int REG_EDX = 2;
		const int REG_EBX = 3;
		const int REG_ESP = 4;
		const int REG_EBP = 5;
		const int REG_ESI = 6;
		const int REG_EDI = 7;

		const int SEG_UNDEF = -1;
		const int SEG_ES = 0; // Indexes of segment/selector registers
		const int SEG_CS = 1;
		const int SEG_SS = 2;
		const int SEG_DS = 3;
		const int SEG_FS = 4;
		const int SEG_GS = 5;

		const int C_TYPEMASK = 0xF0; // Mask for command type
		const int C_CMD = 0x00; // Ordinary instruction
		const int C_PSH = 0x10; // 1-word PUSH instruction
		const int C_POP = 0x20; // 1-word POP instruction
		const int C_MMX = 0x30; // MMX instruction
		const int C_FLT = 0x40; // FPU instruction
		const int C_JMP = 0x50; // JUMP instruction
		const int C_JMC = 0x60; // Conditional JUMP instruction
		const int C_CAL = 0x70; // CALL instruction
		const int C_RET = 0x80; // RET instruction
		const int C_FLG = 0x90; // Changes system flags
		const int C_RTF = 0xA0; // C_JMP and C_FLG simultaneously
		const int C_REP = 0xB0; // Instruction with REPxx prefix
		const int C_PRI = 0xC0; // Privileged instruction
		const int C_DAT = 0xD0; // Data (address) doubleword
		const int C_NOW = 0xE0; // 3DNow! instruction
		const int C_BAD = 0xF0; // Unrecognized command
		const int C_RARE = 0x08; // Rare command, seldom used in programs
		const int C_SIZEMASK = 0x07; // MMX data size or special flag
		const int C_EXPL = 0x01; // (non-MMX) Specify explicit memory size

		const int C_DANGER95 = 0x01; // Command is dangerous under Win95/98
		const int C_DANGER = 0x03; // Command is dangerous everywhere
		const int C_DANGERLOCK = 0x07; // Dangerous with LOCK prefix

		const int DEC_TYPEMASK = 0x1F; // Type of memory byte
		const int DEC_UNKNOWN = 0x00; // Unknown type
		const int DEC_BYTE = 0x01; // Accessed as byte
		const int DEC_WORD = 0x02; // Accessed as short
		const int DEC_NEXTDATA = 0x03; // Subsequent byte of code or data
		const int DEC_DWORD = 0x04; // Accessed as long
		const int DEC_FLOAT4 = 0x05; // Accessed as float
		const int DEC_FWORD = 0x06; // Accessed as descriptor/long pointer
		const int DEC_FLOAT8 = 0x07; // Accessed as double
		const int DEC_QWORD = 0x08; // Accessed as 8-byte integer
		const int DEC_FLOAT10 = 0x09; // Accessed as long double
		const int DEC_TBYTE = 0x0A; // Accessed as 10-byte integer
		const int DEC_STRING = 0x0B; // Zero-terminated ASCII string
		const int DEC_UNICODE = 0x0C; // Zero-terminated UNICODE string
		const int DEC_3DNOW = 0x0D; // Accessed as 3Dnow operand
		const int DEC_BYTESW = 0x11; // Accessed as byte index to switch
		const int DEC_NEXTCODE = 0x13; // Subsequent byte of command
		const int DEC_COMMAND = 0x1D; // First byte of command
		const int DEC_JMPDEST = 0x1E; // Jump destination
		const int DEC_CALLDEST = 0x1F; // Call (and maybe jump) destination
		const int DEC_PROCMASK = 0x60; // Procedure analysis
		const int DEC_PROC = 0x20; // Start of procedure
		const int DEC_PBODY = 0x40; // Body of procedure
		const int DEC_PEND = 0x60; // End of procedure
		const int DEC_CHECKED = 0x80; // Byte was analysed

		const int DECR_TYPEMASK = 0x3F; // Type of register or memory
		const int DECR_BYTE = 0x21; // Byte register
		const int DECR_WORD = 0x22; // Short integer register
		const int DECR_DWORD = 0x24; // Long integer register
		const int DECR_QWORD = 0x28; // MMX register
		const int DECR_FLOAT10 = 0x29; // Floating-point register
		const int DECR_SEG = 0x2A; // Segment register
		const int DECR_3DNOW = 0x2D; // 3Dnow! register
		const int DECR_ISREG = 0x20; // Mask to check that operand is register

		public const int DISASM_SIZE = 0; // Determine command size only
		public const int DISASM_DATA = 1; // Determine size and analysis data
		public const int DISASM_FILE = 3; // Disassembly, no symbols
		public const int DISASM_CODE = 4; // Full disassembly

		// Warnings issued by Disasm():
		const int DAW_FARADDR = 0x0001; // Command is a far jump, call or return
		const int DAW_SEGMENT = 0x0002; // Command loads segment register
		const int DAW_PRIV = 0x0004; // Privileged command
		const int DAW_IO = 0x0008; // I/O command
		const int DAW_SHIFT = 0x0010; // Shift constant out of range 1..31
		const int DAW_PREFIX = 0x0020; // Superfluous prefix
		const int DAW_LOCK = 0x0040; // Command has LOCK prefix
		const int DAW_STACK = 0x0080; // Unaligned stack operation
		const int DAW_DANGER95 = 0x1000; // May mess up Win95 if executed
		const int DAW_DANGEROUS = 0x3000; // May mess up any OS if executed


		#endregion

		#region Constant Names

		static readonly string[,] regname = new string[,]{
		{ "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH", "R8"  },
		{ "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R16" },
		{ "EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI","R32" } };

		static readonly string[] segname = new string[] {
		"ES","CS","SS","DS","FS","GS","SEG?","SEG?" };

		static readonly string[] sizename = new string[]{
		"(0-BYTE)", "BYTE", "WORD", "(3-BYTE)",
		"DWORD", "(5-BYTE)", "FWORD", "(7-BYTE)",
		"QWORD", "(9-BYTE)", "TBYTE" };

		static t_addrdec[] addr16 = new t_addrdec[] {
			new t_addrdec(SEG_DS,"BX+SI"), new t_addrdec(SEG_DS,"BX+DI"),
			new t_addrdec(SEG_SS,"BP+SI"), new t_addrdec(SEG_SS,"BP+DI"),
			new t_addrdec(SEG_DS,"SI"),    new t_addrdec(SEG_DS,"DI"),
			new t_addrdec(SEG_SS,"BP"),    new t_addrdec(SEG_DS,"BX" ) };

		static t_addrdec[] addr32 = new t_addrdec[] {
			new t_addrdec(SEG_DS,"EAX"), new t_addrdec(SEG_DS,"ECX"),
			new t_addrdec(SEG_DS,"EDX"), new t_addrdec(SEG_DS,"EBX"),
			new t_addrdec(SEG_SS,""),    new t_addrdec(SEG_SS,"EBP"),
			new t_addrdec(SEG_DS,"ESI"), new t_addrdec(SEG_DS,"EDI" ) };

		static readonly string[] fpuname = new string[] {
		"ST0","ST1","ST2","ST3","ST4","ST5","ST6","ST7","FPU" };

		static readonly string[] mmxname = new string[]  {
		"MM0","MM1","MM2","MM3","MM4","MM5","MM6","MM7","MMX" };

		static readonly string[] crname = new string[]  {
		"CR0","CR1","CR2","CR3","CR4","CR5","CR6","CR7","CRX" };

		static readonly string[] drname = new string[]  {
		"DR0","DR1","DR2","DR3","DR4","DR5","DR6","DR7","DRX" };

		static readonly t_cmddata[] cmddata = new t_cmddata[] {
			new t_cmddata( 0x0000FF, 0x000090, 1,00,  NNN,NNN,NNN, C_CMD+0,        "NOP" ),
			new t_cmddata( 0x0000FE, 0x00008A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "MOV" ),
			new t_cmddata( 0x0000F8, 0x000050, 1,00,  RCM,NNN,NNN, C_PSH+0,        "PUSH" ),
			new t_cmddata( 0x0000FE, 0x000088, 1,WW,  MRG,REG,NNN, C_CMD+0,        "MOV" ),
			new t_cmddata( 0x0000FF, 0x0000E8, 1,00,  JOW,NNN,NNN, C_CAL+0,        "CALL" ),
			new t_cmddata( 0x0000FD, 0x000068, 1,SS,  IMM,NNN,NNN, C_PSH+0,        "PUSH" ),
			new t_cmddata( 0x0000FF, 0x00008D, 1,00,  REG,MMA,NNN, C_CMD+0,        "LEA" ),
			new t_cmddata( 0x0000FF, 0x000074, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JE,JZ" ),
			new t_cmddata( 0x0000F8, 0x000058, 1,00,  RCM,NNN,NNN, C_POP+0,        "POP" ),
			new t_cmddata( 0x0038FC, 0x000080, 1,WS,  MRG,IMM,NNN, C_CMD+1,        "ADD" ),
			new t_cmddata( 0x0000FF, 0x000075, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JNZ,JNE" ),
			new t_cmddata( 0x0000FF, 0x0000EB, 1,00,  JOB,NNN,NNN, C_JMP+0,        "JMP" ),
			new t_cmddata( 0x0000FF, 0x0000E9, 1,00,  JOW,NNN,NNN, C_JMP+0,        "JMP" ),
			new t_cmddata( 0x0000FE, 0x000084, 1,WW,  MRG,REG,NNN, C_CMD+0,        "TEST" ),
			new t_cmddata( 0x0038FE, 0x0000C6, 1,WW,  MRG,IMM,NNN, C_CMD+1,        "MOV" ),
			new t_cmddata( 0x0000FE, 0x000032, 1,WW,  REG,MRG,NNN, C_CMD+0,        "XOR" ),
			new t_cmddata( 0x0000FE, 0x00003A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "CMP" ),
			new t_cmddata( 0x0038FC, 0x003880, 1,WS,  MRG,IMM,NNN, C_CMD+1,        "CMP" ),
			new t_cmddata( 0x0038FF, 0x0010FF, 1,00,  MRJ,NNN,NNN, C_CAL+0,        "CALL" ),
			new t_cmddata( 0x0000FF, 0x0000C3, 1,00,  PRN,NNN,NNN, C_RET+0,        "RETN,RET" ),
			new t_cmddata( 0x0000F0, 0x0000B0, 1,W3,  RCM,IMM,NNN, C_CMD+0,        "MOV" ),
			new t_cmddata( 0x0000FE, 0x0000A0, 1,WW,  RAC,IMA,NNN, C_CMD+0,        "MOV" ),
			new t_cmddata( 0x00FFFF, 0x00840F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JE,JZ" ),
			new t_cmddata( 0x0000F8, 0x000040, 1,00,  RCM,NNN,NNN, C_CMD+0,        "INC" ),
			new t_cmddata( 0x0038FE, 0x0000F6, 1,WW,  MRG,IMU,NNN, C_CMD+1,        "TEST" ),
			new t_cmddata( 0x0000FE, 0x0000A2, 1,WW,  IMA,RAC,NNN, C_CMD+0,        "MOV" ),
			new t_cmddata( 0x0000FE, 0x00002A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "SUB" ),
			new t_cmddata( 0x0000FF, 0x00007E, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JLE,JNG" ),
			new t_cmddata( 0x00FFFF, 0x00850F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JNZ,JNE" ),
			new t_cmddata( 0x0000FF, 0x0000C2, 1,00,  IM2,PRN,NNN, C_RET+0,        "RETN" ),
			new t_cmddata( 0x0038FF, 0x0030FF, 1,00,  MRG,NNN,NNN, C_PSH+1,        "PUSH" ),
			new t_cmddata( 0x0038FC, 0x000880, 1,WS,  MRG,IMU,NNN, C_CMD+1,        "OR" ),
			new t_cmddata( 0x0038FC, 0x002880, 1,WS,  MRG,IMM,NNN, C_CMD+1,        "SUB" ),
			new t_cmddata( 0x0000F8, 0x000048, 1,00,  RCM,NNN,NNN, C_CMD+0,        "DEC" ),
			new t_cmddata( 0x00FFFF, 0x00BF0F, 2,00,  REG,MR2,NNN, C_CMD+1,        "MOVSX" ),
			new t_cmddata( 0x0000FF, 0x00007C, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JL,JNGE" ),
			new t_cmddata( 0x0000FE, 0x000002, 1,WW,  REG,MRG,NNN, C_CMD+0,        "ADD" ),
			new t_cmddata( 0x0038FC, 0x002080, 1,WS,  MRG,IMU,NNN, C_CMD+1,        "AND" ),
			new t_cmddata( 0x0000FE, 0x00003C, 1,WW,  RAC,IMM,NNN, C_CMD+0,        "CMP" ),
			new t_cmddata( 0x0038FF, 0x0020FF, 1,00,  MRJ,NNN,NNN, C_JMP+0,        "JMP" ),
			new t_cmddata( 0x0038FE, 0x0010F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "NOT" ),
			new t_cmddata( 0x0038FE, 0x0028C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "SHR" ),
			new t_cmddata( 0x0000FE, 0x000038, 1,WW,  MRG,REG,NNN, C_CMD+0,        "CMP" ),
			new t_cmddata( 0x0000FF, 0x00007D, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JGE,JNL" ),
			new t_cmddata( 0x0000FF, 0x00007F, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JG,JNLE" ),
			new t_cmddata( 0x0038FE, 0x0020C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "SHL" ),
			new t_cmddata( 0x0000FE, 0x00001A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "SBB" ),
			new t_cmddata( 0x0038FE, 0x0018F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "NEG" ),
			new t_cmddata( 0x0000FF, 0x0000C9, 1,00,  NNN,NNN,NNN, C_CMD+0,        "LEAVE" ),
			new t_cmddata( 0x0000FF, 0x000060, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "&PUSHA*" ),
			new t_cmddata( 0x0038FF, 0x00008F, 1,00,  MRG,NNN,NNN, C_POP+1,        "POP" ),
			new t_cmddata( 0x0000FF, 0x000061, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "&POPA*" ),
			new t_cmddata( 0x0000F8, 0x000090, 1,00,  RAC,RCM,NNN, C_CMD+0,        "XCHG" ),
			new t_cmddata( 0x0000FE, 0x000086, 1,WW,  MRG,REG,NNN, C_CMD+0,        "XCHG" ),
			new t_cmddata( 0x0000FE, 0x000000, 1,WW,  MRG,REG,NNN, C_CMD+0,        "ADD" ),
			new t_cmddata( 0x0000FE, 0x000010, 1,WW,  MRG,REG,NNN, C_CMD+C_RARE+0, "ADC" ),
			new t_cmddata( 0x0000FE, 0x000012, 1,WW,  REG,MRG,NNN, C_CMD+C_RARE+0, "ADC" ),
			new t_cmddata( 0x0000FE, 0x000020, 1,WW,  MRG,REG,NNN, C_CMD+0,        "AND" ),
			new t_cmddata( 0x0000FE, 0x000022, 1,WW,  REG,MRG,NNN, C_CMD+0,        "AND" ),
			new t_cmddata( 0x0000FE, 0x000008, 1,WW,  MRG,REG,NNN, C_CMD+0,        "OR" ),
			new t_cmddata( 0x0000FE, 0x00000A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "OR" ),
			new t_cmddata( 0x0000FE, 0x000028, 1,WW,  MRG,REG,NNN, C_CMD+0,        "SUB" ),
			new t_cmddata( 0x0000FE, 0x000018, 1,WW,  MRG,REG,NNN, C_CMD+C_RARE+0, "SBB" ),
			new t_cmddata( 0x0000FE, 0x000030, 1,WW,  MRG,REG,NNN, C_CMD+0,        "XOR" ),
			new t_cmddata( 0x0038FC, 0x001080, 1,WS,  MRG,IMM,NNN, C_CMD+C_RARE+1, "ADC" ),
			new t_cmddata( 0x0038FC, 0x001880, 1,WS,  MRG,IMM,NNN, C_CMD+C_RARE+1, "SBB" ),
			new t_cmddata( 0x0038FC, 0x003080, 1,WS,  MRG,IMU,NNN, C_CMD+1,        "XOR" ),
			new t_cmddata( 0x0000FE, 0x000004, 1,WW,  RAC,IMM,NNN, C_CMD+0,        "ADD" ),
			new t_cmddata( 0x0000FE, 0x000014, 1,WW,  RAC,IMM,NNN, C_CMD+C_RARE+0, "ADC" ),
			new t_cmddata( 0x0000FE, 0x000024, 1,WW,  RAC,IMU,NNN, C_CMD+0,        "AND" ),
			new t_cmddata( 0x0000FE, 0x00000C, 1,WW,  RAC,IMU,NNN, C_CMD+0,        "OR" ),
			new t_cmddata( 0x0000FE, 0x00002C, 1,WW,  RAC,IMM,NNN, C_CMD+0,        "SUB" ),
			new t_cmddata( 0x0000FE, 0x00001C, 1,WW,  RAC,IMM,NNN, C_CMD+C_RARE+0, "SBB" ),
			new t_cmddata( 0x0000FE, 0x000034, 1,WW,  RAC,IMU,NNN, C_CMD+0,        "XOR" ),
			new t_cmddata( 0x0038FE, 0x0000FE, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "INC" ),
			new t_cmddata( 0x0038FE, 0x0008FE, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "DEC" ),
			new t_cmddata( 0x0000FE, 0x0000A8, 1,WW,  RAC,IMU,NNN, C_CMD+0,        "TEST" ),
			new t_cmddata( 0x0038FE, 0x0020F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "MUL" ),
			new t_cmddata( 0x0038FE, 0x0028F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "IMUL" ),
			new t_cmddata( 0x00FFFF, 0x00AF0F, 2,00,  REG,MRG,NNN, C_CMD+0,        "IMUL" ),
			new t_cmddata( 0x0000FF, 0x00006B, 1,00,  REG,MRG,IMX, C_CMD+C_RARE+0, "IMUL" ),
			new t_cmddata( 0x0000FF, 0x000069, 1,00,  REG,MRG,IMM, C_CMD+C_RARE+0, "IMUL" ),
			new t_cmddata( 0x0038FE, 0x0030F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "DIV" ),
			new t_cmddata( 0x0038FE, 0x0038F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "IDIV" ),
			new t_cmddata( 0x0000FF, 0x000098, 1,00,  NNN,NNN,NNN, C_CMD+0,        "&CBW:CWDE" ),
			new t_cmddata( 0x0000FF, 0x000099, 1,00,  NNN,NNN,NNN, C_CMD+0,        "&CWD:CDQ" ),
			new t_cmddata( 0x0038FE, 0x0000D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "ROL" ),
			new t_cmddata( 0x0038FE, 0x0008D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "ROR" ),
			new t_cmddata( 0x0038FE, 0x0010D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "RCL" ),
			new t_cmddata( 0x0038FE, 0x0018D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "RCR" ),
			new t_cmddata( 0x0038FE, 0x0020D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "SHL" ),
			new t_cmddata( 0x0038FE, 0x0028D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "SHR" ),
			new t_cmddata( 0x0038FE, 0x0038D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "SAR" ),
			new t_cmddata( 0x0038FE, 0x0000D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "ROL" ),
			new t_cmddata( 0x0038FE, 0x0008D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "ROR" ),
			new t_cmddata( 0x0038FE, 0x0010D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "RCL" ),
			new t_cmddata( 0x0038FE, 0x0018D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "RCR" ),
			new t_cmddata( 0x0038FE, 0x0020D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "SHL" ),
			new t_cmddata( 0x0038FE, 0x0028D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "SHR" ),
			new t_cmddata( 0x0038FE, 0x0038D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "SAR" ),
			new t_cmddata( 0x0038FE, 0x0000C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "ROL" ),
			new t_cmddata( 0x0038FE, 0x0008C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "ROR" ),
			new t_cmddata( 0x0038FE, 0x0010C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "RCL" ),
			new t_cmddata( 0x0038FE, 0x0018C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "RCR" ),
			new t_cmddata( 0x0038FE, 0x0038C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "SAR" ),
			new t_cmddata( 0x0000FF, 0x000070, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JO" ),
			new t_cmddata( 0x0000FF, 0x000071, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JNO" ),
			new t_cmddata( 0x0000FF, 0x000072, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JB,JC" ),
			new t_cmddata( 0x0000FF, 0x000073, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JNB,JNC" ),
			new t_cmddata( 0x0000FF, 0x000076, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JBE,JNA" ),
			new t_cmddata( 0x0000FF, 0x000077, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JA,JNBE" ),
			new t_cmddata( 0x0000FF, 0x000078, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JS" ),
			new t_cmddata( 0x0000FF, 0x000079, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JNS" ),
			new t_cmddata( 0x0000FF, 0x00007A, 1,CC,  JOB,NNN,NNN, C_JMC+C_RARE+0, "JPE,JP" ),
			new t_cmddata( 0x0000FF, 0x00007B, 1,CC,  JOB,NNN,NNN, C_JMC+C_RARE+0, "JPO,JNP" ),
			new t_cmddata( 0x0000FF, 0x0000E3, 1,00,  JOB,NNN,NNN, C_JMC+C_RARE+0, "$JCXZ:JECXZ" ),
			new t_cmddata( 0x00FFFF, 0x00800F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JO" ),
			new t_cmddata( 0x00FFFF, 0x00810F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JNO" ),
			new t_cmddata( 0x00FFFF, 0x00820F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JB,JC" ),
			new t_cmddata( 0x00FFFF, 0x00830F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JNB,JNC" ),
			new t_cmddata( 0x00FFFF, 0x00860F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JBE,JNA" ),
			new t_cmddata( 0x00FFFF, 0x00870F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JA,JNBE" ),
			new t_cmddata( 0x00FFFF, 0x00880F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JS" ),
			new t_cmddata( 0x00FFFF, 0x00890F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JNS" ),
			new t_cmddata( 0x00FFFF, 0x008A0F, 2,CC,  JOW,NNN,NNN, C_JMC+C_RARE+0, "JPE,JP" ),
			new t_cmddata( 0x00FFFF, 0x008B0F, 2,CC,  JOW,NNN,NNN, C_JMC+C_RARE+0, "JPO,JNP" ),
			new t_cmddata( 0x00FFFF, 0x008C0F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JL,JNGE" ),
			new t_cmddata( 0x00FFFF, 0x008D0F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JGE,JNL" ),
			new t_cmddata( 0x00FFFF, 0x008E0F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JLE,JNG" ),
			new t_cmddata( 0x00FFFF, 0x008F0F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JG,JNLE" ),
			new t_cmddata( 0x0000FF, 0x0000F8, 1,00,  NNN,NNN,NNN, C_CMD+0,        "CLC" ),
			new t_cmddata( 0x0000FF, 0x0000F9, 1,00,  NNN,NNN,NNN, C_CMD+0,        "STC" ),
			new t_cmddata( 0x0000FF, 0x0000F5, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "CMC" ),
			new t_cmddata( 0x0000FF, 0x0000FC, 1,00,  NNN,NNN,NNN, C_CMD+0,        "CLD" ),
			new t_cmddata( 0x0000FF, 0x0000FD, 1,00,  NNN,NNN,NNN, C_CMD+0,        "STD" ),
			new t_cmddata( 0x0000FF, 0x0000FA, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "CLI" ),
			new t_cmddata( 0x0000FF, 0x0000FB, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "STI" ),
			new t_cmddata( 0x0000FF, 0x00008C, 1,FF,  MRG,SGM,NNN, C_CMD+C_RARE+0, "MOV" ),
			new t_cmddata( 0x0000FF, 0x00008E, 1,FF,  SGM,MRG,NNN, C_CMD+C_RARE+0, "MOV" ),
			new t_cmddata( 0x0000FE, 0x0000A6, 1,WW,  MSO,MDE,NNN, C_CMD+1,        "CMPS" ),
			new t_cmddata( 0x0000FE, 0x0000AC, 1,WW,  MSO,NNN,NNN, C_CMD+1,        "LODS" ),
			new t_cmddata( 0x0000FE, 0x0000A4, 1,WW,  MDE,MSO,NNN, C_CMD+1,        "MOVS" ),
			new t_cmddata( 0x0000FE, 0x0000AE, 1,WW,  MDE,PAC,NNN, C_CMD+1,        "SCAS" ),
			new t_cmddata( 0x0000FE, 0x0000AA, 1,WW,  MDE,PAC,NNN, C_CMD+1,        "STOS" ),
			new t_cmddata( 0x00FEFF, 0x00A4F3, 1,WW,  MDE,MSO,PCX, C_REP+1,        "REP MOVS" ),
			new t_cmddata( 0x00FEFF, 0x00ACF3, 1,WW,  MSO,PAC,PCX, C_REP+C_RARE+1, "REP LODS" ),
			new t_cmddata( 0x00FEFF, 0x00AAF3, 1,WW,  MDE,PAC,PCX, C_REP+1,        "REP STOS" ),
			new t_cmddata( 0x00FEFF, 0x00A6F3, 1,WW,  MDE,MSO,PCX, C_REP+1,        "REPE CMPS" ),
			new t_cmddata( 0x00FEFF, 0x00AEF3, 1,WW,  MDE,PAC,PCX, C_REP+1,        "REPE SCAS" ),
			new t_cmddata( 0x00FEFF, 0x00A6F2, 1,WW,  MDE,MSO,PCX, C_REP+1,        "REPNE CMPS" ),
			new t_cmddata( 0x00FEFF, 0x00AEF2, 1,WW,  MDE,PAC,PCX, C_REP+1,        "REPNE SCAS" ),
			new t_cmddata( 0x0000FF, 0x0000EA, 1,00,  JMF,NNN,NNN, C_JMP+C_RARE+0, "JMP" ),
			new t_cmddata( 0x0038FF, 0x0028FF, 1,00,  MMS,NNN,NNN, C_JMP+C_RARE+1, "JMP" ),
			new t_cmddata( 0x0000FF, 0x00009A, 1,00,  JMF,NNN,NNN, C_CAL+C_RARE+0, "CALL" ),
			new t_cmddata( 0x0038FF, 0x0018FF, 1,00,  MMS,NNN,NNN, C_CAL+C_RARE+1, "CALL" ),
			new t_cmddata( 0x0000FF, 0x0000CB, 1,00,  PRF,NNN,NNN, C_RET+C_RARE+0, "RETF" ),
			new t_cmddata( 0x0000FF, 0x0000CA, 1,00,  IM2,PRF,NNN, C_RET+C_RARE+0, "RETF" ),
			new t_cmddata( 0x00FFFF, 0x00A40F, 2,00,  MRG,REG,IMS, C_CMD+0,        "SHLD" ),
			new t_cmddata( 0x00FFFF, 0x00AC0F, 2,00,  MRG,REG,IMS, C_CMD+0,        "SHRD" ),
			new t_cmddata( 0x00FFFF, 0x00A50F, 2,00,  MRG,REG,RCL, C_CMD+0,        "SHLD" ),
			new t_cmddata( 0x00FFFF, 0x00AD0F, 2,00,  MRG,REG,RCL, C_CMD+0,        "SHRD" ),
			new t_cmddata( 0x00F8FF, 0x00C80F, 2,00,  RCM,NNN,NNN, C_CMD+C_RARE+0, "BSWAP" ),
			new t_cmddata( 0x00FEFF, 0x00C00F, 2,WW,  MRG,REG,NNN, C_CMD+C_RARE+0, "XADD" ),
			new t_cmddata( 0x0000FF, 0x0000E2, 1,LL,  JOB,PCX,NNN, C_JMC+0,        "$LOOP*" ),
			new t_cmddata( 0x0000FF, 0x0000E1, 1,LL,  JOB,PCX,NNN, C_JMC+0,        "$LOOP*E" ),
			new t_cmddata( 0x0000FF, 0x0000E0, 1,LL,  JOB,PCX,NNN, C_JMC+0,        "$LOOP*NE" ),
			new t_cmddata( 0x0000FF, 0x0000C8, 1,00,  IM2,IM1,NNN, C_CMD+0,        "ENTER" ),
			new t_cmddata( 0x0000FE, 0x0000E4, 1,WP,  RAC,IM1,NNN, C_CMD+C_RARE+0, "IN" ),
			new t_cmddata( 0x0000FE, 0x0000EC, 1,WP,  RAC,RDX,NNN, C_CMD+C_RARE+0, "IN" ),
			new t_cmddata( 0x0000FE, 0x0000E6, 1,WP,  IM1,RAC,NNN, C_CMD+C_RARE+0, "OUT" ),
			new t_cmddata( 0x0000FE, 0x0000EE, 1,WP,  RDX,RAC,NNN, C_CMD+C_RARE+0, "OUT" ),
			new t_cmddata( 0x0000FE, 0x00006C, 1,WP,  MDE,RDX,NNN, C_CMD+C_RARE+1, "INS" ),
			new t_cmddata( 0x0000FE, 0x00006E, 1,WP,  RDX,MDE,NNN, C_CMD+C_RARE+1, "OUTS" ),
			new t_cmddata( 0x00FEFF, 0x006CF3, 1,WP,  MDE,RDX,PCX, C_REP+C_RARE+1, "REP INS" ),
			new t_cmddata( 0x00FEFF, 0x006EF3, 1,WP,  RDX,MDE,PCX, C_REP+C_RARE+1, "REP OUTS" ),
			new t_cmddata( 0x0000FF, 0x000037, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "AAA" ),
			new t_cmddata( 0x0000FF, 0x00003F, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "AAS" ),
			new t_cmddata( 0x00FFFF, 0x000AD4, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "AAM" ),
			new t_cmddata( 0x0000FF, 0x0000D4, 1,00,  IM1,NNN,NNN, C_CMD+C_RARE+0, "AAM" ),
			new t_cmddata( 0x00FFFF, 0x000AD5, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "AAD" ),
			new t_cmddata( 0x0000FF, 0x0000D5, 1,00,  IM1,NNN,NNN, C_CMD+C_RARE+0, "AAD" ),
			new t_cmddata( 0x0000FF, 0x000027, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "DAA" ),
			new t_cmddata( 0x0000FF, 0x00002F, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "DAS" ),
			new t_cmddata( 0x0000FF, 0x0000F4, 1,PR,  NNN,NNN,NNN, C_PRI+C_RARE+0, "HLT" ),
			new t_cmddata( 0x0000FF, 0x00000E, 1,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" ),
			new t_cmddata( 0x0000FF, 0x000016, 1,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" ),
			new t_cmddata( 0x0000FF, 0x00001E, 1,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" ),
			new t_cmddata( 0x0000FF, 0x000006, 1,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" ),
			new t_cmddata( 0x00FFFF, 0x00A00F, 2,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" ),
			new t_cmddata( 0x00FFFF, 0x00A80F, 2,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" ),
			new t_cmddata( 0x0000FF, 0x00001F, 1,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" ),
			new t_cmddata( 0x0000FF, 0x000007, 1,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" ),
			new t_cmddata( 0x0000FF, 0x000017, 1,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" ),
			new t_cmddata( 0x00FFFF, 0x00A10F, 2,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" ),
			new t_cmddata( 0x00FFFF, 0x00A90F, 2,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" ),
			new t_cmddata( 0x0000FF, 0x0000D7, 1,00,  MXL,NNN,NNN, C_CMD+C_RARE+1, "XLAT" ),
			new t_cmddata( 0x00FFFF, 0x00BE0F, 2,00,  REG,MR1,NNN, C_CMD+1,        "MOVSX" ),
			new t_cmddata( 0x00FFFF, 0x00B60F, 2,00,  REG,MR1,NNN, C_CMD+1,        "MOVZX" ),
			new t_cmddata( 0x00FFFF, 0x00B70F, 2,00,  REG,MR2,NNN, C_CMD+1,        "MOVZX" ),
			new t_cmddata( 0x0000FF, 0x00009B, 1,00,  NNN,NNN,NNN, C_CMD+0,        "WAIT" ),
			new t_cmddata( 0x0000FF, 0x00009F, 1,00,  PAH,PFL,NNN, C_CMD+C_RARE+0, "LAHF" ),
			new t_cmddata( 0x0000FF, 0x00009E, 1,00,  PFL,PAH,NNN, C_CMD+C_RARE+0, "SAHF" ),
			new t_cmddata( 0x0000FF, 0x00009C, 1,00,  NNN,NNN,NNN, C_PSH+0,        "&PUSHF*" ),
			new t_cmddata( 0x0000FF, 0x00009D, 1,00,  NNN,NNN,NNN, C_FLG+0,        "&POPF*" ),
			new t_cmddata( 0x0000FF, 0x0000CD, 1,00,  IM1,NNN,NNN, C_CAL+C_RARE+0, "INT" ),
			new t_cmddata( 0x0000FF, 0x0000CC, 1,00,  NNN,NNN,NNN, C_CAL+C_RARE+0, "INT3" ),
			new t_cmddata( 0x0000FF, 0x0000CE, 1,00,  NNN,NNN,NNN, C_CAL+C_RARE+0, "INTO" ),
			new t_cmddata( 0x0000FF, 0x0000CF, 1,00,  NNN,NNN,NNN, C_RTF+C_RARE+0, "&IRET*" ),
			new t_cmddata( 0x00FFFF, 0x00900F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETO" ),
			new t_cmddata( 0x00FFFF, 0x00910F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETNO" ),
			new t_cmddata( 0x00FFFF, 0x00920F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETB,SETC" ),
			new t_cmddata( 0x00FFFF, 0x00930F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETNB,SETNC" ),
			new t_cmddata( 0x00FFFF, 0x00940F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETE,SETZ" ),
			new t_cmddata( 0x00FFFF, 0x00950F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETNE,SETNZ" ),
			new t_cmddata( 0x00FFFF, 0x00960F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETBE,SETNA" ),
			new t_cmddata( 0x00FFFF, 0x00970F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETA,SETNBE" ),
			new t_cmddata( 0x00FFFF, 0x00980F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETS" ),
			new t_cmddata( 0x00FFFF, 0x00990F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETNS" ),
			new t_cmddata( 0x00FFFF, 0x009A0F, 2,CC,  MR1,NNN,NNN, C_CMD+C_RARE+0, "SETPE,SETP" ),
			new t_cmddata( 0x00FFFF, 0x009B0F, 2,CC,  MR1,NNN,NNN, C_CMD+C_RARE+0, "SETPO,SETNP" ),
			new t_cmddata( 0x00FFFF, 0x009C0F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETL,SETNGE" ),
			new t_cmddata( 0x00FFFF, 0x009D0F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETGE,SETNL" ),
			new t_cmddata( 0x00FFFF, 0x009E0F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETLE,SETNG" ),
			new t_cmddata( 0x00FFFF, 0x009F0F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETG,SETNLE" ),
			new t_cmddata( 0x38FFFF, 0x20BA0F, 2,00,  MRG,IM1,NNN, C_CMD+C_RARE+1, "BT" ),
			new t_cmddata( 0x38FFFF, 0x28BA0F, 2,00,  MRG,IM1,NNN, C_CMD+C_RARE+1, "BTS" ),
			new t_cmddata( 0x38FFFF, 0x30BA0F, 2,00,  MRG,IM1,NNN, C_CMD+C_RARE+1, "BTR" ),
			new t_cmddata( 0x38FFFF, 0x38BA0F, 2,00,  MRG,IM1,NNN, C_CMD+C_RARE+1, "BTC" ),
			new t_cmddata( 0x00FFFF, 0x00A30F, 2,00,  MRG,REG,NNN, C_CMD+C_RARE+1, "BT" ),
			new t_cmddata( 0x00FFFF, 0x00AB0F, 2,00,  MRG,REG,NNN, C_CMD+C_RARE+1, "BTS" ),
			new t_cmddata( 0x00FFFF, 0x00B30F, 2,00,  MRG,REG,NNN, C_CMD+C_RARE+1, "BTR" ),
			new t_cmddata( 0x00FFFF, 0x00BB0F, 2,00,  MRG,REG,NNN, C_CMD+C_RARE+1, "BTC" ),
			new t_cmddata( 0x0000FF, 0x0000C5, 1,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LDS" ),
			new t_cmddata( 0x0000FF, 0x0000C4, 1,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LES" ),
			new t_cmddata( 0x00FFFF, 0x00B40F, 2,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LFS" ),
			new t_cmddata( 0x00FFFF, 0x00B50F, 2,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LGS" ),
			new t_cmddata( 0x00FFFF, 0x00B20F, 2,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LSS" ),
			new t_cmddata( 0x0000FF, 0x000063, 1,00,  MRG,REG,NNN, C_CMD+C_RARE+0, "ARPL" ),
			new t_cmddata( 0x0000FF, 0x000062, 1,00,  REG,MMB,NNN, C_CMD+C_RARE+0, "BOUND" ),
			new t_cmddata( 0x00FFFF, 0x00BC0F, 2,00,  REG,MRG,NNN, C_CMD+C_RARE+0, "BSF" ),
			new t_cmddata( 0x00FFFF, 0x00BD0F, 2,00,  REG,MRG,NNN, C_CMD+C_RARE+0, "BSR" ),
			new t_cmddata( 0x00FFFF, 0x00060F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "CLTS" ),
			new t_cmddata( 0x00FFFF, 0x00400F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVO" ),
			new t_cmddata( 0x00FFFF, 0x00410F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVNO" ),
			new t_cmddata( 0x00FFFF, 0x00420F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVB,CMOVC" ),
			new t_cmddata( 0x00FFFF, 0x00430F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVNB,CMOVNC" ),
			new t_cmddata( 0x00FFFF, 0x00440F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVE,CMOVZ" ),
			new t_cmddata( 0x00FFFF, 0x00450F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVNE,CMOVNZ" ),
			new t_cmddata( 0x00FFFF, 0x00460F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVBE,CMOVNA" ),
			new t_cmddata( 0x00FFFF, 0x00470F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVA,CMOVNBE" ),
			new t_cmddata( 0x00FFFF, 0x00480F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVS" ),
			new t_cmddata( 0x00FFFF, 0x00490F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVNS" ),
			new t_cmddata( 0x00FFFF, 0x004A0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVPE,CMOVP" ),
			new t_cmddata( 0x00FFFF, 0x004B0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVPO,CMOVNP" ),
			new t_cmddata( 0x00FFFF, 0x004C0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVL,CMOVNGE" ),
			new t_cmddata( 0x00FFFF, 0x004D0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVGE,CMOVNL" ),
			new t_cmddata( 0x00FFFF, 0x004E0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVLE,CMOVNG" ),
			new t_cmddata( 0x00FFFF, 0x004F0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVG,CMOVNLE" ),
			new t_cmddata( 0x00FEFF, 0x00B00F, 2,WW,  MRG,REG,NNN, C_CMD+C_RARE+0, "CMPXCHG" ),
			new t_cmddata( 0x38FFFF, 0x08C70F, 2,00,  MD8,NNN,NNN, C_CMD+C_RARE+1, "CMPXCHG8B" ),
			new t_cmddata( 0x00FFFF, 0x00A20F, 2,00,  NNN,NNN,NNN, C_CMD+0,        "CPUID" ),
			new t_cmddata( 0x00FFFF, 0x00080F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "INVD" ),
			new t_cmddata( 0x00FFFF, 0x00020F, 2,00,  REG,MRG,NNN, C_CMD+C_RARE+0, "LAR" ),
			new t_cmddata( 0x00FFFF, 0x00030F, 2,00,  REG,MRG,NNN, C_CMD+C_RARE+0, "LSL" ),
			new t_cmddata( 0x38FFFF, 0x38010F, 2,PR,  MR1,NNN,NNN, C_CMD+C_RARE+0, "INVLPG" ),
			new t_cmddata( 0x00FFFF, 0x00090F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "WBINVD" ),
			new t_cmddata( 0x38FFFF, 0x10010F, 2,PR,  MM6,NNN,NNN, C_CMD+C_RARE+0, "LGDT" ),
			new t_cmddata( 0x38FFFF, 0x00010F, 2,00,  MM6,NNN,NNN, C_CMD+C_RARE+0, "SGDT" ),
			new t_cmddata( 0x38FFFF, 0x18010F, 2,PR,  MM6,NNN,NNN, C_CMD+C_RARE+0, "LIDT" ),
			new t_cmddata( 0x38FFFF, 0x08010F, 2,00,  MM6,NNN,NNN, C_CMD+C_RARE+0, "SIDT" ),
			new t_cmddata( 0x38FFFF, 0x10000F, 2,PR,  MR2,NNN,NNN, C_CMD+C_RARE+0, "LLDT" ),
			new t_cmddata( 0x38FFFF, 0x00000F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "SLDT" ),
			new t_cmddata( 0x38FFFF, 0x18000F, 2,PR,  MR2,NNN,NNN, C_CMD+C_RARE+0, "LTR" ),
			new t_cmddata( 0x38FFFF, 0x08000F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "STR" ),
			new t_cmddata( 0x38FFFF, 0x30010F, 2,PR,  MR2,NNN,NNN, C_CMD+C_RARE+0, "LMSW" ),
			new t_cmddata( 0x38FFFF, 0x20010F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "SMSW" ),
			new t_cmddata( 0x38FFFF, 0x20000F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "VERR" ),
			new t_cmddata( 0x38FFFF, 0x28000F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "VERW" ),
			new t_cmddata( 0xC0FFFF, 0xC0220F, 2,PR,  CRX,RR4,NNN, C_CMD+C_RARE+0, "MOV" ),
			new t_cmddata( 0xC0FFFF, 0xC0200F, 2,00,  RR4,CRX,NNN, C_CMD+C_RARE+0, "MOV" ),
			new t_cmddata( 0xC0FFFF, 0xC0230F, 2,PR,  DRX,RR4,NNN, C_CMD+C_RARE+0, "MOV" ),
			new t_cmddata( 0xC0FFFF, 0xC0210F, 2,PR,  RR4,DRX,NNN, C_CMD+C_RARE+0, "MOV" ),
			new t_cmddata( 0x00FFFF, 0x00310F, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "RDTSC" ),
			new t_cmddata( 0x00FFFF, 0x00320F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "RDMSR" ),
			new t_cmddata( 0x00FFFF, 0x00300F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "WRMSR" ),
			new t_cmddata( 0x00FFFF, 0x00330F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "RDPMC" ),
			new t_cmddata( 0x00FFFF, 0x00AA0F, 2,PR,  NNN,NNN,NNN, C_RTF+C_RARE+0, "RSM" ),
			new t_cmddata( 0x00FFFF, 0x000B0F, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "UD2" ),
			new t_cmddata( 0x00FFFF, 0x00340F, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "SYSENTER" ),
			new t_cmddata( 0x00FFFF, 0x00350F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "SYSEXIT" ),
			new t_cmddata( 0x0000FF, 0x0000D6, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "SALC" ),
			// FPU instructions. Never change the order of instructions!
			new t_cmddata( 0x00FFFF, 0x00F0D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "F2XM1" ),
			new t_cmddata( 0x00FFFF, 0x00E0D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FCHS" ),
			new t_cmddata( 0x00FFFF, 0x00E1D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FABS" ),
			new t_cmddata( 0x00FFFF, 0x00E2DB, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FCLEX" ),
			new t_cmddata( 0x00FFFF, 0x00E3DB, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FINIT" ),
			new t_cmddata( 0x00FFFF, 0x00F6D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FDECSTP" ),
			new t_cmddata( 0x00FFFF, 0x00F7D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FINCSTP" ),
			new t_cmddata( 0x00FFFF, 0x00E4D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FTST" ),
			new t_cmddata( 0x00FFFF, 0x00FAD9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FSQRT" ),
			new t_cmddata( 0x00FFFF, 0x00FED9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FSIN" ),
			new t_cmddata( 0x00FFFF, 0x00FFD9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FCOS" ),
			new t_cmddata( 0x00FFFF, 0x00FBD9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FSINCOS" ),
			new t_cmddata( 0x00FFFF, 0x00F2D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FPTAN" ),
			new t_cmddata( 0x00FFFF, 0x00F3D9, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FPATAN" ),
			new t_cmddata( 0x00FFFF, 0x00F8D9, 2,00,  PS1,PS0,NNN, C_FLT+0,        "FPREM" ),
			new t_cmddata( 0x00FFFF, 0x00F5D9, 2,00,  PS1,PS0,NNN, C_FLT+0,        "FPREM1" ),
			new t_cmddata( 0x00FFFF, 0x00F1D9, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FYL2X" ),
			new t_cmddata( 0x00FFFF, 0x00F9D9, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FYL2XP1" ),
			new t_cmddata( 0x00FFFF, 0x00FCD9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FRNDINT" ),
			new t_cmddata( 0x00FFFF, 0x00E8D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLD1" ),
			new t_cmddata( 0x00FFFF, 0x00E9D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDL2T" ),
			new t_cmddata( 0x00FFFF, 0x00EAD9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDL2E" ),
			new t_cmddata( 0x00FFFF, 0x00EBD9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDPI" ),
			new t_cmddata( 0x00FFFF, 0x00ECD9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDLG2" ),
			new t_cmddata( 0x00FFFF, 0x00EDD9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDLN2" ),
			new t_cmddata( 0x00FFFF, 0x00EED9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDZ" ),
			new t_cmddata( 0x00FFFF, 0x00FDD9, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FSCALE" ),
			new t_cmddata( 0x00FFFF, 0x00D0D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FNOP" ),
			new t_cmddata( 0x00FFFF, 0x00E0DF, 2,FF,  RAX,NNN,NNN, C_FLT+0,        "FSTSW" ),
			new t_cmddata( 0x00FFFF, 0x00E5D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FXAM" ),
			new t_cmddata( 0x00FFFF, 0x00F4D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FXTRACT" ),
			new t_cmddata( 0x00FFFF, 0x00D9DE, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FCOMPP" ),
			new t_cmddata( 0x00FFFF, 0x00E9DA, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FUCOMPP" ),
			new t_cmddata( 0x00F8FF, 0x00C0DD, 2,00,  RST,NNN,NNN, C_FLT+0,        "FFREE" ),
			new t_cmddata( 0x00F8FF, 0x00C0DA, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVB" ),
			new t_cmddata( 0x00F8FF, 0x00C8DA, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVE" ),
			new t_cmddata( 0x00F8FF, 0x00D0DA, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVBE" ),
			new t_cmddata( 0x00F8FF, 0x00D8DA, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVU" ),
			new t_cmddata( 0x00F8FF, 0x00C0DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVNB" ),
			new t_cmddata( 0x00F8FF, 0x00C8DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVNE" ),
			new t_cmddata( 0x00F8FF, 0x00D0DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVNBE" ),
			new t_cmddata( 0x00F8FF, 0x00D8DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVNU" ),
			new t_cmddata( 0x00F8FF, 0x00F0DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCOMI" ),
			new t_cmddata( 0x00F8FF, 0x00F0DF, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCOMIP" ),
			new t_cmddata( 0x00F8FF, 0x00E8DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FUCOMI" ),
			new t_cmddata( 0x00F8FF, 0x00E8DF, 2,00,  RS0,RST,NNN, C_FLT+0,        "FUCOMIP" ),
			new t_cmddata( 0x00F8FF, 0x00C0D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FADD" ),
			new t_cmddata( 0x00F8FF, 0x00C0DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FADD" ),
			new t_cmddata( 0x00F8FF, 0x00C0DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FADDP" ),
			new t_cmddata( 0x00F8FF, 0x00E0D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FSUB" ),
			new t_cmddata( 0x00F8FF, 0x00E8DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FSUB" ),
			new t_cmddata( 0x00F8FF, 0x00E8DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FSUBP" ),
			new t_cmddata( 0x00F8FF, 0x00E8D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FSUBR" ),
			new t_cmddata( 0x00F8FF, 0x00E0DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FSUBR" ),
			new t_cmddata( 0x00F8FF, 0x00E0DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FSUBRP" ),
			new t_cmddata( 0x00F8FF, 0x00C8D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FMUL" ),
			new t_cmddata( 0x00F8FF, 0x00C8DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FMUL" ),
			new t_cmddata( 0x00F8FF, 0x00C8DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FMULP" ),
			new t_cmddata( 0x00F8FF, 0x00D0D8, 2,00,  RST,PS0,NNN, C_FLT+0,        "FCOM" ),
			new t_cmddata( 0x00F8FF, 0x00D8D8, 2,00,  RST,PS0,NNN, C_FLT+0,        "FCOMP" ),
			new t_cmddata( 0x00F8FF, 0x00E0DD, 2,00,  RST,PS0,NNN, C_FLT+0,        "FUCOM" ),
			new t_cmddata( 0x00F8FF, 0x00E8DD, 2,00,  RST,PS0,NNN, C_FLT+0,        "FUCOMP" ),
			new t_cmddata( 0x00F8FF, 0x00F0D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FDIV" ),
			new t_cmddata( 0x00F8FF, 0x00F8DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FDIV" ),
			new t_cmddata( 0x00F8FF, 0x00F8DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FDIVP" ),
			new t_cmddata( 0x00F8FF, 0x00F8D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FDIVR" ),
			new t_cmddata( 0x00F8FF, 0x00F0DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FDIVR" ),
			new t_cmddata( 0x00F8FF, 0x00F0DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FDIVRP" ),
			new t_cmddata( 0x00F8FF, 0x00C0D9, 2,00,  RST,NNN,NNN, C_FLT+0,        "FLD" ),
			new t_cmddata( 0x00F8FF, 0x00D0DD, 2,00,  RST,PS0,NNN, C_FLT+0,        "FST" ),
			new t_cmddata( 0x00F8FF, 0x00D8DD, 2,00,  RST,PS0,NNN, C_FLT+0,        "FSTP" ),
			new t_cmddata( 0x00F8FF, 0x00C8D9, 2,00,  RST,PS0,NNN, C_FLT+0,        "FXCH" ),
			new t_cmddata( 0x0038FF, 0x0000D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FADD" ),
			new t_cmddata( 0x0038FF, 0x0000DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FADD" ),
			new t_cmddata( 0x0038FF, 0x0000DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIADD" ),
			new t_cmddata( 0x0038FF, 0x0000DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIADD" ),
			new t_cmddata( 0x0038FF, 0x0020D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FSUB" ),
			new t_cmddata( 0x0038FF, 0x0020DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FSUB" ),
			new t_cmddata( 0x0038FF, 0x0020DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FISUB" ),
			new t_cmddata( 0x0038FF, 0x0020DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FISUB" ),
			new t_cmddata( 0x0038FF, 0x0028D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FSUBR" ),
			new t_cmddata( 0x0038FF, 0x0028DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FSUBR" ),
			new t_cmddata( 0x0038FF, 0x0028DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FISUBR" ),
			new t_cmddata( 0x0038FF, 0x0028DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FISUBR" ),
			new t_cmddata( 0x0038FF, 0x0008D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FMUL" ),
			new t_cmddata( 0x0038FF, 0x0008DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FMUL" ),
			new t_cmddata( 0x0038FF, 0x0008DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIMUL" ),
			new t_cmddata( 0x0038FF, 0x0008DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIMUL" ),
			new t_cmddata( 0x0038FF, 0x0010D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FCOM" ),
			new t_cmddata( 0x0038FF, 0x0010DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FCOM" ),
			new t_cmddata( 0x0038FF, 0x0018D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FCOMP" ),
			new t_cmddata( 0x0038FF, 0x0018DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FCOMP" ),
			new t_cmddata( 0x0038FF, 0x0030D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FDIV" ),
			new t_cmddata( 0x0038FF, 0x0030DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FDIV" ),
			new t_cmddata( 0x0038FF, 0x0030DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIDIV" ),
			new t_cmddata( 0x0038FF, 0x0030DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIDIV" ),
			new t_cmddata( 0x0038FF, 0x0038D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FDIVR" ),
			new t_cmddata( 0x0038FF, 0x0038DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FDIVR" ),
			new t_cmddata( 0x0038FF, 0x0038DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIDIVR" ),
			new t_cmddata( 0x0038FF, 0x0038DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIDIVR" ),
			new t_cmddata( 0x0038FF, 0x0020DF, 1,00,  MDA,NNN,NNN, C_FLT+C_RARE+1, "FBLD" ),
			new t_cmddata( 0x0038FF, 0x0030DF, 1,00,  MDA,PS0,NNN, C_FLT+C_RARE+1, "FBSTP" ),
			new t_cmddata( 0x0038FF, 0x0010DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FICOM" ),
			new t_cmddata( 0x0038FF, 0x0010DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FICOM" ),
			new t_cmddata( 0x0038FF, 0x0018DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FICOMP" ),
			new t_cmddata( 0x0038FF, 0x0018DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FICOMP" ),
			new t_cmddata( 0x0038FF, 0x0000DF, 1,00,  MD2,NNN,NNN, C_FLT+1,        "FILD" ),
			new t_cmddata( 0x0038FF, 0x0000DB, 1,00,  MD4,NNN,NNN, C_FLT+1,        "FILD" ),
			new t_cmddata( 0x0038FF, 0x0028DF, 1,00,  MD8,NNN,NNN, C_FLT+1,        "FILD" ),
			new t_cmddata( 0x0038FF, 0x0010DF, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIST" ),
			new t_cmddata( 0x0038FF, 0x0010DB, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIST" ),
			new t_cmddata( 0x0038FF, 0x0018DF, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FISTP" ),
			new t_cmddata( 0x0038FF, 0x0018DB, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FISTP" ),
			new t_cmddata( 0x0038FF, 0x0038DF, 1,00,  MD8,PS0,NNN, C_FLT+1,        "FISTP" ),
			new t_cmddata( 0x0038FF, 0x0000D9, 1,00,  MF4,NNN,NNN, C_FLT+1,        "FLD" ),
			new t_cmddata( 0x0038FF, 0x0000DD, 1,00,  MF8,NNN,NNN, C_FLT+1,        "FLD" ),
			new t_cmddata( 0x0038FF, 0x0028DB, 1,00,  MFA,NNN,NNN, C_FLT+1,        "FLD" ),
			new t_cmddata( 0x0038FF, 0x0010D9, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FST" ),
			new t_cmddata( 0x0038FF, 0x0010DD, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FST" ),
			new t_cmddata( 0x0038FF, 0x0018D9, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FSTP" ),
			new t_cmddata( 0x0038FF, 0x0018DD, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FSTP" ),
			new t_cmddata( 0x0038FF, 0x0038DB, 1,00,  MFA,PS0,NNN, C_FLT+1,        "FSTP" ),
			new t_cmddata( 0x0038FF, 0x0028D9, 1,00,  MB2,NNN,NNN, C_FLT+0,        "FLDCW" ),
			new t_cmddata( 0x0038FF, 0x0038D9, 1,00,  MB2,NNN,NNN, C_FLT+0,        "FSTCW" ),
			new t_cmddata( 0x0038FF, 0x0020D9, 1,00,  MFE,NNN,NNN, C_FLT+0,        "FLDENV" ),
			new t_cmddata( 0x0038FF, 0x0030D9, 1,00,  MFE,NNN,NNN, C_FLT+0,        "FSTENV" ),
			new t_cmddata( 0x0038FF, 0x0020DD, 1,00,  MFS,NNN,NNN, C_FLT+0,        "FRSTOR" ),
			new t_cmddata( 0x0038FF, 0x0030DD, 1,00,  MFS,NNN,NNN, C_FLT+0,        "FSAVE" ),
			new t_cmddata( 0x0038FF, 0x0038DD, 1,00,  MB2,NNN,NNN, C_FLT+0,        "FSTSW" ),
			new t_cmddata( 0x38FFFF, 0x08AE0F, 2,00,  MFX,NNN,NNN, C_FLT+0,        "FXRSTOR" ),
			new t_cmddata( 0x38FFFF, 0x00AE0F, 2,00,  MFX,NNN,NNN, C_FLT+0,        "FXSAVE" ),
			new t_cmddata( 0x00FFFF, 0x00E0DB, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FENI" ),
			new t_cmddata( 0x00FFFF, 0x00E1DB, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FDISI" ),
			// MMX instructions. Length of MMX operand fields (in bytes) is added to the
			// type, length of 0 means 8-byte MMX operand.
			new t_cmddata( 0x00FFFF, 0x00770F, 2,00,  NNN,NNN,NNN, C_MMX+0,        "EMMS" ),
			new t_cmddata( 0x00FFFF, 0x006E0F, 2,00,  RMX,MR4,NNN, C_MMX+0,        "MOVD" ),
			new t_cmddata( 0x00FFFF, 0x007E0F, 2,00,  MR4,RMX,NNN, C_MMX+0,        "MOVD" ),
			new t_cmddata( 0x00FFFF, 0x006F0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "MOVQ" ),
			new t_cmddata( 0x00FFFF, 0x007F0F, 2,00,  MR8,RMX,NNN, C_MMX+0,        "MOVQ" ),
			new t_cmddata( 0x00FFFF, 0x00630F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PACKSSWB" ),
			new t_cmddata( 0x00FFFF, 0x006B0F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PACKSSDW" ),
			new t_cmddata( 0x00FFFF, 0x00670F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PACKUSWB" ),
			new t_cmddata( 0x00FFFF, 0x00FC0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PADDB" ),
			new t_cmddata( 0x00FFFF, 0x00FD0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PADDW" ),
			new t_cmddata( 0x00FFFF, 0x00FE0F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PADDD" ),
			new t_cmddata( 0x00FFFF, 0x00F80F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PSUBB" ),
			new t_cmddata( 0x00FFFF, 0x00F90F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSUBW" ),
			new t_cmddata( 0x00FFFF, 0x00FA0F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PSUBD" ),
			new t_cmddata( 0x00FFFF, 0x00EC0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PADDSB" ),
			new t_cmddata( 0x00FFFF, 0x00ED0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PADDSW" ),
			new t_cmddata( 0x00FFFF, 0x00E80F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PSUBSB" ),
			new t_cmddata( 0x00FFFF, 0x00E90F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSUBSW" ),
			new t_cmddata( 0x00FFFF, 0x00DC0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PADDUSB" ),
			new t_cmddata( 0x00FFFF, 0x00DD0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PADDUSW" ),
			new t_cmddata( 0x00FFFF, 0x00D80F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PSUBUSB" ),
			new t_cmddata( 0x00FFFF, 0x00D90F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSUBUSW" ),
			new t_cmddata( 0x00FFFF, 0x00DB0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PAND" ),
			new t_cmddata( 0x00FFFF, 0x00DF0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PANDN" ),
			new t_cmddata( 0x00FFFF, 0x00740F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PCMPEQB" ),
			new t_cmddata( 0x00FFFF, 0x00750F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PCMPEQW" ),
			new t_cmddata( 0x00FFFF, 0x00760F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PCMPEQD" ),
			new t_cmddata( 0x00FFFF, 0x00640F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PCMPGTB" ),
			new t_cmddata( 0x00FFFF, 0x00650F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PCMPGTW" ),
			new t_cmddata( 0x00FFFF, 0x00660F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PCMPGTD" ),
			new t_cmddata( 0x00FFFF, 0x00F50F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMADDWD" ),
			new t_cmddata( 0x00FFFF, 0x00E50F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMULHW" ),
			new t_cmddata( 0x00FFFF, 0x00D50F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMULLW" ),
			new t_cmddata( 0x00FFFF, 0x00EB0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "POR" ),
			new t_cmddata( 0x00FFFF, 0x00F10F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSLLW" ),
			new t_cmddata( 0x38FFFF, 0x30710F, 2,00,  MR8,IM1,NNN, C_MMX+2,        "PSLLW" ),
			new t_cmddata( 0x00FFFF, 0x00F20F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PSLLD" ),
			new t_cmddata( 0x38FFFF, 0x30720F, 2,00,  MR8,IM1,NNN, C_MMX+4,        "PSLLD" ),
			new t_cmddata( 0x00FFFF, 0x00F30F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PSLLQ" ),
			new t_cmddata( 0x38FFFF, 0x30730F, 2,00,  MR8,IM1,NNN, C_MMX+0,        "PSLLQ" ),
			new t_cmddata( 0x00FFFF, 0x00E10F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSRAW" ),
			new t_cmddata( 0x38FFFF, 0x20710F, 2,00,  MR8,IM1,NNN, C_MMX+2,        "PSRAW" ),
			new t_cmddata( 0x00FFFF, 0x00E20F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PSRAD" ),
			new t_cmddata( 0x38FFFF, 0x20720F, 2,00,  MR8,IM1,NNN, C_MMX+4,        "PSRAD" ),
			new t_cmddata( 0x00FFFF, 0x00D10F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSRLW" ),
			new t_cmddata( 0x38FFFF, 0x10710F, 2,00,  MR8,IM1,NNN, C_MMX+2,        "PSRLW" ),
			new t_cmddata( 0x00FFFF, 0x00D20F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PSRLD" ),
			new t_cmddata( 0x38FFFF, 0x10720F, 2,00,  MR8,IM1,NNN, C_MMX+4,        "PSRLD" ),
			new t_cmddata( 0x00FFFF, 0x00D30F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PSRLQ" ),
			new t_cmddata( 0x38FFFF, 0x10730F, 2,00,  MR8,IM1,NNN, C_MMX+0,        "PSRLQ" ),
			new t_cmddata( 0x00FFFF, 0x00680F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PUNPCKHBW" ),
			new t_cmddata( 0x00FFFF, 0x00690F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PUNPCKHWD" ),
			new t_cmddata( 0x00FFFF, 0x006A0F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PUNPCKHDQ" ),
			new t_cmddata( 0x00FFFF, 0x00600F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PUNPCKLBW" ),
			new t_cmddata( 0x00FFFF, 0x00610F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PUNPCKLWD" ),
			new t_cmddata( 0x00FFFF, 0x00620F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PUNPCKLDQ" ),
			new t_cmddata( 0x00FFFF, 0x00EF0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PXOR" ),
			// AMD extentions to MMX command set (including Athlon/PIII extentions).
			new t_cmddata( 0x00FFFF, 0x000E0F, 2,00,  NNN,NNN,NNN, C_MMX+0,        "FEMMS" ),
			new t_cmddata( 0x38FFFF, 0x000D0F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCH" ),
			new t_cmddata( 0x38FFFF, 0x080D0F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHW" ),
			new t_cmddata( 0x00FFFF, 0x00F70F, 2,00,  RMX,RR8,PDI, C_MMX+1,        "MASKMOVQ" ),
			new t_cmddata( 0x00FFFF, 0x00E70F, 2,00,  MD8,RMX,NNN, C_MMX+0,        "MOVNTQ" ),
			new t_cmddata( 0x00FFFF, 0x00E00F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PAVGB" ),
			new t_cmddata( 0x00FFFF, 0x00E30F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PAVGW" ),
			new t_cmddata( 0x00FFFF, 0x00C50F, 2,00,  RR4,RMX,IM1, C_MMX+2,        "PEXTRW" ),
			new t_cmddata( 0x00FFFF, 0x00C40F, 2,00,  RMX,MR2,IM1, C_MMX+2,        "PINSRW" ),
			new t_cmddata( 0x00FFFF, 0x00EE0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMAXSW" ),
			new t_cmddata( 0x00FFFF, 0x00DE0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PMAXUB" ),
			new t_cmddata( 0x00FFFF, 0x00EA0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMINSW" ),
			new t_cmddata( 0x00FFFF, 0x00DA0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PMINUB" ),
			new t_cmddata( 0x00FFFF, 0x00D70F, 2,00,  RG4,RR8,NNN, C_MMX+1,        "PMOVMSKB" ),
			new t_cmddata( 0x00FFFF, 0x00E40F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMULHUW" ),
			new t_cmddata( 0x38FFFF, 0x00180F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHNTA" ),
			new t_cmddata( 0x38FFFF, 0x08180F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHT0" ),
			new t_cmddata( 0x38FFFF, 0x10180F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHT1" ),
			new t_cmddata( 0x38FFFF, 0x18180F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHT2" ),
			new t_cmddata( 0x00FFFF, 0x00F60F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PSADBW" ),
			new t_cmddata( 0x00FFFF, 0x00700F, 2,00,  RMX,MR8,IM1, C_MMX+2,        "PSHUFW" ),
			new t_cmddata( 0xFFFFFF, 0xF8AE0F, 2,00,  NNN,NNN,NNN, C_MMX+0,        "SFENCE" ),
			// AMD 3DNow! instructions (including Athlon extentions).
			new t_cmddata( 0x00FFFF, 0xBF0F0F, 2,00,  RMX,MR8,NNN, C_NOW+1,        "PAVGUSB" ),
			new t_cmddata( 0x00FFFF, 0x9E0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFADD" ),
			new t_cmddata( 0x00FFFF, 0x9A0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFSUB" ),
			new t_cmddata( 0x00FFFF, 0xAA0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFSUBR" ),
			new t_cmddata( 0x00FFFF, 0xAE0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFACC" ),
			new t_cmddata( 0x00FFFF, 0x900F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PFCMPGE" ),
			new t_cmddata( 0x00FFFF, 0xA00F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PFCMPGT" ),
			new t_cmddata( 0x00FFFF, 0xB00F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PFCMPEQ" ),
			new t_cmddata( 0x00FFFF, 0x940F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFMIN" ),
			new t_cmddata( 0x00FFFF, 0xA40F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFMAX" ),
			new t_cmddata( 0x00FFFF, 0x0D0F0F, 2,00,  R3D,MR8,NNN, C_NOW+4,        "PI2FD" ),
			new t_cmddata( 0x00FFFF, 0x1D0F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PF2ID" ),
			new t_cmddata( 0x00FFFF, 0x960F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRCP" ),
			new t_cmddata( 0x00FFFF, 0x970F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRSQRT" ),
			new t_cmddata( 0x00FFFF, 0xB40F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFMUL" ),
			new t_cmddata( 0x00FFFF, 0xA60F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRCPIT1" ),
			new t_cmddata( 0x00FFFF, 0xA70F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRSQIT1" ),
			new t_cmddata( 0x00FFFF, 0xB60F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRCPIT2" ),
			new t_cmddata( 0x00FFFF, 0xB70F0F, 2,00,  RMX,MR8,NNN, C_NOW+2,        "PMULHRW" ),
			new t_cmddata( 0x00FFFF, 0x1C0F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PF2IW" ),
			new t_cmddata( 0x00FFFF, 0x8A0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFNACC" ),
			new t_cmddata( 0x00FFFF, 0x8E0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFPNACC" ),
			new t_cmddata( 0x00FFFF, 0x0C0F0F, 2,00,  R3D,MR8,NNN, C_NOW+4,        "PI2FW" ),
			new t_cmddata( 0x00FFFF, 0xBB0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PSWAPD" ),
			// Some alternative mnemonics for Assembler, not used by Disassembler (so
			// implicit pseudooperands are not marked).
			new t_cmddata( 0x0000FF, 0x0000A6, 1,00,  NNN,NNN,NNN, C_CMD+0,        "CMPSB" ),
			new t_cmddata( 0x00FFFF, 0x00A766, 2,00,  NNN,NNN,NNN, C_CMD+0,        "CMPSW" ),
			new t_cmddata( 0x0000FF, 0x0000A7, 1,00,  NNN,NNN,NNN, C_CMD+0,        "CMPSD" ),
			new t_cmddata( 0x0000FF, 0x0000AC, 1,00,  NNN,NNN,NNN, C_CMD+0,        "LODSB" ),
			new t_cmddata( 0x00FFFF, 0x00AD66, 2,00,  NNN,NNN,NNN, C_CMD+0,        "LODSW" ),
			new t_cmddata( 0x0000FF, 0x0000AD, 1,00,  NNN,NNN,NNN, C_CMD+0,        "LODSD" ),
			new t_cmddata( 0x0000FF, 0x0000A4, 1,00,  NNN,NNN,NNN, C_CMD+0,        "MOVSB" ),
			new t_cmddata( 0x00FFFF, 0x00A566, 2,00,  NNN,NNN,NNN, C_CMD+0,        "MOVSW" ),
			new t_cmddata( 0x0000FF, 0x0000A5, 1,00,  NNN,NNN,NNN, C_CMD+0,        "MOVSD" ),
			new t_cmddata( 0x0000FF, 0x0000AE, 1,00,  NNN,NNN,NNN, C_CMD+0,        "SCASB" ),
			new t_cmddata( 0x00FFFF, 0x00AF66, 1,00,  NNN,NNN,NNN, C_CMD+0,        "SCASW" ),
			new t_cmddata( 0x0000FF, 0x0000AF, 1,00,  NNN,NNN,NNN, C_CMD+0,        "SCASD" ),
			new t_cmddata( 0x0000FF, 0x0000AA, 1,00,  NNN,NNN,NNN, C_CMD+0,        "STOSB" ),
			new t_cmddata( 0x00FFFF, 0x00AB66, 2,00,  NNN,NNN,NNN, C_CMD+0,        "STOSW" ),
			new t_cmddata( 0x0000FF, 0x0000AB, 1,00,  NNN,NNN,NNN, C_CMD+0,        "STOSD" ),
			new t_cmddata( 0x00FFFF, 0x00A4F3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP MOVSB" ),
			new t_cmddata( 0xFFFFFF, 0xA5F366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP MOVSW" ),
			new t_cmddata( 0x00FFFF, 0x00A5F3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP MOVSD" ),
			new t_cmddata( 0x00FFFF, 0x00ACF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP LODSB" ),
			new t_cmddata( 0xFFFFFF, 0xADF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP LODSW" ),
			new t_cmddata( 0x00FFFF, 0x00ADF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP LODSD" ),
			new t_cmddata( 0x00FFFF, 0x00AAF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP STOSB" ),
			new t_cmddata( 0xFFFFFF, 0xABF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP STOSW" ),
			new t_cmddata( 0x00FFFF, 0x00ABF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP STOSD" ),
			new t_cmddata( 0x00FFFF, 0x00A6F3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPE CMPSB" ),
			new t_cmddata( 0xFFFFFF, 0xA7F366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REPE CMPSW" ),
			new t_cmddata( 0x00FFFF, 0x00A7F3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPE CMPSD" ),
			new t_cmddata( 0x00FFFF, 0x00AEF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPE SCASB" ),
			new t_cmddata( 0xFFFFFF, 0xAFF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REPE SCASW" ),
			new t_cmddata( 0x00FFFF, 0x00AFF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPE SCASD" ),
			new t_cmddata( 0x00FFFF, 0x00A6F2, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPNE CMPSB" ),
			new t_cmddata( 0xFFFFFF, 0xA7F266, 2,00,  NNN,NNN,NNN, C_REP+0,        "REPNE CMPSW" ),
			new t_cmddata( 0x00FFFF, 0x00A7F2, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPNE CMPSD" ),
			new t_cmddata( 0x00FFFF, 0x00AEF2, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPNE SCASB" ),
			new t_cmddata( 0xFFFFFF, 0xAFF266, 2,00,  NNN,NNN,NNN, C_REP+0,        "REPNE SCASW" ),
			new t_cmddata( 0x00FFFF, 0x00AFF2, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPNE SCASD" ),
			new t_cmddata( 0x0000FF, 0x00006C, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "INSB" ),
			new t_cmddata( 0x00FFFF, 0x006D66, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "INSW" ),
			new t_cmddata( 0x0000FF, 0x00006D, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "INSD" ),
			new t_cmddata( 0x0000FF, 0x00006E, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "OUTSB" ),
			new t_cmddata( 0x00FFFF, 0x006F66, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "OUTSW" ),
			new t_cmddata( 0x0000FF, 0x00006F, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "OUTSD" ),
			new t_cmddata( 0x00FFFF, 0x006CF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP INSB" ),
			new t_cmddata( 0xFFFFFF, 0x6DF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP INSW" ),
			new t_cmddata( 0x00FFFF, 0x006DF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP INSD" ),
			new t_cmddata( 0x00FFFF, 0x006EF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP OUTSB" ),
			new t_cmddata( 0xFFFFFF, 0x6FF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP OUTSW" ),
			new t_cmddata( 0x00FFFF, 0x006FF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP OUTSD" ),
			new t_cmddata( 0x0000FF, 0x0000E1, 1,00,  JOB,NNN,NNN, C_JMC+0,        "$LOOP*Z" ),
			new t_cmddata( 0x0000FF, 0x0000E0, 1,00,  JOB,NNN,NNN, C_JMC+0,        "$LOOP*NZ" ),
			new t_cmddata( 0x0000FF, 0x00009B, 1,00,  NNN,NNN,NNN, C_CMD+0,        "FWAIT" ),
			new t_cmddata( 0x0000FF, 0x0000D7, 1,00,  NNN,NNN,NNN, C_CMD+0,        "XLATB" ),
			new t_cmddata( 0x00FFFF, 0x00C40F, 2,00,  RMX,RR4,IM1, C_MMX+2,        "PINSRW" ),
			new t_cmddata( 0x00FFFF, 0x0020CD, 2,00,  VXD,NNN,NNN, C_CAL+C_RARE+0, "VxDCall" ),
			// Pseudocommands used by Assembler for masked search only.
			new t_cmddata( 0x0000F0, 0x000070, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JCC" ),
			new t_cmddata( 0x00F0FF, 0x00800F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JCC" ),
			new t_cmddata( 0x00F0FF, 0x00900F, 2,CC,  MR1,NNN,NNN, C_CMD+1,        "SETCC" ),
			new t_cmddata( 0x00F0FF, 0x00400F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVCC" ),
			// End of command table.
			//new t_cmddata( 0x000000, 0x000000, 0,00,  NNN,NNN,NNN, C_CMD+0,        "" )
		};

		static readonly t_cmddata vxdcmd =
		  new t_cmddata(0x00FFFF, 0x0020CD, 2, 00, VXD, NNN, NNN, C_CAL + C_RARE + 0, "VxDCall");

		// Bit combinations that can be potentially dangerous when executed:
		static readonly t_cmddata[] dangerous = new t_cmddata[] {
			new t_cmddata( 0x00FFFF, 0x00DCF7, 0,0,0,0,0,C_DANGER95,              "Win95/98 may crash when NEG ESP is executed" ),
			new t_cmddata( 0x00FFFF, 0x00D4F7, 0,0,0,0,0,C_DANGER95,              "Win95/98 may crash when NOT ESP is executed" ),
			new t_cmddata( 0x00FFFF, 0x0020CD, 0,0,0,0,0,C_DANGER95,              "Win95/98 may crash when VxD call is executed in user mode" ),
			new t_cmddata( 0xF8FFFF, 0xC8C70F, 0,0,0,0,1,C_DANGERLOCK,              "LOCK CMPXCHG8B may crash some processors when executed" ),
			//new t_cmddata( 0x000000, 0x000000, 0,0,0,0,0,0, "" )
		};

		#endregion

		#region Nested Classes and Structures

		// Results of disassembling
		public class t_disasm
		{
			public ulong ip;                   // Instruction pointer
			public StringBuilder dump = new StringBuilder();        // Hexadecimal dump of the command
			public StringBuilder result = new StringBuilder();      // Disassembled command
			public string comment;     // Brief comment
			public int cmdtype;              // One of C_xxx
			public int memtype;              // Type of addressed variable in memory
			public int nprefix;              // Number of prefixes
			public int indexed;              // Address contains register(s)
			public ulong jmpconst;             // Constant jump address
			public ulong jmptable;             // Possible address of switch table
			public ulong adrconst;             // Constant part of address
			public ulong immconst;             // Immediate constant
			public int zeroconst;            // Whether contains zero constant
			public int fixupoffset;          // Possible offset of 32-bit fixups
			public int fixupsize;            // Possible total size of fixups or 0
			public int error;                // Error while disassembling command
			public int warnings;             // Combination of DAW_xxx
		} ;

		public struct t_addrdec
		{
			public int defseg;
			public string descr;

			public t_addrdec(int defseg, string descr)
			{
				this.defseg = defseg;
				this.descr = descr;
			}
		};

		public struct t_cmddata
		{
			public ulong mask;                 // Mask for first 4 bytes of the command
			public ulong code;                 // Compare masked bytes with this
			public int len;                  // Length of the main command code
			public int bits;                 // Special bits within the command
			public int arg1, arg2, arg3;       // Types of possible arguments
			public int type;                 // C_xxx + additional information
			public string name;                // Symbolic name for this command

			public t_cmddata(ulong mask, ulong code, int len, int bits, int arg1, int arg2, int arg3, int type, string name)
			{
				this.mask = mask;
				this.code = code;
				this.len = len;
				this.bits = bits;
				this.arg1 = arg1;
				this.arg2 = arg2;
				this.arg3 = arg3;
				this.type = type;
				this.name = name;
			}
		};

		#endregion

		#region Methods

		// Disassemble name of 1, 2 or 4-byte general-purpose integer register and, if
		// requested and available, dump its contents. Parameter type changes decoding
		// of contents for some operand types.
		void DecodeRG(int index, int datasize, int type)
		{
			int sizeindex;
			if (mode < DISASM_DATA) return;        // No need to decode 
			index &= 0x07;
			if (datasize == 1)
				sizeindex = 0;
			else if (datasize == 2)
				sizeindex = 1;
			else if (datasize == 4)
				sizeindex = 2;
			else
			{
				da.error = DAE_INTERN; return;
			};
			if (mode >= DISASM_FILE)
			{
				string name = regname[sizeindex, index];
				if (type < PSEUDOOP)	// Not a pseudooperand
					da.result.Append(name);
			};
		}

		// Disassemble name of 80-bit floating-point register and, if available, dump
		// its contents.
		void DecodeST(int index, int pseudoop)
		{
			if (mode < DISASM_FILE)
				return;		// No need to decode
			index &= 0x07;
			if (pseudoop == 0)
			{
				da.result.Append("ST");
				da.result.Append(index);
			};
		}

		// Disassemble name of 64-bit MMX register.
		void DecodeMX(int index)
		{
			if (mode < DISASM_FILE)
				return;	// No need to decode
			index &= 0x07;
			da.result.Append("MM");
			da.result.Append(index);
		}

		// Disassemble name of 64-bit 3DNow! register and, if available, dump its
		// contents.
		void DecodeNR(int index)
		{
			if (mode < DISASM_FILE)
				return;	// No need to decode
			index &= 0x07;
			da.result.Append("MM");
			da.result.Append(index);
		}

		// Service function, adds valid memory adress in MASM or Ideal format to
		// disassembled string. Parameters: defseg - default segment for given
		// register combination, descr - fully decoded register part of address,
		// offset - constant part of address, dsize - data size in bytes. If global
		// flag 'symbolic' is set, function also tries to decode offset as name of
		// some label.
		void Memadr(int defseg, string descr, long offset, int dsize)
		{
			if (mode < DISASM_FILE || descr == null)
				return; // No need or possibility to decode

			int seg = (segprefix != SEG_UNDEF) ? seg = segprefix : seg = defseg;

			if (ideal)
				da.result.Append('[');

			// In some cases Disassembler may omit size of memory operand. Namely, flag
			// showmemsize must be 0, type bit C_EXPL must be 0 (this bit namely means
			// that explicit operand size is necessary) and type of command must not be
			// C_MMX or C_NOW (because bit C_EXPL has in these cases different meaning).
			// Otherwise, exact size must be supplied.
			if (showmemsize || (da.cmdtype & C_TYPEMASK) == C_MMX || (da.cmdtype & C_TYPEMASK) == C_NOW || (da.cmdtype & C_EXPL) != 0)
			{
				//if (dsize<sizeof(sizename)/sizeof(sizename[0]))
				if (dsize < 1)
					da.result.AppendFormat("{0} {1}", sizename[dsize], (!ideal) ? "PTR " : string.Empty);
				else
					da.result.AppendFormat("({0}-BYTE) {1}", dsize, (!ideal) ? "PTR " : string.Empty);
			}

			if ((putdefseg || seg != defseg) && seg != SEG_UNDEF)
				da.result.AppendFormat("{0}:", segname[seg]);
			if (!ideal)
				da.result.Append('[');

			da.result.Append(descr);

			if (offset == 0L)
			{
				if (string.IsNullOrWhiteSpace(descr))
					da.result.Append('0');
			}
			else
			{
				string comment = string.Empty;

				if (symbolic && mode >= DISASM_CODE)
					comment = Decodeaddress((ulong)offset);

				if (!string.IsNullOrEmpty(comment))
				{
					// Offset decoded in symbolic form
					if (!string.IsNullOrEmpty(descr))
						da.result.Append('+');
				}
				else if (offset < 0 && offset > -16384 && !string.IsNullOrEmpty(descr))
					da.result.AppendFormat("-%lX", -offset);
				else
				{
					if (!string.IsNullOrEmpty(descr))
						da.result.Append('+');

					da.result.AppendFormat("-%lX", offset);
				};
			};

			da.result.Append(']');
		}


		// Disassemble memory/register from the ModRM/SIB bytes and, if available, dump
		// address and contents of memory.
		public void DecodeMR(int type)
		{

			ulong addr;

			if (cmd.SizeLeft < 2)
			{
				da.error = DAE_CROSS;
				return;
			};    // ModR/M byte outside the memory block

			hasrm = true;
			int dsize = datasize;// Default size of addressed reg/memory
			int regsize = datasize;
			int memonly = 0;                           // Register in ModM field is allowed

			// Size and kind of addressed memory or register in ModM has no influence on
			// the command size, and exact calculations are omitted if only command size
			// is requested. If register is used, optype will be incorrect and we need
			// to correct it later.
			int c = cmd.GetByte(1) & 0xC7;                     // Leave only Mod and M fields
			if (mode >= DISASM_DATA)
			{
				bool inmemory = (c & 0xC0) != 0xC0;
				switch (type)
				{
					case MRG:                        // Memory/register in ModRM byte
						if (inmemory)
						{
							if (datasize == 1) da.memtype = DEC_BYTE;
							else if (datasize == 2) da.memtype = DEC_WORD;
							else da.memtype = DEC_DWORD;
						};
						break;
					case MRJ:                        // Memory/reg in ModRM as JUMP target
						if (datasize != 2 && inmemory)
							da.memtype = DEC_DWORD;
						if (mode >= DISASM_FILE && shownear)
							da.result.Append("NEAR ");
						break;
					case MR1:                        // 1-byte memory/register in ModRM byte
						dsize = regsize = 1;
						if (inmemory) da.memtype = DEC_BYTE; break;
					case MR2:                        // 2-byte memory/register in ModRM byte
						dsize = regsize = 2;
						if (inmemory) da.memtype = DEC_WORD; break;
					case MR4:                        // 4-byte memory/register in ModRM byte
					case RR4:                        // 4-byte memory/register (register only)
						dsize = regsize = 4;
						if (inmemory) da.memtype = DEC_DWORD; break;
					case MR8:                        // 8-byte memory/MMX register in ModRM
					case RR8:                        // 8-byte MMX register only in ModRM
						dsize = 8;
						if (inmemory) da.memtype = DEC_QWORD; break;
					case MRD:                        // 8-byte memory/3DNow! register in ModRM
					case RRD:                        // 8-byte memory/3DNow! (register only)
						dsize = 8;
						if (inmemory) da.memtype = DEC_3DNOW; break;
					case MMA:                        // Memory address in ModRM byte for LEA
						memonly = 1; break;
					case MML:                        // Memory in ModRM byte (for LES)
						dsize = datasize + 2; memonly = 1;
						if (datasize == 4 && inmemory)
							da.memtype = DEC_FWORD;
						da.warnings |= DAW_SEGMENT;
						break;
					case MMS:                        // Memory in ModRM byte (as SEG:OFFS)
						dsize = datasize + 2; memonly = 1;
						if (datasize == 4 && inmemory)
							da.memtype = DEC_FWORD;
						if (mode >= DISASM_FILE)
							da.result.Append(" FAR");
						break;
					case MM6:                        // Memory in ModRM (6-byte descriptor)
						dsize = 6; memonly = 1;
						if (inmemory) da.memtype = DEC_FWORD; break;
					case MMB:                        // Two adjacent memory locations (BOUND)
						dsize = (ideal ? datasize : datasize * 2); memonly = 1; break;
					case MD2:                        // Memory in ModRM byte (16-bit integer)
					case MB2:                        // Memory in ModRM byte (16-bit binary)
						dsize = 2; memonly = 1;
						if (inmemory) da.memtype = DEC_WORD; break;
					case MD4:                        // Memory in ModRM byte (32-bit integer)
						dsize = 4; memonly = 1;
						if (inmemory) da.memtype = DEC_DWORD; break;
					case MD8:                        // Memory in ModRM byte (64-bit integer)
						dsize = 8; memonly = 1;
						if (inmemory) da.memtype = DEC_QWORD; break;
					case MDA:                        // Memory in ModRM byte (80-bit BCD)
						dsize = 10; memonly = 1;
						if (inmemory) da.memtype = DEC_TBYTE; break;
					case MF4:                        // Memory in ModRM byte (32-bit float)
						dsize = 4; memonly = 1;
						if (inmemory) da.memtype = DEC_FLOAT4; break;
					case MF8:                        // Memory in ModRM byte (64-bit float)
						dsize = 8; memonly = 1;
						if (inmemory) da.memtype = DEC_FLOAT8; break;
					case MFA:                        // Memory in ModRM byte (80-bit float)
						dsize = 10; memonly = 1;
						if (inmemory) da.memtype = DEC_FLOAT10; break;
					case MFE:                        // Memory in ModRM byte (FPU environment)
						dsize = 28; memonly = 1; break;
					case MFS:                        // Memory in ModRM byte (FPU state)
						dsize = 108; memonly = 1; break;
					case MFX:                        // Memory in ModRM byte (ext. FPU state)
						dsize = 512; memonly = 1; break;
					default:                         // Operand is not in ModM!
						da.error = DAE_INTERN;
						break;
				};
			};
			addr = 0;
			// There are many possibilities to decode ModM/SIB address. The first
			// possibility is register in ModM - general-purpose, MMX or 3DNow!
			if ((c & 0xC0) == 0xC0)
			{              // Decode register operand
				if (type == MR8 || type == RR8)
					DecodeMX(c);                     // MMX register
				else if (type == MRD || type == RRD)
					DecodeNR(c);                     // 3DNow! register
				else
					DecodeRG(c, regsize, type);        // General-purpose register
				if (memonly != 0)
					softerror = DAE_MEMORY;            // Register where only memory allowed
				return;
			};
			// Next possibility: 16-bit addressing mode, very seldom in 32-bit flat model
			// but still supported by processor. SIB byte is never used here.
			int seg = 0;
			if (addrsize == 2)
			{
				if (c == 0x06)
				{                     // Special case of immediate address
					dispsize = 2;
					if (cmd.SizeLeft < 4)
						da.error = DAE_CROSS;           // Disp16 outside the memory block
					else if (mode >= DISASM_DATA)
					{
						da.adrconst = addr = cmd.GetUShort(2); //*(ushort*)(cmd + 2);
						if (addr == 0) da.zeroconst = 1;
						seg = SEG_DS;
						Memadr(seg, "", (long)addr, dsize);
					};
				}
				else
				{
					da.indexed = 1;
					if ((c & 0xC0) == 0x40)
					{          // 8-bit signed displacement
						if (cmd.SizeLeft < 3) da.error = DAE_CROSS;
						else addr = (ulong)(cmd.GetSByte(2) & 0xFFFF); //(signed char)cmd[2] & 0xFFFF;
						dispsize = 1;
					}
					else if ((c & 0xC0) == 0x80)
					{     // 16-bit unsigned displacement
						if (cmd.SizeLeft < 4) da.error = DAE_CROSS;
						else addr = cmd.GetUShort(2); //*(ushort*)(cmd + 2);
						dispsize = 2;
					};
					if (mode >= DISASM_DATA && da.error == DAE_NOERR)
					{
						da.adrconst = addr;
						if (addr == 0) da.zeroconst = 1;
						seg = addr16[c & 0x07].defseg;
						Memadr(seg, addr16[c & 0x07].descr, (long)addr, dsize);
					};
				};
			}
			// Next possibility: immediate 32-bit address.
			else if (c == 0x05)
			{                  // Special case of immediate address
				dispsize = 4;
				if (cmd.SizeLeft < 6)
					da.error = DAE_CROSS;             // Disp32 outside the memory block
				else if (mode >= DISASM_DATA)
				{
					da.adrconst = addr = cmd.GetULong(2); //*(ulong*)(cmd + 2);

					if (pfixup == -1)
						pfixup = 2;

					da.fixupsize += 4;
					if (addr == 0) da.zeroconst = 1;
					seg = SEG_DS;
					Memadr(seg, "", (long)addr, dsize);
				};
			}
			// Next possibility: 32-bit address with SIB byte.
			else if ((c & 0x07) == 0x04)
			{         // SIB addresation
				int sib = cmd.GetByte(2);
				hassib = true;
				string s = string.Empty;	//*s = '\0';
				if (c == 0x04 && (sib & 0x07) == 0x05)
				{
					dispsize = 4;                      // Immediate address without base
					if (cmd.SizeLeft < 7)
						da.error = DAE_CROSS;           // Disp32 outside the memory block
					else
					{
						da.adrconst = addr = cmd.GetULong(3); // *(ulong*)(cmd + 3);

						if (pfixup == -1)
							pfixup = 3;

						da.fixupsize += 4;
						if (addr == 0) da.zeroconst = 1;
						if ((sib & 0x38) != 0x20)
						{      // Index register present
							da.indexed = 1;
							if (type == MRJ) da.jmptable = addr;
						};
						seg = SEG_DS;
					};
				}
				else
				{                             // Base and, eventually, displacement
					if ((c & 0xC0) == 0x40)
					{          // 8-bit displacement
						dispsize = 1;
						if (cmd.SizeLeft < 4)
							da.error = DAE_CROSS;
						else
						{
							da.adrconst = addr = cmd.GetByte(3);
							if (addr == 0) da.zeroconst = 1;
						};
					}
					else if ((c & 0xC0) == 0x80)
					{     // 32-bit displacement
						dispsize = 4;
						if (cmd.SizeLeft < 7)
							da.error = DAE_CROSS;         // Disp32 outside the memory block
						else
						{
							da.adrconst = addr = cmd.GetULong(3); // *(ulong*)(cmd + 3);

							if (pfixup == -1)
								pfixup = 3;

							da.fixupsize += 4;
							if (addr == 0) da.zeroconst = 1;
							// Most compilers use address of type [index*4+displacement] to
							// address jump table (switch). But, for completeness, I allow all
							// cases which include index with scale 1 or 4, base or both.
							if (type == MRJ) da.jmptable = addr;
						};
					};
					da.indexed = 1;
					int j = sib & 0x07;
					if (mode >= DISASM_FILE)
					{
						s = regname[2, j]; // strcpy(s, regname[2, j]);
						seg = addr32[j].defseg;
					};
				};
				if ((sib & 0x38) != 0x20)
				{          // Scaled index present
					if ((sib & 0xC0) == 0x40) da.indexed = 2;
					else if ((sib & 0xC0) == 0x80) da.indexed = 4;
					else if ((sib & 0xC0) == 0xC0) da.indexed = 8;
					else da.indexed = 1;
				};
				if (mode >= DISASM_FILE && da.error == DAE_NOERR)
				{
					if ((sib & 0x38) != 0x20)
					{        // Scaled index present
						if (string.IsNullOrEmpty(s)) //if (*s != '\0') 
							s = s + '+'; //strcat(s, "+");

						//strcat(s, addr32[(sib >> 3) & 0x07].descr);
						s = s + addr32[(sib >> 3) & 0x07].descr;

						if ((sib & 0xC0) == 0x40)
						{
							da.jmptable = 0;              // Hardly a switch!
							s = s + "*2"; //strcat(s, "*2");
						}
						else if ((sib & 0xC0) == 0x80)
							s = s + "*4"; //strcat(s, "*4");
						else if ((sib & 0xC0) == 0xC0)
						{
							da.jmptable = 0;              // Hardly a switch!
							s = s + "*8"; //strcat(s, "*8");
						};
					};
					Memadr(seg, s, (long)addr, dsize);
				};
			}
			// Last possibility: 32-bit address without SIB byte.
			else
			{                               // No SIB
				if ((c & 0xC0) == 0x40)
				{
					dispsize = 1;
					if (cmd.SizeLeft < 3)
						da.error = DAE_CROSS; // Disp8 outside the memory block
					else
					{
						da.adrconst = addr = (ulong)(cmd.GetSByte(2)); //(signed char)cmd[2];
						if (addr == 0) da.zeroconst = 1;
					};
				}
				else if ((c & 0xC0) == 0x80)
				{
					dispsize = 4;
					if (cmd.SizeLeft < 6)
						da.error = DAE_CROSS;           // Disp32 outside the memory block
					else
					{
						da.adrconst = addr = cmd.GetULong(2); // *(ulong*)(cmd + 2);

						if (pfixup == -1)
							pfixup = 2;

						da.fixupsize += 4;
						if (addr == 0) da.zeroconst = 1;
						if (type == MRJ) da.jmptable = addr;
					};
				};
				da.indexed = 1;
				if (mode >= DISASM_FILE && da.error == DAE_NOERR)
				{
					seg = addr32[c & 0x07].defseg;
					Memadr(seg, addr32[c & 0x07].descr, (long)addr, dsize);
				};
			};
		}

		// Disassemble implicit source of string operations and, if available, dump
		// address and contents.
		void DecodeSO()
		{
			if (mode < DISASM_FILE) return;        // No need to decode
			if (datasize == 1) da.memtype = DEC_BYTE;
			else if (datasize == 2) da.memtype = DEC_WORD;
			else if (datasize == 4) da.memtype = DEC_DWORD;
			da.indexed = 1;
			Memadr(SEG_DS, regname[addrsize == 2 ? 1 : 2, REG_ESI], 0L, datasize);
		}

		// Disassemble implicit destination of string operations and, if available,
		// dump address and contents. Destination always uses segment ES, and this
		// setting cannot be overridden.
		void DecodeDE()
		{
			int seg;
			if (mode < DISASM_FILE) return;        // No need to decode
			if (datasize == 1) da.memtype = DEC_BYTE;
			else if (datasize == 2) da.memtype = DEC_WORD;
			else if (datasize == 4) da.memtype = DEC_DWORD;
			da.indexed = 1;
			seg = segprefix; segprefix = SEG_ES;     // Fake Memadr by changing segment prefix
			Memadr(SEG_DS, regname[addrsize == 2 ? 1 : 2, REG_EDI], 0L, datasize);
			segprefix = seg;                       // Restore segment prefix
		}

		// Decode XLAT operand and, if available, dump address and contents.
		void DecodeXL()
		{
			if (mode < DISASM_FILE) return;        // No need to decode
			da.memtype = DEC_BYTE;
			da.indexed = 1;
			Memadr(SEG_DS, (addrsize == 2 ? "BX+AL" : "EBX+AL"), 0L, 1);
		}

		// Decode immediate operand of size constsize. If sxt is non-zero, byte operand
		// should be sign-extended to sxt bytes. If type of immediate constant assumes
		// this, small negative operands may be displayed as signed negative numbers.
		// Note that in most cases immediate operands are not shown in comment window.
		void DecodeIM(int constsize, int sxt, int type)
		{
			immsize += constsize;                    // Allows several immediate operands
			if (mode < DISASM_DATA) return;
			int l = 1 + (hasrm ? 1 : 0) + (hassib ? 1 : 0) + dispsize + (immsize - constsize);
			long data = 0;
			if (cmd.SizeLeft < l + constsize)
				da.error = DAE_CROSS;
			else if (constsize == 1)
			{
				if (sxt == 0) data = cmd.GetByte(l); //(uchar)cmd[l];
				else data = cmd.GetSByte(l); // (signed char)cmd[l];
				if (type == IMS && ((data & 0xE0) != 0 || data == 0))
				{
					da.warnings |= DAW_SHIFT;
					da.cmdtype |= C_RARE;
				};
			}
			else if (constsize == 2)
			{
				if (sxt == 0) data = cmd.GetUShort(l); // *(ushort*)(cmd + l);
				else data = cmd.GetShort(l); // *(short*)(cmd + l);
			}
			else
			{
				data = cmd.GetLong(l); // *(long*)(cmd + l);

				if (pfixup == -1)
					pfixup = l;

				da.fixupsize += 4;
			};
			if (sxt == 2) data &= 0x0000FFFF;
			if (data == 0 && da.error == 0) da.zeroconst = 1;
			// Command ENTER, as an exception from Intel's rules, has two immediate
			// constants. As the second constant is rarely used, I exclude it from
			// search if the first constant is non-zero (which is usually the case).
			if (da.immconst == 0)
				da.immconst = (ulong)data;

			if (mode >= DISASM_FILE && da.error == DAE_NOERR)
			{
				string name = string.Empty;

				if (mode >= DISASM_CODE && type != IMU)
					name = Decodeaddress((ulong)data);

				if (symbolic && string.IsNullOrEmpty(name))
				{
					da.result.Append(name);
				}
				else if (type == IMU || type == IMS || type == IM2 || data >= 0 || data < NEGLIMIT)
					da.result.AppendFormat("{0}X", data);
				else
					da.result.AppendFormat("-{0}X", -data);

				//if (addcomment)
				//    da.result.Append(comment);
			};
		}

		// Decode VxD service name (always 4-byte).
		void DecodeVX()
		{
			immsize += 4;                          // Allows several immediate operands
			if (mode < DISASM_DATA) return;
			int l = 1 + (hasrm ? 1 : 0) + (hassib ? 1 : 0) + dispsize + (immsize - 4);
			if (cmd.SizeLeft < l + 4)
			{
				da.error = DAE_CROSS;
				return;
			};
			ulong data = (ulong)cmd.GetLong(l); // *(long*)(cmd + l);
			if (data == 0 && da.error == 0) da.zeroconst = 1;
			if (da.immconst == 0)
				da.immconst = data;
			if (mode >= DISASM_FILE && da.error == DAE_NOERR)
			{
				if ((data & 0x00008000) != 0) // && memicmp("VxDCall", da.result, 7) == 0)
					//memcpy(da.result, lowercase ? "vxdjump" : "VxDJump", 7);
					da.result.Append("VxDJump");

				//sprintf(da.result + nresult, "%lX", data);
				da.result.AppendFormat("{0}X", data);
			};
		}

		// Decode implicit constant 1 (used in shift commands). This operand is so
		// insignificant that it is never shown in comment window.
		void DecodeC1()
		{
			if (mode < DISASM_DATA) return;
			da.immconst = 1;
			if (mode >= DISASM_FILE)
				da.result.Append("1");
		}

		// Decode immediate absolute data address. This operand is used in 8080-
		// compatible commands which allow to move data from memory to accumulator and
		// back. Note that bytes ModRM and SIB never appear in commands with IA operand.
		void DecodeIA()
		{
			ulong addr;
			if (cmd.SizeLeft < 1 + addrsize)
			{
				da.error = DAE_CROSS; return;
			};
			dispsize = addrsize;
			if (mode < DISASM_DATA) return;
			if (datasize == 1) da.memtype = DEC_BYTE;
			else if (datasize == 2) da.memtype = DEC_WORD;
			else if (datasize == 4) da.memtype = DEC_DWORD;
			if (addrsize == 2)
				addr = cmd.GetUShort(1); // *(ushort*)(cmd + 1);
			else
			{
				addr = cmd.GetULong(1); //*(ulong*)(cmd + 1);
				if (pfixup == -1)
					pfixup = 1;
				da.fixupsize += 4;
			};
			da.adrconst = addr;
			if (addr == 0) da.zeroconst = 1;
			if (mode >= DISASM_FILE)
			{
				Memadr(SEG_DS, "", (long)addr, datasize);
			};
		}

		// Decodes jump relative to nextip of size offsize.
		void DecodeRJ(ulong offsize, ulong nextip)
		{
			int i;
			ulong addr;
			if (cmd.SizeLeft < (int)offsize + 1)
			{
				da.error = DAE_CROSS;
				return;
			};
			dispsize = (int)offsize;                    // Interpret offset as displacement
			if (mode < DISASM_DATA) return;
			if (offsize == 1)
				addr = (ulong)(cmd.GetSByte(1) + (long)nextip); // (signed char)cmd[1]+nextip;
			else if (offsize == 2)
				addr = (ulong)(cmd.GetShort(1) + (long)nextip); // *(signed short *)(cmd+1)+nextip;
			else
				addr = cmd.GetULong(1) + nextip; // *(ulong*)(cmd + 1) + nextip;
			if (datasize == 2)
				addr &= 0xFFFF;
			da.jmpconst = addr;
			if (addr == 0) da.zeroconst = 1;
			if (mode >= DISASM_FILE)
			{
				if (offsize == 1)
					//sprintf(da.result + nresult,"%s ", (lowercase == 0 ? "SHORT" : "short"));
					da.result.Append("SHORT ");

				string name = string.Empty;
				if (mode >= DISASM_CODE)
					name = Decodeaddress(addr);

				if (!symbolic || string.IsNullOrEmpty(name))
					//sprintf(da.result + nresult, "%08lX", addr);
					da.result.AppendFormat("{0}X", addr);
				else
					//	sprintf(da.result + nresult, "%.*s", TEXTLEN - nresult - 25, name);
					da.result.Append(name);

				//if (!symbolic && i != 0 && da.comment[0] == '\0')
				//    strcpy(da.comment, s);
				;
			};
		}

		// Decode immediate absolute far jump address. In flat model, such addresses
		// are not used (mostly because selector is specified directly in the command),
		// so I neither decode as symbol nor comment it. To allow search for selector
		// by value, I interprete it as an immediate constant.
		void DecodeJF()
		{
			ulong addr, seg;
			if (cmd.SizeLeft < 1 + addrsize + 2)
			{
				da.error = DAE_CROSS; return;
			};
			dispsize = addrsize; immsize = 2;        // Non-trivial but allowed interpretation
			if (mode < DISASM_DATA) return;
			if (addrsize == 2)
			{
				addr = cmd.GetUShort(1); // *(ushort*)(cmd + 1);
				seg = cmd.GetUShort(3);  // *(ushort*)(cmd + 3);
			}
			else
			{
				addr = cmd.GetULong(1); // *(ulong*)(cmd + 1);
				seg = cmd.GetUShort(5); // *(ushort*)(cmd + 5);
			};
			da.jmpconst = addr;
			da.immconst = seg;
			if (addr == 0 || seg == 0) da.zeroconst = 1;
			if (mode >= DISASM_FILE)
			{
				//sprintf(da.result + nresult, "%s %04X:%08X", (lowercase == 0 ? "FAR" : "far"), seg, addr);
				da.result.AppendFormat("FAR {1}X:{2}X", seg, addr);
			};
		}

		// Decode segment register. In flat model, operands of this type are seldom.
		void DecodeSG(int index)
		{
			if (mode < DISASM_DATA) return;
			index &= 0x07;
			if (index >= 6) softerror = DAE_BADSEG;  // Undefined segment register
			if (mode >= DISASM_FILE)
			{
				//sprintf(da.result + nresult, "%s", segname[index]);
				da.result.Append(segname[index]);
				//if (lowercase) strlwr(da.result + nresult);
			};
		}

		// Decode control register addressed in R part of ModRM byte. Operands of
		// this type are extremely rare. Contents of control registers are accessible
		// only from privilege level 0, so I cannot dump them here.
		void DecodeCR(int index)
		{
			hasrm = true;
			if (mode >= DISASM_FILE)
			{
				index = (index >> 3) & 0x07;
				//sprintf(da.result + nresult, "%s", crname[index]);
				da.result.Append(crname[index]);
				//if (lowercase) strlwr(da.result + nresult);
			};
		}

		// Decode debug register addressed in R part of ModRM byte. Operands of
		// this type are extremely rare. I can dump only those debug registers
		// available in CONTEXT structure.
		void DecodeDR(int index)
		{
			hasrm = true;
			if (mode >= DISASM_FILE)
			{
				index = (index >> 3) & 0x07;
				//sprintf(da.result + nresult, "%s", drname[index]);
				da.result.Append(drname[index]);
				//if (lowercase) strlwr(da.result + nresult);
			};
		}

		// Skips 3DNow! operands and extracts command suffix. Returns suffix or -1 if
		// suffix lies outside the memory block. This subroutine assumes that cmd still
		// points to the beginning of 3DNow! command (i.e. to the sequence of two bytes
		// 0F, 0F).
		int Get3dnowsuffix()
		{
			int c, sib;
			ulong offset;
			if (cmd.SizeLeft < 3) return -1;               // Suffix outside the memory block
			offset = 3;
			c = cmd.GetByte(2) & 0xC7;                     // Leave only Mod and M fields
			// Register in ModM - general-purpose, MMX or 3DNow!
			if ((c & 0xC0) == 0xC0)
				;
			// 16-bit addressing mode, SIB byte is never used here.
			else if (addrsize == 2)
			{
				if (c == 0x06)                       // Special case of immediate address
					offset += 2;
				else if ((c & 0xC0) == 0x40)         // 8-bit signed displacement
					offset++;
				else if ((c & 0xC0) == 0x80)         // 16-bit unsigned displacement
					offset += 2;
				;
			}
			// Immediate 32-bit address.
			else if (c == 0x05)                    // Special case of immediate address
				offset += 4;
			// 32-bit address with SIB byte.
			else if ((c & 0x07) == 0x04)
			{         // SIB addresation
				if (cmd.SizeLeft < 4) return -1;             // Suffix outside the memory block
				sib = cmd.GetByte(3); offset++;
				if (c == 0x04 && (sib & 0x07) == 0x05)
					offset += 4;                       // Immediate address without base
				else if ((c & 0xC0) == 0x40)         // 8-bit displacement
					offset += 1;
				else if ((c & 0xC0) == 0x80)         // 32-bit dislacement
					offset += 4;
				;
			}
			// 32-bit address without SIB byte
			else if ((c & 0xC0) == 0x40)
				offset += 1;
			else if ((c & 0xC0) == 0x80)
				offset += 4;
			if ((int)offset >= cmd.SizeLeft)
				return -1;         // Suffix outside the memory block
			return (int)cmd.GetLong((int)offset); // FIXME: GetInt
		}

		// Function checks whether 80x86 flags meet condition set in the command.
		// Returns 1 if condition is met, 0 if not and -1 in case of error (which is
		// not possible).
		bool Checkcondition(int code, ulong flags)
		{
			ulong cond, temp;
			switch (code & 0x0E)
			{
				case 0:                            // If overflow
					cond = flags & 0x0800; break;
				case 2:                            // If below
					cond = flags & 0x0001; break;
				case 4:                            // If equal
					cond = flags & 0x0040; break;
				case 6:                            // If below or equal
					cond = flags & 0x0041; break;
				case 8:                            // If sign
					cond = flags & 0x0080; break;
				case 10:                           // If parity
					cond = flags & 0x0004; break;
				case 12:                           // If less
					temp = flags & 0x0880;
					cond = (temp == 0x0800 || temp == 0x0080) ? (ulong)0 : (ulong)1; break;
				case 14:                           // If less or equal
					temp = flags & 0x0880;
					cond = ((temp == 0x0800 || temp == 0x0080 || (flags & 0x0040) != 0)) ? (ulong)0 : (ulong)1; break;
				default:
					return false; // should never hit
			};

			if ((code & 0x01) == 0)
				return (cond != 0);
			else
				return (cond == 0);               // Invert condition
		}

		public void Disasm(ByteStream src, ulong srcip, t_disasm disasm, int disasmmode)
		{
			int i, j, operand, mnemosize, arg;
			ulong u;

			int cxsize;

			string pname;

			// Prepare disassembler variables and initialize structure disasm.
			datasize = addrsize = 4;                 // 32-bit code and data segments only!
			segprefix = SEG_UNDEF;
			hasrm = false;
			hassib = false;
			dispsize = immsize = 0;
			bool lockprefix = false;                      // Non-zero if lock prefix present
			byte repprefix = 0; // REPxxx prefix or 0
			ndump = 0;

			cmd = new ByteStream(src, 0);
			//size = srcsize;

			pfixup = -1;
			softerror = 0;
			bool is3dnow = false;
			da = disasm;
			da.ip = srcip;
			da.comment = string.Empty;
			da.cmdtype = C_BAD; da.nprefix = 0;
			da.memtype = DEC_UNKNOWN; da.indexed = 0;
			da.jmpconst = 0; da.jmptable = 0;
			da.adrconst = 0; da.immconst = 0;
			da.zeroconst = 0;
			da.fixupoffset = 0;
			da.fixupsize = 0;
			da.warnings = 0;
			da.error = DAE_NOERR;
			mode = disasmmode;                     // No need to use register contents

			// Correct 80x86 command may theoretically contain up to 4 prefixes belonging
			// to different prefix groups. This limits maximal possible size of the
			// command to MAXCMDSIZE=16 bytes. In order to maintain this limit, if
			// Disasm() detects second prefix from the same group, it flushes first
			// prefix in the sequence as a pseudocommand.
			u = 0;
			bool repeated = false;
			while (size > 0)
			{
				bool isprefix = true;                        // Assume that there is some prefix
				switch (cmd[0])
				{
					case 0x26: if (segprefix == SEG_UNDEF) segprefix = SEG_ES;
						else repeated = true; break;
					case 0x2E: if (segprefix == SEG_UNDEF) segprefix = SEG_CS;
						else repeated = true; break;
					case 0x36: if (segprefix == SEG_UNDEF) segprefix = SEG_SS;
						else repeated = true; break;
					case 0x3E: if (segprefix == SEG_UNDEF) segprefix = SEG_DS;
						else repeated = true; break;
					case 0x64: if (segprefix == SEG_UNDEF) segprefix = SEG_FS;
						else repeated = true; break;
					case 0x65: if (segprefix == SEG_UNDEF) segprefix = SEG_GS;
						else repeated = true; break;
					case 0x66: if (datasize == 4) datasize = 2;
						else repeated = true; break;
					case 0x67: if (addrsize == 4) addrsize = 2;
						else repeated = true; break;
					case 0xF0: if (!lockprefix) repprefix = 0xF0; // lockprefix = 0xF0;
						else repeated = true; break;
					case 0xF2: if (repprefix == 0) repprefix = 0xF2;
						else repeated = true; break;
					case 0xF3: if (repprefix == 0) repprefix = 0xF3;
						else repeated = true; break;
					default: isprefix = false; break;
				};
				if (!isprefix || repeated)
					break;                           // No more prefixes or duplicated prefix

				if (mode >= DISASM_FILE)
					//	sprintf(da.dump + ndump, "%02X:", *cmd);
					da.dump.AppendFormat("{0}:", cmd[0]); // FIXME: "%02X:"

				da.nprefix++;
				cmd.AdjustOffset(1);
				srcip++;
				u++;
			};

			// We do have repeated prefix. Flush first prefix from the sequence.
			if (repeated)
			{
				if (mode >= DISASM_FILE)
				{
					da.dump[3] = '\0';                // Leave only first dumped prefix
					da.nprefix = 1;
					switch (cmd[(int)-(long)u])
					{
						case 0x26: pname = segname[SEG_ES]; break;
						case 0x2E: pname = segname[SEG_CS]; break;
						case 0x36: pname = segname[SEG_SS]; break;
						case 0x3E: pname = segname[SEG_DS]; break;
						case 0x64: pname = segname[SEG_FS]; break;
						case 0x65: pname = segname[SEG_GS]; break;
						case 0x66: pname = "DATASIZE"; break;
						case 0x67: pname = "ADDRSIZE"; break;
						case 0xF0: pname = "LOCK"; break;
						case 0xF2: pname = "REPNE"; break;
						case 0xF3: pname = "REPE"; break;
						default: pname = "?"; break;
					};
					//sprintf(da.result + nresult, "PREFIX %s:", pname);
					da.result.AppendFormat("PREFIX {0}:", pname);

					if (!extraprefix)
						da.comment = "Superfluous prefix";
				};
				da.warnings |= DAW_PREFIX;
				if (lockprefix)
					da.warnings |= DAW_LOCK;
				da.cmdtype = C_RARE;
				return; // 1;                          // Any prefix is 1 byte long
			};
			// If lock prefix available, display it and forget, because it has no
			// influence on decoding of rest of the command.
			if (lockprefix)
			{
				if (mode >= DISASM_FILE)
					da.result.Append("LOCK ");
				da.warnings |= DAW_LOCK;
			};
			// Fetch (if available) first 3 bytes of the command, add repeat prefix and
			// find command in the command table.
			ulong code = 0;
			if (cmd.SizeLeft > 0) code = cmd[0];
			if (cmd.SizeLeft > 1) code = code + (ulong)(cmd[1] << 8);
			if (cmd.SizeLeft > 2) code = code + (ulong)(cmd[2] << 16);
			if (repprefix != 0)                    // RER/REPE/REPNE is considered to be
				code = (code << 8) | repprefix;        // part of command.

			t_cmddata pd = cmddata[0]; // Assignment to first entry is to avoid compiler error
			int pd_index = 0;

			if (decodevxd && (code & 0xFFFF) == 0x20CD)
				pd = vxdcmd;                        // Decode VxD call (Win95/98)
			else
			{
				for (pd_index = 0; pd_index < cmddata.Length; pd_index++)
				{
					pd = cmddata[pd_index];
					if (((code ^ pd.code) & pd.mask) != 0)
						continue;

					if (mode >= DISASM_FILE && shortstringcmds && (pd.arg1 == MSO || pd.arg1 == MDE || pd.arg2 == MSO || pd.arg2 == MDE))
						continue;                      // Search short form of string command

					break;
				};
			};

			if ((pd.type & C_TYPEMASK) == C_NOW)
			{
				// 3DNow! commands require additional search.
				is3dnow = true;
				j = Get3dnowsuffix();
				if (j < 0)
					da.error = DAE_CROSS;
				else
				{
					//for (; pd.mask != 0; pd++)
					for (; pd_index < cmddata.Length; pd_index++)
					{
						pd = cmddata[pd_index];
						if (((code ^ pd.code) & pd.mask) != 0)
							continue;

						//if (((uchar*)&(pd.code))[2] == j)
						if ((int)((pd.code & 0xFF0000) >> 24) == j)
							break;
					};
				};
			};
			if (pd.mask == 0)
			{                   // Command not found
				da.cmdtype = C_BAD;
				if (cmd.SizeLeft < 2) da.error = DAE_CROSS;
				else da.error = DAE_BADCMD;
			}
			else
			{                               // Command recognized, decode it
				da.cmdtype = pd.type;
				cxsize = datasize;                   // Default size of ECX used as counter
				if (segprefix == SEG_FS || segprefix == SEG_GS || lockprefix)
					da.cmdtype |= C_RARE;             // These prefixes are rare
				if (pd.bits == PR)
					da.warnings |= DAW_PRIV;          // Privileged command (ring 0)
				else if (pd.bits == WP)
					da.warnings |= DAW_IO;            // I/O command
				// Win32 programs usually try to keep stack dword-aligned, so INC ESP
				// (44) and DEC ESP (4C) usually don't appear in real code. Also check for
				// ADD ESP,imm and SUB ESP,imm (81,C4,imm32; 83,C4,imm8; 81,EC,imm32;
				// 83,EC,imm8).
				if (cmd[0] == 0x44 || cmd[0] == 0x4C ||
				  (cmd.SizeLeft >= 3 && (cmd[0] == 0x81 || cmd[0] == 0x83) &&
				  (cmd[1] == 0xC4 || cmd[1] == 0xEC) && (cmd[2] & 0x03) != 0)
				)
				{
					da.warnings |= DAW_STACK;
					da.cmdtype |= C_RARE;
				};
				// Warn also on MOV SEG,... (8E...). Win32 works in flat mode.
				if (cmd[0] == 0x8E)
					da.warnings |= DAW_SEGMENT;
				// If opcode is 2-byte, adjust command.
				if (pd.len == 2)
				{
					if (cmd.SizeLeft == 0) da.error = DAE_CROSS;
					else
					{
						if (mode >= DISASM_FILE)
							//sprintf(da.dump + ndump, "%02X", *cmd);
							da.dump.AppendFormat("{0}", cmd[0]); // FIXME "%02X"

						cmd.AdjustOffset(1);

						srcip++;
					};
				};
				if (cmd.SizeLeft == 0) da.error = DAE_CROSS;
				// Some commands either feature non-standard data size or have bit which
				// allows to select data size.
				if ((pd.bits & WW) != 0 && (cmd[0] & WW) == 0)
					datasize = 1;                      // Bit W in command set to 0
				else if ((pd.bits & W3) != 0 && (cmd[0] & W3) == 0)
					datasize = 1;                      // Another position of bit W
				else if ((pd.bits & FF) != 0)
					datasize = 2;                      // Forced word (2-byte) size
				// Some commands either have mnemonics which depend on data size (8/16 bits
				// or 32 bits, like CWD/CDQ), or have several different mnemonics (like
				// JNZ/JNE). First case is marked by either '&' (mnemonic depends on
				// operand size) or '$' (depends on address size). In the second case,
				// there is no special marker and disassembler selects main mnemonic.
				if (mode >= DISASM_FILE)
				{
					string name = string.Empty;

					if (pd.name[0] == '&')
						mnemosize = datasize;
					else if (pd.name[0] == '$')
						mnemosize = addrsize;
					else mnemosize = 0;

					if (mnemosize != 0)
					{
						for (i = 0, j = 1; pd.name[j] != '\0'; j++)
						{
							if (pd.name[j] == ':')
							{      // Separator between 16/32 mnemonics
								if (mnemosize == 4) i = 0;
								else break;
							}
							else if (pd.name[j] == '*')
							{ // Substitute by 'W', 'D' or none
								if (mnemosize == 4 && sizesens != 2)
									name = name + 'D';
								else if (mnemosize != 4 && sizesens != 0)
									name = name + 'W';
							}
							else
								//name[i++] = pd.name[j];
								name = name + pd.name[j];
						};
						//name[i] = '\0';
					}
					else
					{
						//strcpy(name, pd.name);
						name = pd.name;

						int comma_index = name.IndexOf(',');
						if (comma_index >= 0)
							name = name.Substring(0, comma_index - 1);

						//for (i = 0; name[i] != '\0'; i++)
						//{
						//    if (name[i] == ',')
						//    {          // Use main mnemonic
						//        name[i] = '\0';
						//        break;
						//    };
						//};
					};
					//if (repprefix != 0 && tabarguments)
					//{
					//    for (i = 0; name[i] != '\0' && name[i] != ' '; i++)
					//        da.result[nresult++] = name[i];

					//    if (name[i] == ' ')
					//    {
					//        da.result[nresult++] = ' '; i++;
					//    };

					//    while (nresult < 8) da.result[nresult++] = ' ';

					//    for (; name[i] != '\0'; i++)
					//        da.result[nresult++] = name[i];

					//}
					//else
					//sprintf(da.result + nresult, "%s", name);
					da.result.Append(name);
				};
				// Decode operands (explicit - encoded in command, implicit - present in
				// mmemonic or assumed - used or modified by command). Assumed operands
				// must stay after all explicit and implicit operands. Up to 3 operands
				// are allowed.
				for (operand = 0; operand < 3; operand++)
				{
					if (da.error == 0) break;            // Error - no sense to continue
					// If command contains both source and destination, one usually must not
					// decode destination to comment because it will be overwritten on the
					// next step. Global addcomment takes care of this. Decoding routines,
					// however, may ignore this flag.
					if (operand == 0 && pd.arg2 != NNN && pd.arg2 < PSEUDOOP)
						addcomment = false;
					else
						addcomment = true;
					// Get type of next argument.
					if (operand == 0) arg = pd.arg1;
					else if (operand == 1) arg = pd.arg2;
					else arg = pd.arg3;
					if (arg == NNN) break;             // No more operands
					// Arguments with arg>=PSEUDOOP are assumed operands and are not
					// displayed in disassembled result, so they require no delimiter.
					if ((mode >= DISASM_FILE) && arg < PSEUDOOP)
					{
						if (operand == 0)
						{
							//da.result[nresult++] = ' ';
							da.result.Append(' ');
							//if (tabarguments)
							//{
							//    while (nresult < 8) da.result[nresult++] = ' ';
							//};
						}
						else
						{
							//da.result[nresult++] = ',';
							da.result.Append(',');
							//if (extraspace)
							//    //da.result[nresult++] = ' ';
							//    da.result.Append(' ');
						};
					};
					// Decode, analyse and comment next operand of the command.
					switch (arg)
					{
						case REG:                      // Integer register in Reg field
							if (cmd.SizeLeft < 2) da.error = DAE_CROSS;
							else DecodeRG(cmd[1] >> 3, datasize, REG);
							hasrm = true; break;
						case RCM:                      // Integer register in command byte
							DecodeRG(cmd[0], datasize, RCM); break;
						case RG4:                      // Integer 4-byte register in Reg field
							if (cmd.SizeLeft < 2) da.error = DAE_CROSS;
							else DecodeRG(cmd[1] >> 3, 4, RG4);
							hasrm = true; break;
						case RAC:                      // Accumulator (AL/AX/EAX, implicit)
							DecodeRG(REG_EAX, datasize, RAC); break;
						case RAX:                      // AX (2-byte, implicit)
							DecodeRG(REG_EAX, 2, RAX); break;
						case RDX:                      // DX (16-bit implicit port address)
							DecodeRG(REG_EDX, 2, RDX); break;
						case RCL:                      // Implicit CL register (for shifts)
							DecodeRG(REG_ECX, 1, RCL); break;
						case RS0:                      // Top of FPU stack (ST(0))
							DecodeST(0, 0); break;
						case RST:                      // FPU register (ST(i)) in command byte
							DecodeST(cmd[0], 0); break;
						case RMX:                      // MMX register MMx
							if (cmd.SizeLeft < 2) da.error = DAE_CROSS;
							else DecodeMX(cmd[1] >> 3);
							hasrm = true; break;
						case R3D:                      // 3DNow! register MMx
							if (cmd.SizeLeft < 2) da.error = DAE_CROSS;
							else DecodeNR(cmd[1] >> 3);
							hasrm = true; break;
						case MRG:                      // Memory/register in ModRM byte
						case MRJ:                      // Memory/reg in ModRM as JUMP target
						case MR1:                      // 1-byte memory/register in ModRM byte
						case MR2:                      // 2-byte memory/register in ModRM byte
						case MR4:                      // 4-byte memory/register in ModRM byte
						case MR8:                      // 8-byte memory/MMX register in ModRM
						case MRD:                      // 8-byte memory/3DNow! register in ModRM
						case MMA:                      // Memory address in ModRM byte for LEA
						case MML:                      // Memory in ModRM byte (for LES)
						case MM6:                      // Memory in ModRm (6-byte descriptor)
						case MMB:                      // Two adjacent memory locations (BOUND)
						case MD2:                      // Memory in ModRM byte (16-bit integer)
						case MB2:                      // Memory in ModRM byte (16-bit binary)
						case MD4:                      // Memory in ModRM byte (32-bit integer)
						case MD8:                      // Memory in ModRM byte (64-bit integer)
						case MDA:                      // Memory in ModRM byte (80-bit BCD)
						case MF4:                      // Memory in ModRM byte (32-bit float)
						case MF8:                      // Memory in ModRM byte (64-bit float)
						case MFA:                      // Memory in ModRM byte (80-bit float)
						case MFE:                      // Memory in ModRM byte (FPU environment)
						case MFS:                      // Memory in ModRM byte (FPU state)
						case MFX:                      // Memory in ModRM byte (ext. FPU state)
							DecodeMR(arg); break;
						case MMS:                      // Memory in ModRM byte (as SEG:OFFS)
							DecodeMR(arg);
							da.warnings |= DAW_FARADDR; break;
						case RR4:                      // 4-byte memory/register (register only)
						case RR8:                      // 8-byte MMX register only in ModRM
						case RRD:                      // 8-byte memory/3DNow! (register only)
							if ((cmd[1] & 0xC0) != 0xC0) softerror = DAE_REGISTER;
							DecodeMR(arg); break;
						case MSO:                      // Source in string op's ([ESI])
							DecodeSO(); break;
						case MDE:                      // Destination in string op's ([EDI])
							DecodeDE(); break;
						case MXL:                      // XLAT operand ([EBX+AL])
							DecodeXL(); break;
						case IMM:                      // Immediate data (8 or 16/32)
						case IMU:                      // Immediate unsigned data (8 or 16/32)
							if ((pd.bits & SS) != 0 && (cmd[0] & 0x02) != 0)
								DecodeIM(1, datasize, arg);
							else
								DecodeIM(datasize, 0, arg);
							break;
						case VXD:                      // VxD service (32-bit only)
							DecodeVX(); break;
						case IMX:                      // Immediate sign-extendable byte
							DecodeIM(1, datasize, arg); break;
						case C01:                      // Implicit constant 1 (for shifts)
							DecodeC1(); break;
						case IMS:                      // Immediate byte (for shifts)
						case IM1:                      // Immediate byte
							DecodeIM(1, 0, arg); break;
						case IM2:                      // Immediate word (ENTER/RET)
							DecodeIM(2, 0, arg);
							if ((da.immconst & 0x03) != 0) da.warnings |= DAW_STACK;
							break;
						case IMA:                      // Immediate absolute near data address
							DecodeIA(); break;
						case JOB:                      // Immediate byte offset (for jumps)
							DecodeRJ(1, srcip + 2); break;
						case JOW:                      // Immediate full offset (for jumps)
							DecodeRJ((ulong)datasize, (ulong)((int)srcip + datasize + 1)); break;	// FIXME
						case JMF:                      // Immediate absolute far jump/call addr
							DecodeJF();
							da.warnings |= DAW_FARADDR; break;
						case SGM:                      // Segment register in ModRM byte
							if (cmd.SizeLeft < 2) da.error = DAE_CROSS;
							DecodeSG(cmd[1] >> 3); hasrm = true; break;
						case SCM:                      // Segment register in command byte
							DecodeSG(cmd[0] >> 3);
							if ((da.cmdtype & C_TYPEMASK) == C_POP) da.warnings |= DAW_SEGMENT;
							break;
						case CRX:                      // Control register CRx
							if ((cmd[1] & 0xC0) != 0xC0) da.error = DAE_REGISTER;
							DecodeCR(cmd[1]); break;
						case DRX:                      // Debug register DRx
							if ((cmd[1] & 0xC0) != 0xC0) da.error = DAE_REGISTER;
							DecodeDR(cmd[1]); break;
						case PRN:                      // Near return address (pseudooperand)
							break;
						case PRF:                      // Far return address (pseudooperand)
							da.warnings |= DAW_FARADDR; break;
						case PAC:                      // Accumulator (AL/AX/EAX, pseudooperand)
							DecodeRG(REG_EAX, datasize, PAC); break;
						case PAH:                      // AH (in LAHF/SAHF, pseudooperand)
						case PFL:                      // Lower byte of flags (pseudooperand)
							break;
						case PS0:                      // Top of FPU stack (pseudooperand)
							DecodeST(0, 1); break;
						case PS1:                      // ST(1) (pseudooperand)
							DecodeST(1, 1); break;
						case PCX:                      // CX/ECX (pseudooperand)
							DecodeRG(REG_ECX, cxsize, PCX); break;
						case PDI:                      // EDI (pseudooperand in MMX extentions)
							DecodeRG(REG_EDI, 4, PDI); break;
						default:
							da.error = DAE_INTERN;        // Unknown argument type
							break;
					};
				};
				// Check whether command may possibly contain fixups.
				if (pfixup != -1 && da.fixupsize > 0)
					da.fixupoffset = pfixup;
				// Segment prefix and address size prefix are superfluous for command which
				// does not access memory. If this the case, mark command as rare to help
				// in analysis.
				if (da.memtype == DEC_UNKNOWN &&
				  (segprefix != SEG_UNDEF || (addrsize != 4 && pd.name[0] != '$'))
				)
				{
					da.warnings |= DAW_PREFIX;
					da.cmdtype |= C_RARE;
				};
				// 16-bit addressing is rare in 32-bit programs. If this is the case,
				// mark command as rare to help in analysis.
				if (addrsize != 4) da.cmdtype |= C_RARE;
			};
			// Suffix of 3DNow! command is accounted best by assuming it immediate byte
			// constant.
			if (is3dnow)
			{
				if (immsize != 0) da.error = DAE_BADCMD;
				else immsize = 1;
			};
			// Right or wrong, command decoded. Now dump it.
			if (da.error != 0)
			{                  // Hard error in command detected
				if (mode >= DISASM_FILE)
					//nresult = sprintf(da.result, "???");
					da.result.Append("???");

				if (da.error == DAE_BADCMD &&
				  (cmd[0] == 0x0F || cmd[0] == 0xFF) && size > 0
				)
				{
					if (mode >= DISASM_FILE)
						//sprintf(da.dump + ndump, "%02X", *cmd);
						da.dump.AppendFormat("{0}", cmd[0]); // FIXME: "%02X"

					cmd.AdjustOffset(1);
				};
				if (size > 0)
				{
					if (mode >= DISASM_FILE)
						//sprintf(da.dump + ndump, "%02X", *cmd);
						da.dump.AppendFormat("{0}", cmd[0]); // FIXME: "%02X"

					cmd.AdjustOffset(1);
				};
			}
			else
			{                               // No hard error, dump command
				if (mode >= DISASM_FILE)
				{
					cmd.AdjustOffset(1);
					da.dump.AppendFormat("{0}", cmd[0]); // FIXME: "%02X"

					if (hasrm)
					{
						cmd.AdjustOffset(1);
						da.dump.AppendFormat("{0}", cmd[0]); // FIXME: "%02X"
					}

					if (hassib)
					{
						cmd.AdjustOffset(1);
						da.dump.AppendFormat("{0}", cmd[0]); // FIXME: "%02X"
					}

					if (dispsize != 0)
					{
						da.dump[ndump++] = ' ';
						for (i = 0; i < dispsize; i++)
						{
							cmd.AdjustOffset(1);
							da.dump.AppendFormat("{0}", cmd[0]); // FIXME: "%02X"
						};
					};
					if (immsize != 0)
					{
						da.dump[ndump++] = ' ';
						for (i = 0; i < immsize; i++)
						{
							cmd.AdjustOffset(1);
							da.dump.AppendFormat("{0}", cmd[0]); // FIXME: "%02X"
						};
					};
				}
				else
					cmd.AdjustOffset(1 + (hasrm ? 1 : 0) + (hassib ? 1 : 0) + dispsize + immsize);
			};
			// Check that command is not a dangerous one.
			if (mode >= DISASM_DATA)
			{
				//t_cmddata pdan;
				//for (pdan = dangerous; pdan.mask != 0; pdan++)
				foreach (t_cmddata pdan in dangerous)
				{
					if (((code ^ pdan.code) & pdan.mask) != 0)
						continue;
					if (pdan.type == C_DANGERLOCK && !lockprefix)
						break;                         // Command harmless without LOCK prefix
					if (iswindowsnt && pdan.type == C_DANGER95)
						break;                         // Command harmless under Windows NT
					// Dangerous command!
					if (pdan.type == C_DANGER95) da.warnings |= DAW_DANGER95;
					else da.warnings |= DAW_DANGEROUS;
					break;
				};
			};
			if (da.error == 0 && softerror != 0)
				da.error = softerror;               // Error, but still display command
			if (mode >= DISASM_FILE)
			{
				if (da.error != DAE_NOERR) switch (da.error)
					{
						case DAE_CROSS:
							da.comment = "Command crosses end of memory block"; break;
						case DAE_BADCMD:
							da.comment = "Unknown command"; break;
						case DAE_BADSEG:
							da.comment = "Undefined segment register"; break;
						case DAE_MEMORY:
							da.comment = "Illegal use of register"; break;
						case DAE_REGISTER:
							da.comment = "Memory address not allowed"; break;
						case DAE_INTERN:
							da.comment = "Internal OLLYDBG error"; break;
						default:
							da.comment = "Unknown error";
							break;
					}
				else if ((da.warnings & DAW_PRIV) != 0 && !privileged)
					da.comment = "Privileged command";
				else if ((da.warnings & DAW_IO) != 0 && !iocommand)
					da.comment = "I/O command";
				else if ((da.warnings & DAW_FARADDR) != 0 && !farcalls)
				{
					if ((da.cmdtype & C_TYPEMASK) == C_JMP)
						da.comment = "Far jump";
					else if ((da.cmdtype & C_TYPEMASK) == C_CAL)
						da.comment = "Far call";
					else if ((da.cmdtype & C_TYPEMASK) == C_RET)
						da.comment = "Far return";
					;
				}
				else if ((da.warnings & DAW_SEGMENT) != 0 && !farcalls)
					da.comment = "Modification of segment register";
				else if ((da.warnings & DAW_SHIFT) != 0 && !badshift)
					da.comment = "Shift constant out of range 1..31";
				else if ((da.warnings & DAW_PREFIX) != 0 && !extraprefix)
					da.comment = "Superfluous prefix";
				else if ((da.warnings & DAW_LOCK) != 0 && !lockedbus)
					da.comment = "LOCK prefix";
				else if ((da.warnings & DAW_STACK) != 0 && !stackalign)
					da.comment = "Unaligned stack operation";
				;
			};

			return;
		}


		#endregion

		#region Customized Methods

		// Decodes address into symb (nsymb bytes long, including the terminating zero
		// character) and comments its possible meaning. Returns number of bytes in
		// symb not including terminating zero.
		string Decodeaddress(ulong addr)
		{
			// Environment-specific routine! Do it yourself!

			return string.Empty;
		}

		#endregion

	}
}
