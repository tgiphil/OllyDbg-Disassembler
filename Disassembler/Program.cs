
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Disassembler
{
	class Program
	{

		static byte[] sample1 = new byte[] {
			0x81,0x05,0xE0,0x5A,0x47,0x00,0x01,0x00,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66
		};

		static byte[] add1 = new byte[] {
			0x81,0x05,0xE0,0x5A,0x47,0x00,0x01,0x00,0x00,0x00
		};

		static byte[] call1 = new byte[] {
			0xE8,0x1F,0x14,0x00,0x00
		};

		static void Main(string[] args)
		{
			t_disasm asm;

			Disassemble disam1 = new Disassemble();
			disam1.ideal = false;
			disam1.putdefseg = false;
			asm = disam1.Disasm(new ByteStream(add1), 0x400000, Disassemble.DISASM_FILE);
			Console.WriteLine(asm.result.ToString());
			Console.WriteLine(asm.dump.ToString());
			
			Disassemble disam2 = new Disassemble();
			disam2.ideal = true;
			disam2.putdefseg = true;
			asm = disam2.Disasm(new ByteStream(add1), 0x400000, Disassemble.DISASM_FILE);
			Console.WriteLine(asm.result.ToString());
			Console.WriteLine(asm.dump.ToString());

			Disassemble disam3 = new Disassemble();
			t_disasm asm3 = disam3.Disasm(new ByteStream(call1), 0x450458, Disassemble.DISASM_FILE);
			Console.WriteLine(asm.result.ToString());
			Console.WriteLine(asm.dump.ToString());

			return;
		}
	}
}
