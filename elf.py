#
#
#	z2kit v2 : Security Camp track Z2 : sort of analysis framework
#
#	elf.py
#	ELF data structure
#
#	Copyright (C) 2018 Tsukasa OI.
#
#	Permission to use, copy, modify, and/or distribute this software
#	for any purpose with or without fee is hereby granted, provided
#	that the above copyright notice and this permission notice
#	appear in all copies.
#
#	THE SOFTWARE IS PROVIDED “AS IS” AND ISC DISCLAIMS ALL WARRANTIES
#	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR
#	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
#	DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
#	WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
#	ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#	PERFORMANCE OF THIS SOFTWARE.
#
#	Portions of the code is based on elf.h from the GNU C Library
#	but I'm not complying with GNU LGPL, the original license.
#	This is because elf.h only defines common semantics and common
#	constants, neither can be copyright-applicable (in general).
#
#
from . import zstruct

########################################################################
#
#   ELF 識別ヘッダー
#
########################################################################

#  e_ident のインデックス
EI_MAG0       = 0
EI_MAG1       = 1
EI_MAG2       = 2
EI_MAG3       = 3
EI_CLASS      = 4
EI_DATA       = 5
EI_VERSION    = 6
EI_OSABI      = 7
EI_ABIVERSION = 8
EI_PAD        = 9

#  EI_MAG[0123]
ELFMAG0 = 0x7f
ELFMAG1 = 0x45  # 'E'
ELFMAG2 = 0x4c  # 'L'
ELFMAG3 = 0x46  # 'F'

#  EI_CLASS
ELFCLASSNONE = 0
ELFCLASS32   = 1
ELFCLASS64   = 2

#  EI_DATA
ELFDATANONE = 0
ELFDATA2LSB = 1
ELFDATA2MSB = 2

#  EI_VERSION
EV_NONE    = 0
EV_CURRENT = 1

#  EI_OSABI
ELFOSABI_NONE       = 0
ELFOSABI_SYSV       = 0
ELFOSABI_HPUX       = 1
ELFOSABI_NETBSD     = 2
ELFOSABI_GNU        = 3
ELFOSABI_LINUX      = 3
ELFOSABI_SOLARIS    = 6
ELFOSABI_AIX        = 7
ELFOSABI_IRIX       = 8
ELFOSABI_FREEBSD    = 9
ELFOSABI_TRU64      = 10
ELFOSABI_MODESTO    = 11
ELFOSABI_OPENBSD    = 12
ELFOSABI_ARM_AEABI  = 64
ELFOSABI_ARM        = 97
ELFOSABI_STANDALONE = 255

class __Elf_IdentHeader_impl:
	def is_valid_elf(self):
		#  ELF 識別情報が正しいものかを読み取る。
		#   * 先頭から '\x7fELF' であること
		#   * 32-bit もしくは 64-bit クラスであること
		#   * 2 の補数形式のリトルもしくはビッグエンディアンであること
		#   * ELF フォーマットの正しいバージョン (EV_CURRENT) であること
		return \
			self.e_ident[EI_MAG0] == ELFMAG0 and \
			self.e_ident[EI_MAG1] == ELFMAG1 and \
			self.e_ident[EI_MAG2] == ELFMAG2 and \
			self.e_ident[EI_MAG3] == ELFMAG3 and \
			( \
				self.e_ident[EI_CLASS] == ELFCLASS32 or \
				self.e_ident[EI_CLASS] == ELFCLASS64
			) and \
			( \
				self.e_ident[EI_DATA] == ELFDATA2LSB or \
				self.e_ident[EI_DATA] == ELFDATA2MSB
			) and \
			self.e_ident[EI_VERSION] == EV_CURRENT
	def get_endian(self):
		# ELF ファイルにはリトルエンディアンとビッグエンディアンの両方が有り得る。
		if   self.e_ident[EI_DATA] == ELFDATA2LSB:
			return zstruct.ENDIAN_LITTLE
		elif self.e_ident[EI_DATA] == ELFDATA2MSB:
			return zstruct.ENDIAN_BIG
		else:
			return None
	def get_class(self):
		return self.e_ident[EI_CLASS]

@zstruct.zstruct(('e_ident', '[16]unsigned char'))
class Elf_IdentHeader(__Elf_IdentHeader_impl):
	pass

########################################################################
#
#   ELF ファイルヘッダー (識別ヘッダーを含む)
#
########################################################################

#  e_type
ET_NONE = 0
ET_REL  = 1
ET_EXEC = 2
ET_DYN  = 3
ET_CORE = 4

#  e_machine
EM_NONE            =   0   # No machine
EM_M32             =   1   # AT&T WE 32100
EM_SPARC           =   2   # SUN SPARC
EM_386             =   3   # Intel 80386
EM_68K             =   4   # Motorola m68k family
EM_88K             =   5   # Motorola m88k family
EM_IAMCU           =   6   # Intel MCU
EM_860             =   7   # Intel 80860
EM_MIPS            =   8   # MIPS R3000 big-endian
EM_S370            =   9   # IBM System/370
EM_MIPS_RS3_LE     =  10   # MIPS R3000 little-endian
EM_PARISC          =  15   # HPPA
EM_VPP500          =  17   # Fujitsu VPP500
EM_SPARC32PLUS     =  18   # Sun's "v8plus"
EM_960             =  19   # Intel 80960
EM_PPC             =  20   # PowerPC
EM_PPC64           =  21   # PowerPC 64-bit
EM_S390            =  22   # IBM S390
EM_SPU             =  23   # IBM SPU/SPC
EM_V800            =  36   # NEC V800 series
EM_FR20            =  37   # Fujitsu FR20
EM_RH32            =  38   # TRW RH-32
EM_RCE             =  39   # Motorola RCE
EM_ARM             =  40   # ARM
EM_FAKE_ALPHA      =  41   # Digital Alpha
EM_SH              =  42   # Hitachi SH
EM_SPARCV9         =  43   # SPARC v9 64-bit
EM_TRICORE         =  44   # Siemens Tricore
EM_ARC             =  45   # Argonaut RISC Core
EM_H8_300          =  46   # Hitachi H8/300
EM_H8_300H         =  47   # Hitachi H8/300H
EM_H8S             =  48   # Hitachi H8S
EM_H8_500          =  49   # Hitachi H8/500
EM_IA_64           =  50   # Intel Merced
EM_MIPS_X          =  51   # Stanford MIPS-X
EM_COLDFIRE        =  52   # Motorola Coldfire
EM_68HC12          =  53   # Motorola M68HC12
EM_MMA             =  54   # Fujitsu MMA Multimedia Accelerator
EM_PCP             =  55   # Siemens PCP
EM_NCPU            =  56   # Sony nCPU embeeded RISC
EM_NDR1            =  57   # Denso NDR1 microprocessor
EM_STARCORE        =  58   # Motorola Start*Core processor
EM_ME16            =  59   # Toyota ME16 processor
EM_ST100           =  60   # STMicroelectronic ST100 processor
EM_TINYJ           =  61   # Advanced Logic Corp. Tinyj emb.fam
EM_X86_64          =  62   # AMD x86-64 architecture
EM_PDSP            =  63   # Sony DSP Processor
EM_PDP10           =  64   # Digital PDP-10
EM_PDP11           =  65   # Digital PDP-11
EM_FX66            =  66   # Siemens FX66 microcontroller
EM_ST9PLUS         =  67   # STMicroelectronics ST9+ 8/16 mc
EM_ST7             =  68   # STmicroelectronics ST7 8 bit mc
EM_68HC16          =  69   # Motorola MC68HC16 microcontroller
EM_68HC11          =  70   # Motorola MC68HC11 microcontroller
EM_68HC08          =  71   # Motorola MC68HC08 microcontroller
EM_68HC05          =  72   # Motorola MC68HC05 microcontroller
EM_SVX             =  73   # Silicon Graphics SVx
EM_ST19            =  74   # STMicroelectronics ST19 8 bit mc
EM_VAX             =  75   # Digital VAX
EM_CRIS            =  76   # Axis Communications 32-bit emb.proc
EM_JAVELIN         =  77   # Infineon Technologies 32-bit emb.proc
EM_FIREPATH        =  78   # Element 14 64-bit DSP Processor
EM_ZSP             =  79   # LSI Logic 16-bit DSP Processor
EM_MMIX            =  80   # Donald Knuth's educational 64-bit proc
EM_HUANY           =  81   # Harvard University machine-independent object files
EM_PRISM           =  82   # SiTera Prism
EM_AVR             =  83   # Atmel AVR 8-bit microcontroller
EM_FR30            =  84   # Fujitsu FR30
EM_D10V            =  85   # Mitsubishi D10V
EM_D30V            =  86   # Mitsubishi D30V
EM_V850            =  87   # NEC v850
EM_M32R            =  88   # Mitsubishi M32R
EM_MN10300         =  89   # Matsushita MN10300
EM_MN10200         =  90   # Matsushita MN10200
EM_PJ              =  91   # picoJava
EM_OPENRISC        =  92   # OpenRISC 32-bit embedded processor
EM_ARC_COMPACT     =  93   # ARC International ARCompact
EM_XTENSA          =  94   # Tensilica Xtensa Architecture
EM_VIDEOCORE       =  95   # Alphamosaic VideoCore
EM_TMM_GPP         =  96   # Thompson Multimedia General Purpose Proc
EM_NS32K           =  97   # National Semi. 32000
EM_TPC             =  98   # Tenor Network TPC
EM_SNP1K           =  99   # Trebia SNP 1000
EM_ST200           = 100   # STMicroelectronics ST200
EM_IP2K            = 101   # Ubicom IP2xxx
EM_MAX             = 102   # MAX processor
EM_CR              = 103   # National Semi. CompactRISC
EM_F2MC16          = 104   # Fujitsu F2MC16
EM_MSP430          = 105   # Texas Instruments msp430
EM_BLACKFIN        = 106   # Analog Devices Blackfin DSP
EM_SE_C33          = 107   # Seiko Epson S1C33 family
EM_SEP             = 108   # Sharp embedded microprocessor
EM_ARCA            = 109   # Arca RISC
EM_UNICORE         = 110   # PKU-Unity & MPRC Peking Uni. mc series
EM_EXCESS          = 111   # eXcess configurable cpu
EM_DXP             = 112   # Icera Semi. Deep Execution Processor
EM_ALTERA_NIOS2    = 113   # Altera Nios II
EM_CRX             = 114   # National Semi. CompactRISC CRX
EM_XGATE           = 115   # Motorola XGATE
EM_C166            = 116   # Infineon C16x/XC16x
EM_M16C            = 117   # Renesas M16C
EM_DSPIC30F        = 118   # Microchip Technology dsPIC30F
EM_CE              = 119   # Freescale Communication Engine RISC
EM_M32C            = 120   # Renesas M32C
EM_TSK3000         = 131   # Altium TSK3000
EM_RS08            = 132   # Freescale RS08
EM_SHARC           = 133   # Analog Devices SHARC family
EM_ECOG2           = 134   # Cyan Technology eCOG2
EM_SCORE7          = 135   # Sunplus S+core7 RISC
EM_DSP24           = 136   # New Japan Radio (NJR) 24-bit DSP
EM_VIDEOCORE3      = 137   # Broadcom VideoCore III
EM_LATTICEMICO32   = 138   # RISC for Lattice FPGA
EM_SE_C17          = 139   # Seiko Epson C17
EM_TI_C6000        = 140   # Texas Instruments TMS320C6000 DSP
EM_TI_C2000        = 141   # Texas Instruments TMS320C2000 DSP
EM_TI_C5500        = 142   # Texas Instruments TMS320C55x DSP
EM_TI_ARP32        = 143   # Texas Instruments App. Specific RISC
EM_TI_PRU          = 144   # Texas Instruments Prog. Realtime Unit
EM_MMDSP_PLUS      = 160   # STMicroelectronics 64bit VLIW DSP
EM_CYPRESS_M8C     = 161   # Cypress M8C
EM_R32C            = 162   # Renesas R32C
EM_TRIMEDIA        = 163   # NXP Semi. TriMedia
EM_QDSP6           = 164   # QUALCOMM DSP6
EM_8051            = 165   # Intel 8051 and variants
EM_STXP7X          = 166   # STMicroelectronics STxP7x
EM_NDS32           = 167   # Andes Tech. compact code emb. RISC
EM_ECOG1X          = 168   # Cyan Technology eCOG1X
EM_MAXQ30          = 169   # Dallas Semi. MAXQ30 mc
EM_XIMO16          = 170   # New Japan Radio (NJR) 16-bit DSP
EM_MANIK           = 171   # M2000 Reconfigurable RISC
EM_CRAYNV2         = 172   # Cray NV2 vector architecture
EM_RX              = 173   # Renesas RX
EM_METAG           = 174   # Imagination Tech. META
EM_MCST_ELBRUS     = 175   # MCST Elbrus
EM_ECOG16          = 176   # Cyan Technology eCOG16
EM_CR16            = 177   # National Semi. CompactRISC CR16
EM_ETPU            = 178   # Freescale Extended Time Processing Unit
EM_SLE9X           = 179   # Infineon Tech. SLE9X
EM_L10M            = 180   # Intel L10M
EM_K10M            = 181   # Intel K10M
EM_AARCH64         = 183   # ARM AARCH64
EM_AVR32           = 185   # Amtel 32-bit microprocessor
EM_STM8            = 186   # STMicroelectronics STM8
EM_TILE64          = 187   # Tileta TILE64
EM_TILEPRO         = 188   # Tilera TILEPro
EM_MICROBLAZE      = 189   # Xilinx MicroBlaze
EM_CUDA            = 190   # NVIDIA CUDA
EM_TILEGX          = 191   # Tilera TILE-Gx
EM_CLOUDSHIELD     = 192   # CloudShield
EM_COREA_1ST       = 193   # KIPO-KAIST Core-A 1st gen.
EM_COREA_2ND       = 194   # KIPO-KAIST Core-A 2nd gen.
EM_ARC_COMPACT2    = 195   # Synopsys ARCompact V2
EM_OPEN8           = 196   # Open8 RISC
EM_RL78            = 197   # Renesas RL78
EM_VIDEOCORE5      = 198   # Broadcom VideoCore V
EM_78KOR           = 199   # Renesas 78KOR
EM_56800EX         = 200   # Freescale 56800EX DSC
EM_BA1             = 201   # Beyond BA1
EM_BA2             = 202   # Beyond BA2
EM_XCORE           = 203   # XMOS xCORE
EM_MCHP_PIC        = 204   # Microchip 8-bit PIC(r)
EM_KM32            = 210   # KM211 KM32
EM_KMX32           = 211   # KM211 KMX32
EM_EMX16           = 212   # KM211 KMX16
EM_EMX8            = 213   # KM211 KMX8
EM_KVARC           = 214   # KM211 KVARC
EM_CDP             = 215   # Paneve CDP
EM_COGE            = 216   # Cognitive Smart Memory Processor
EM_COOL            = 217   # Bluechip CoolEngine
EM_NORC            = 218   # Nanoradio Optimized RISC
EM_CSR_KALIMBA     = 219   # CSR Kalimba
EM_Z80             = 220   # Zilog Z80
EM_VISIUM          = 221   # Controls and Data Services VISIUMcore
EM_FT32            = 222   # FTDI Chip FT32
EM_MOXIE           = 223   # Moxie processor
EM_AMDGPU          = 224   # AMD GPU
EM_RISCV           = 243   # RISC-V
EM_BPF             = 247   # Linux BPF -- in-kernel virtual machine


class __Elf_Ehdr_impl(__Elf_IdentHeader_impl):
	pass

@zstruct.zstruct(
	('e_ident',     '[16]unsigned char'),
	('e_type',      ':Elf32_Half'),
	('e_machine',   ':Elf32_Half'),
	('e_version',   ':Elf32_Word'),
	('e_entry',     ':Elf32_Addr'),
	('e_phoff',     ':Elf32_Off'),
	('e_shoff',     ':Elf32_Off'),
	('e_flags',     ':Elf32_Word'),
	('e_ehsize',    ':Elf32_Half'),
	('e_phentsize', ':Elf32_Half'),
	('e_phnum',     ':Elf32_Half'),
	('e_shentsize', ':Elf32_Half'),
	('e_shnum',     ':Elf32_Half'),
	('e_shstrndx',  ':Elf32_Half'),
	typedefs = {
		'Elf32_Half': 'uint16_t',
		'Elf32_Word': 'uint32_t',
		'Elf32_Addr': 'uint32_t',
		'Elf32_Off':  'uint32_t',
	},
)
class Elf32_Ehdr(__Elf_Ehdr_impl):
	pass

@zstruct.zstruct(
	('e_ident',     '[16]unsigned char'),
	('e_type',      ':Elf64_Half'),
	('e_machine',   ':Elf64_Half'),
	('e_version',   ':Elf64_Word'),
	('e_entry',     ':Elf64_Addr'),
	('e_phoff',     ':Elf64_Off'),
	('e_shoff',     ':Elf64_Off'),
	('e_flags',     ':Elf64_Word'),
	('e_ehsize',    ':Elf64_Half'),
	('e_phentsize', ':Elf64_Half'),
	('e_phnum',     ':Elf64_Half'),
	('e_shentsize', ':Elf64_Half'),
	('e_shnum',     ':Elf64_Half'),
	('e_shstrndx',  ':Elf64_Half'),
	typedefs = {
		'Elf64_Half': 'uint16_t',
		'Elf64_Word': 'uint32_t',
		'Elf64_Addr': 'uint64_t',
		'Elf64_Off':  'uint64_t',
	},
)
class Elf64_Ehdr(__Elf_Ehdr_impl):
	pass

########################################################################
#
#   ELF セクションヘッダー
#
########################################################################

#  セクションヘッダーの特別なインデックス
SHN_UNDEF     = 0x0000
SHN_LORESERVE = 0xff00
SHN_LOPROC    = 0xff00
SHN_BEFORE    = 0xff00
SHN_AFTER     = 0xff01
SHN_HIPROC    = 0xff1f
SHN_LOOS      = 0xff20
SHN_HIOS      = 0xff3f
SHN_ABS       = 0xfff1
SHN_COMMON    = 0xfff2
SHN_XINDEX    = 0xffff
SHN_HIRESERVE = 0xffff

#  sh_type
SHT_NULL          =  0
SHT_PROGBITS      =  1
SHT_SYMTAB        =  2
SHT_STRTAB        =  3
SHT_RELA          =  4
SHT_HASH          =  5
SHT_DYNAMIC       =  6
SHT_NOTE          =  7
SHT_NOBITS        =  8
SHT_REL           =  9
SHT_SHLIB         = 10
SHT_DYNSYM        = 11
SHT_INIT_ARRAY    = 14
SHT_FINI_ARRAY    = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP         = 17
SHT_SYMTAB_SHNDX  = 18

#  sh_flags
SHF_WRITE      = 1 <<  0   # 0x0001
SHF_ALLOC      = 1 <<  1   # 0x0002
SHF_EXECINSTR  = 1 <<  2   # 0x0004
SHF_MERGE      = 1 <<  4   # 0x0010
SHF_STRINGS    = 1 <<  5   # 0x0020
SHF_INFO_LINK  = 1 <<  6   # 0x0040
SHF_LINK_ORDER = 1 <<  7   # 0x0080
SHF_GROUP      = 1 <<  9   # 0x0200
SHF_TLS        = 1 << 10   # 0x0400

class __Elf_Shdr_impl:
	pass

@zstruct.zstruct(
	('sh_name',       ':Elf32_Word'),
	('sh_type',       ':Elf32_Word'),
	('sh_flags',      ':Elf32_Word'),
	('sh_addr',       ':Elf32_Addr'),
	('sh_offset',     ':Elf32_Off'),
	('sh_size',       ':Elf32_Word'),
	('sh_link',       ':Elf32_Word'),
	('sh_info',       ':Elf32_Word'),
	('sh_addralign',  ':Elf32_Word'),
	('sh_entsize',    ':Elf32_Word'),
	typedefs = {
		'Elf32_Word': 'uint32_t',
		'Elf32_Addr': 'uint32_t',
		'Elf32_Off':  'uint32_t',
	},
)
class Elf32_Shdr(__Elf_Shdr_impl):
	pass

@zstruct.zstruct(
	('sh_name',       ':Elf64_Word'),
	('sh_type',       ':Elf64_Word'),
	('sh_flags',      ':Elf64_Xword'),
	('sh_addr',       ':Elf64_Addr'),
	('sh_offset',     ':Elf64_Off'),
	('sh_size',       ':Elf64_Xword'),
	('sh_link',       ':Elf64_Word'),
	('sh_info',       ':Elf64_Word'),
	('sh_addralign',  ':Elf64_Xword'),
	('sh_entsize',    ':Elf64_Xword'),
	typedefs = {
		'Elf64_Word':  'uint32_t',
		'Elf64_Xword': 'uint64_t',
		'Elf64_Addr':  'uint64_t',
		'Elf64_Off':   'uint64_t',
	},
)
class Elf64_Shdr(__Elf_Shdr_impl):
	pass

########################################################################
#
#   ELF プログラムヘッダー
#
########################################################################

# p_type
PT_NULL     = 0
PT_LOAD     = 1
PT_DYNAMIC  = 2
PT_INTERP   = 3
PT_NOTE     = 4
PT_SHLIB    = 5
PT_PHDR     = 6
PT_TLS      = 7
PT_NUM      = 8
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK    = 0x6474e551
PT_GNU_RELRO    = 0x6474e552

# p_flags
PF_X = 1 << 0  # 1
PF_W = 1 << 1  # 2
PF_R = 1 << 2  # 4

class __Elf_Phdr_impl:
	pass

@zstruct.zstruct(
	('p_type',       ':Elf32_Word'),
	('p_offset',     ':Elf32_Off'),
	('p_vaddr',      ':Elf32_Addr'),
	('p_paddr',      ':Elf32_Addr'),
	('p_filesz',     ':Elf32_Word'),
	('p_memsz',      ':Elf32_Word'),
	('p_flags',      ':Elf32_Word'),
	('p_align',      ':Elf32_Word'),
	typedefs = {
		'Elf32_Word': 'uint32_t',
		'Elf32_Addr': 'uint32_t',
		'Elf32_Off':  'uint32_t',
	},
)
class Elf32_Phdr(__Elf_Phdr_impl):
	pass

@zstruct.zstruct(
	('p_type',       ':Elf64_Word'),
	('p_flags',      ':Elf64_Word'),  # Elf32 と位置が違うことに注意
	('p_offset',     ':Elf64_Off'),
	('p_vaddr',      ':Elf64_Addr'),
	('p_paddr',      ':Elf64_Addr'),
	('p_filesz',     ':Elf64_Xword'),
	('p_memsz',      ':Elf64_Xword'),
	('p_align',      ':Elf64_Xword'),
	typedefs = {
		'Elf64_Word':  'uint32_t',
		'Elf64_Xword': 'uint64_t',
		'Elf64_Addr':  'uint64_t',
		'Elf64_Off':   'uint64_t',
	},
)
class Elf64_Phdr(__Elf_Phdr_impl):
	pass

########################################################################
#
#   ELF Dynamic (動的リンク) セクション情報
#
########################################################################

# d_tag
DT_NULL            =  0
DT_NEEDED          =  1
DT_PLTRELSZ        =  2
DT_PLTGOT          =  3
DT_HASH            =  4
DT_STRTAB          =  5
DT_SYMTAB          =  6
DT_RELA            =  7
DT_RELASZ          =  8
DT_RELAENT         =  9
DT_STRSZ           = 10
DT_SYMENT          = 11
DT_INIT            = 12
DT_FINI            = 13
DT_SONAME          = 14
DT_RPATH           = 15
DT_SYMBOLIC        = 16
DT_REL             = 17
DT_RELSZ           = 18
DT_RELENT          = 19
DT_PLTREL          = 20
DT_DEBUG           = 21
DT_TEXTREL         = 22
DT_JMPREL          = 23
DT_BIND_NOW        = 24
DT_INIT_ARRAY      = 25
DT_FINI_ARRAY      = 26
DT_INIT_ARRAYSZ    = 27
DT_FINI_ARRAYSZ    = 28
DT_RUNPATH         = 29
DT_FLAGS           = 30
DT_ENCODING        = 32
DT_PREINIT_ARRAY   = 32
DT_PREINIT_ARRAYSZ = 33

class __Elf_Dyn_impl:
	# d_addr は d_val のエイリアス (/usr/include/elf.h にて union であることを確認)
	#  * Elf32_Word  == Elf32_Addr
	#  * Elf64_Xword == Elf64_Addr
	@property
	def d_addr(self):
		return self.d_val
	@d_addr.setter
	def d_addr(self, value):
		self.d_val = value

@zstruct.zstruct(
	('d_tag', ':Elf32_Sword'),
	('d_val', ':Elf32_Word'),
	typedefs = {
		'Elf32_Sword':  'int32_t',
		'Elf32_Word':  'uint32_t',
	},
)
class Elf32_Dyn(__Elf_Dyn_impl):
	pass

@zstruct.zstruct(
	('d_tag', ':Elf64_Sxword'),
	('d_val', ':Elf64_Xword'),
	typedefs = {
		'Elf64_Sxword':  'int64_t',
		'Elf64_Xword':  'uint64_t',
	},
)
class Elf64_Dyn(__Elf_Dyn_impl):
	pass
