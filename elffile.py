#
#
#	z2kit v2 : Security Camp track Z2 : sort of analysis framework
#
#	elffile.py
#	ELF file reading utilities
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
#
from . import elf





class ELFFile:

	def __check_offset_and_length(self, offset, length):
		if offset < 0:
			raise ValueError('オフセット `{}\' は 0 未満になることができません。'.format(offset))
		if length < 0:
			raise ValueError('長さ `{}\' は 0 未満になることができません。'.format(length))

	#  データの読み取り (シーク無し)
	def __read_data_cur(self, length):
		if length == 0:
			return b''
		return self.__f.read(length)

	#  データの読み取り (できるだけ安全に)
	def read_data(self, offset, length):
		self.__check_offset_and_length(offset, length)
		self.__f.seek(offset, 0)
		if self.__f.tell() != offset:
			raise IOError('指定したオフセット `{}\' に移動できませんでした。'.format(offset))
		data = self.__read_data_cur(length)
		if len(data) != length:
			raise IOError('指定したオフセット `{}\' から長さ `{}\' のデータを読み取れません (実際の読み取り長: `{}\')。'\
				.format(offset, length, len(data)))
		return data

	#  データの読み取り (読み取れなかった分のデータは補完しない)
	def read_data_possible(self, offset, length):
		self.__check_offset_and_length(offset, length)
		self.__f.seek(offset, 0)
		if self.__f.tell() != offset or length == 0:
			return b''
		return self.__f.read(length)

	#  データの読み取り (読み取れなかった分のデータは 0 埋め)
	def read_data_anyway(self, offset, length):
		self.__check_offset_and_length(offset, length)
		self.__f.seek(offset, 0)
		if self.__f.tell() != offset or length == 0:
			return b'\x00' * length
		data = self.__f.read(length)
		if len(data) < length:
			data += b'\x00' * (length - len(data))
		return data



	#  データ用の型の判別 (32-bit もしくは 64-bit 分岐)
	def get_data_type(self, t32, t64):
		return t64 if self.elf_ident_class == elf.ELFCLASS64 else t32

	#  自動データ読み取り (ELF クラスおよびエンディアン分岐)
	def read_data_type(self, offset, t32, t64):
		T = self.get_data_type(t32, t64)
		return T.init_from(self.read_data(offset, T.struct_length), endian=self.elf_ident_endian)



	#
	#  初期化
	def __init__(self, f):
		self.__f = f  # ファイル
		self.elf_ident = elf.Elf_IdentHeader.init_from(self.read_data(0, elf.Elf_IdentHeader.struct_length))
		self.elf_ident_class  = self.elf_ident.get_class()
		self.elf_ident_endian = self.elf_ident.get_endian()
		if not self.elf_ident.is_valid_elf():
			raise ValueError('指定されたファイルは正しい ELF ファイルではありません。')
		self.elf_header = self.read_data_type(0, elf.Elf32_Ehdr, elf.Elf64_Ehdr)
		try:
			self.read_program_headers()
		except:
			pass
		try:
			self.read_section_headers()
		except:
			pass

	#  プログラムヘッダーの読み取り
	def read_program_headers(self):
		self.program_headers = None
		ptype = self.get_data_type(elf.Elf32_Phdr, elf.Elf64_Phdr)
		t = []
		if self.elf_header.e_phoff != 0 and self.elf_header.e_phnum > 0:
			if self.elf_header.e_phentsize < ptype.struct_length:
				raise IOError('プログラムヘッダーのエントリーサイズが小さすぎます。')
			for i in range(self.elf_header.e_phnum):
				t.append(self.read_data_type(self.elf_header.e_phoff + i * self.elf_header.e_phentsize, elf.Elf32_Phdr, elf.Elf64_Phdr))
		self.program_headers = t

	#  セクションヘッダーの読み取り
	def read_section_headers(self):
		self.section_headers = None
		ptype = self.get_data_type(elf.Elf32_Shdr, elf.Elf64_Shdr)
		t = []
		if self.elf_header.e_shoff != 0 and self.elf_header.e_shnum > 0:
			if self.elf_header.e_shentsize < ptype.struct_length:
				raise IOError('プログラムヘッダーのエントリーサイズが小さすぎます。')
			for i in range(self.elf_header.e_shnum):
				t.append(self.read_data_type(self.elf_header.e_shoff + i * self.elf_header.e_shentsize, elf.Elf32_Shdr, elf.Elf64_Shdr))
		self.section_headers = t
