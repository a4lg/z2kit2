#
#
#	z2kit v2 : Security Camp track Z2 : sort of analysis framework
#
#	zstruct.py
#	Structure-reading utility
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
import struct
import re

#  zstruct 要素名の必要要件
#   1. 英字もしくはアンダースコアで始まる
#   2. それより後は英数字もしくはアンダースコア
#   3. ただし、アンダースコアが 2 個連続しているとエラー
#   4. また、次の予約識別子と衝突することもできない:
#       * unpack
#       * pack
#       * struct_length
#       * init_from
__ZSTRUCT_NAME_WHITELIST  = re.compile('^[A-Za-z_][A-Za-z0-9_]*$')
__ZSTRUCT_NAME_BLACKLISTS = [
	re.compile('^__'),
	re.compile('__$'),
	re.compile('^(un)?pack$'),
	re.compile('^struct_length$'),
	re.compile('^init_from$'),
]

#  zstruct 'typedef' 型名の必要要件
#   1. 英字もしくはアンダースコアで始まる
#   2. それより後は英数字もしくはアンダースコア
#  要素名と異なりこれ以外の要件は無い (この二条件もどちらかといえば混乱を避けるため) が、
#  C の予約語などを避ける方が混乱を避けられるだろう。
__ZSTRUCT_TYPEDEFNAME_WHITELIST  = __ZSTRUCT_NAME_WHITELIST
__ZSTRUCT_TYPEDEFNAME_BLACKLISTS = []

#  zstruct 型指定
#   1. 次の Python 型指定を受け入れる
#       * c, ?
#       * b, B, h, H, i, I, l, L, q, Q
#   2. 次の C/C++ 型指定を受け入れる (ただし型名内の空白と指定される部分は厳密に1個の空白であること)
#       * char, signed char, unsigned char
#       * short, short int, signed short, signed short int, unsigned short, unsigned short int
#       * int, signed int, unsigned int
#       * long, long int, signed long, signed long int, unsigned long, unsigned long int
#       * long long, long long int, signed long long, signed long long int, unsigned long long, unsigned long long int
#       * int8_t, int16_t, int32_t, int64_t
#       * uint8_t, uint16_t, uint32_t, uint64_t
#       * bool
#   3. 次の C99 型指定を受け入れる
#       * _Bool
__ZSTRUCT_TYPE_SPECIFIER = re.compile('(\\[[\s]*([1-9][0-9]*)[\s]*][\s]*)?([cbBhHiIlLqQ?]|((un)?signed )?char|((un)?signed )?short( int)?|((un)?signed )?int|((un)?signed )?long( int)?|((un)?signed )?long long( int)?|(u)?int(8|16|32|64)_t|_Bool|bool|:.*)')
__ZSTRUCT_TYPES = {
	'c': 'c',
	'b': 'b',
	'B': 'B',
	'h': 'h',
	'H': 'H',
	'i': 'i',
	'I': 'I',
	'l': 'l',
	'L': 'L',
	'q': 'q',
	'Q': 'Q',
	'?': '?',
	'char': 'c',
	'signed char': 'b',
	'unsigned char': 'B',
	'short': 'h',
	'signed short': 'h',
	'unsigned short': 'H',
	'short int': 'h',
	'signed short int': 'h',
	'unsigned short int': 'H',
	'int': 'i',
	'signed int': 'i',
	'unsigned int': 'I',
	'long': 'l',
	'signed long': 'l',
	'unsigned long': 'L',
	'long int': 'l',
	'signed long int': 'l',
	'unsigned long int': 'L',
	'long long': 'q',
	'signed long long': 'q',
	'unsigned long long': 'Q',
	'long long int': 'q',
	'signed long long int': 'q',
	'unsigned long long int': 'Q',
	'int8_t': 'b',
	'uint8_t': 'B',
	'int16_t': 'h',
	'uint16_t': 'H',
	'int32_t': 'i',
	'uint32_t': 'I',
	'int64_t': 'q',
	'uint64_t': 'Q',
	'_Bool': '?',
	'bool': '?',
}
__ZSTRUCT_TYPE_SIZES = {
	'c': 1,
	'b': 1,
	'B': 1,
	'?': 1,
	'h': 2,
	'H': 2,
	'i': 4,
	'I': 4,
	'l': 4,
	'L': 4,
	'q': 8,
	'Q': 8,
}

#  zstruct は次のエンディアンをサポートする
#   1. ネイティブエンディアン (プラットフォーム依存でリトルもしくはビッグ)
#   2. リトルエンディアン
#   3. ビッグエンディアン
__ZSTRUCT_ENDIANS = [ '=', '<', '>' ]
ENDIAN_NATIVE = 0
ENDIAN_LITTLE = 1
ENDIAN_BIG    = 2

def zstruct(*args, **kwargs):
	if len(args) == 0 and 'members' not in kwargs:
		raise ValueError('構造体のメンバーを与える必要があります。')
	if len(args)  > 0 and 'member'      in kwargs:
		raise ValueError('構造体のメンバーを二度与えることはできません。')
	if len(args) == 0:
		members = kwargs['members']
	else:
		members = args
	typedefs = {}
	if 'typedefs' in kwargs:
		ttypedefs = kwargs['typedefs']
		for zname in ttypedefs.keys():
			ztype = ttypedefs[zname]
			# 'typedef' 名のチェック
			if not __ZSTRUCT_TYPEDEFNAME_WHITELIST.match(zname):
				raise ValueError('`{}\': typedef エイリアス名が無効です。'.format(zname))
			for black in __ZSTRUCT_TYPEDEFNAME_BLACKLISTS:
				if black.match(zname):
					raise ValueError('`{}\': typedef エイリアス名が無効な文字列を含むか予約語を含みます。'.format(zname))
			# 'typedef' 型指定
			tspec = __ZSTRUCT_TYPE_SPECIFIER.fullmatch(ztype)
			if not tspec:
				raise ValueError('`{}\': typedef エイリアスの型指定が不正です。'.format(zname))
			if tspec.group(3)[0] == ':':
				raise ValueError('`{}\': typedef エイリアスは typedef を参照することができません。'.format(zname))
			# 'typedef' 型名を追加
			typedefs[zname] = tspec
	ynames  = []
	yarray  = []
	yformat = ''
	yendian = ENDIAN_NATIVE
	ylength = 0
	if 'default_endian' in kwargs:
		yendian = kwargs['default_endian']
	names = set()
	for member in members:
		if type(member) != tuple:
			raise ValueError('構造体メンバー指定は長さ 2 の tuple の連続 (配列) でなければなりません。')
		if len(member) != 2:
			raise ValueError('構造体メンバー指定の要素は長さ 2 の tuple でなければなりません。')
		zname = member[0]
		ztype = member[1]
		# メンバー名のチェック (None の場合、メンバーは破棄されることを意味する)
		if zname is not None:
			if zname in names:
				raise ValueError('`{}\': 構造体メンバーは重複する名前を持つことができません。'.format(zname))
			if not __ZSTRUCT_NAME_WHITELIST.match(zname):
				raise ValueError('`{}\': 構造体メンバー名が不正です。'.format(zname))
			for black in __ZSTRUCT_NAME_BLACKLISTS:
				if black.match(zname):
					raise ValueError('`{}\': 構造体メンバー名が無効な文字列を含むか予約語を含みます。'.format(zname))
			names.add(zname)
		ynames.append(zname)
		# メンバー型指定のチェック
		tspec = __ZSTRUCT_TYPE_SPECIFIER.fullmatch(ztype)
		if not tspec:
			raise ValueError('`{}\': 構造体メンバーの型指定が無効です。'.format(zname))
		tslen = tspec.group(2)
		ttype = tspec.group(3)
		if ttype[0] == ':':

			# 'typedef' 名の解決
			aname = ttype[1:]
			aspec = typedefs[aname]
			if tslen:
				if aspec.group(2):
					raise ValueError('`{}\': 配列の配列は現状サポートされていません。'.format(zname))
				ttype = aspec.group(3)
			else:
				tslen = aspec.group(2)
				ttype = aspec.group(3)
		# Resolve member type specification
		ttype = __ZSTRUCT_TYPES[ttype]
		if tslen:
			zlength = int(tslen)
			yformat += tslen
			yarray.append(zlength)
			ylength += zlength * __ZSTRUCT_TYPE_SIZES[ttype]
		else:
			yarray.append(0)
			ylength += __ZSTRUCT_TYPE_SIZES[ttype]
		yformat += ttype
	def zstruct_main(cls):
		setattr(cls, '__struct_names__',  ynames)
		setattr(cls, '__struct_array__',  yarray)
		setattr(cls, '__struct_format__', yformat)
		setattr(cls, '__struct_endian__', yendian)
		setattr(cls, 'struct_length', ylength)
		def class_init(self):
			xnames  = self.__struct_names__
			xarray  = self.__struct_array__
			for i in range(len(xnames)):
				if xnames[i] is None:
					continue
				if xarray[i]:
					setattr(self, xnames[i], xarray[i] * [0])
				else:
					setattr(self, xnames[i], 0)
		def class_unpack(self, data, **kwargs0):
			if not isinstance(data, (bytes, bytearray)):
				raise ValueError('unpack にはバイト列が必要です。')
			xnames  = self.__struct_names__
			xarray  = self.__struct_array__
			xendian = self.__struct_endian__
			if 'endian' in kwargs0:
				xendian = kwargs0['endian']
			data = struct.unpack(__ZSTRUCT_ENDIANS[xendian] + self.__struct_format__, data)
			j = 0
			for i in range(len(xnames)):
				xname = xnames[i]
				l = xarray[i]
				if xname is not None:
					if l:
						setattr(self, xnames[i], data[j:j+l])
					else:
						setattr(self, xnames[i], data[j])
				j += l if l else 1
		def class_pack(self, **kwargs0):
			xnames  = self.__struct_names__
			xarray  = self.__struct_array__
			xendian = self.__struct_endian__
			if 'endian' in kwargs0:
				xendian = kwargs0['endian']
			args0 = []
			for i in range(len(xnames)):
				l = xarray[i]
				if xnames[i] is None:
					for j in range(l if l else 1):
						args0.append(0)
				else:
					if l:
						args0.extend(getattr(self, xnames[i]))
					else:
						args0.append(getattr(self, xnames[i]))
			return struct.pack(__ZSTRUCT_ENDIANS[xendian] + self.__struct_format__, *args0)
		def class_repr(self):
			xnames  = self.__struct_names__
			xarray  = self.__struct_array__
			xlen = max([len(x) if x else 1 for x in xnames])
			fmt0 = '\t{0:' + str(xlen) + 's} = '
			s = type(self).__name__ + ' {\n'
			for i in range(len(xnames)):
				if not xnames[i]:
					continue
				s += fmt0.format(xnames[i])
				if xarray[i]:
					s += '[ '
					for v in getattr(self, xnames[i]):
						s += str(v)
						s += ', '
					s += ']\n'
				else:
					s += str(getattr(self, xnames[i]))
					s += '\n'
			s += '}'
			return s
		@classmethod
		def class_init_from(cls, data, **kwargs):
			o = cls()
			o.unpack(data, **kwargs)
			return o
		prefix = '_' + cls.__name__.lstrip('_') + '__internal_'
		def set_attr(name, func):
			setattr(cls, prefix + name, func)
			if not hasattr(cls, name):
				setattr(cls, name, func)
		if not ('override_init' in kwargs and kwargs['override_init']):
			setattr(cls, '__init__', class_init)
		if not ('override_repr' in kwargs and kwargs['override_repr']):
			setattr(cls, '__repr__', class_repr)
		setattr(cls, prefix + 'init', class_init)
		setattr(cls, prefix + 'repr', class_repr)
		set_attr('unpack', class_unpack)
		set_attr('pack',   class_pack)
		setattr(cls, 'init_from', class_init_from)
		return cls
	return zstruct_main
