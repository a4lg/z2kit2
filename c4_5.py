#
#
#	z2kit v2 : Security Camp track Z2 : sort of analysis framework
#
#	c4_5.py
#	Basic (unoptimized) C4.5 implementation
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

class C4_5DecisionBranch:
	def __init__(self, idxOfDecider):
		self.idx = idxOfDecider
		self.gainratio = None
		self.branch0 = None
		self.branch1 = None
	def to_json_object(self):
		o = {}
		o['idx'] = self.idx
		if self.gainratio is not None:
			o['gainratio'] = self.gainratio
		o['b0'] = self.branch0.to_json_object()
		o['b1'] = self.branch1.to_json_object()
		return o
	@staticmethod
	def from_json_object(obj):
		if ('idx' not in obj) and ('value' in obj):
			return C4_5DecisionLeaf.from_json_object(obj)
		branch = C4_5DecisionBranch(obj['idx'])
		if 'gainratio' in branch:
			branch.gainratio = obj['gainratio']
		branch.branch0 = C4_5DecisionBranch.from_json_object(obj['b0'])
		branch.branch1 = C4_5DecisionBranch.from_json_object(obj['b1'])
		return branch

class C4_5DecisionLeaf:
	def __init__(self, value):
		self.value = value
		self.reliability = 1.0
	def to_json_object(self):
		o = {}
		o['value'] = self.value
		if self.reliability != 1.0:
			o['reliability'] = self.reliability
		return o
	@staticmethod
	def from_json_object(obj):
		leaf = C4_5DecisionLeaf(obj['value'])
		if 'reliability' in obj:
			leaf.reliability = obj['reliability']
		return leaf

class C4_5DecisionLearner:
	def __init__(self, teacherObject, decisionObjects):
		self.teacherObject   = teacherObject
		self.decisionObjects = decisionObjects
		self.decisionTree    = None
		self.learnedData     = None
	def clear_learned_data(self):
		self.learnedData = None
	def load_learned_data(self, data):
		self.learnedData = data
	def set_teacher(self, teacherObject):
		self.teacherObject = teacherObject
	def learn(self, inputs):
		if self.teacherObject is None:
			raise ValueError("教師役となる決定器オブジェクトが必要です。")
		if self.decisionObjects is None or len(self.decisionObjects) == 0:
			raise ValueError("学習のためには、決定器オブジェクトの (空でない) 配列を与える必要があります。")
		self.learnedData = []
		for data for inputs:
			decideArray = [ self.teacherObject.decide(data) ]
			for dec in self.decisionObjects:
				decideArray.append(dec.decide(data))
			self.learnedData.append(decideArray)
	def __impurity(self, n0, n1):
		n = n0 + n1
		p0 = float(n0) / n
		p1 = 1.0 - p0
		return -(p0 * math.log(p0,2) + p1 * math.log(p1,2))
	def __make_tree_element(self, data, used_):
		used = set(used_)
		ndecider = len(data[0]) - 1
		ndata    = len(data)
		mgainrat = None
		isplit   = None
		t_count00 = None
		t_count01 = None
		t_count10 = None
		t_count11 = None
		# 教師データの不純度を計算
		countx0  = 0
		countx1  = 0
		for d in data:
			if d[0]:
				countx1 += 1
			else:
				countx0 += 1
		countxx  = ndata
		impurity_teacher = self.__impurity(countx0, countx1)
		# 決定器ごとに計算……
		for i in range(1, ndecider + 1):
			if i in used:
				continue
			count00 = 0
			count01 = 0
			count10 = 0
			count11 = 0
			# 与えられた決定器の不純度を計算
			for d in data:
				if d[i]:
					if d[0]:
						count11 += 1
					else:
						count10 += 1
				else:
					if d[0]:
						count01 += 1
					else:
						count00 += 1
			count0x = count00 + count01
			count1x = count10 + count11
			# 不純度の計算においては、決定器による分割の重み付けを行う
			impurity_decider = \
				float(count0x) / countxx * self.__impurity(count00, count01) + \
				float(count1x) / countxx * self.__impurity(count10, count11)
			# 情報ゲイン (不純度を減らせる量) の計算
			gain_decider = impurity_teacher - impurity_decider
			# 情報ゲイン比の計算 (分割そのものの不純度による情報ゲインの正規化)
			splitinfo_decider = self.__impurity(count0x, count1x)
			gainratio_decider = gain_decider / splitinfo_decider
			# 情報ゲイン比が最大になるものを選択
			if mgainrat is None or gainratio_decider > mgainrat:
				isplit = i
				mgainrat = gainratio_decider
				t_count00 = count00
				t_count01 = count01
				t_count10 = count10
				t_count11 = count11
		# 分割ノードを生成
		used.add(isplit)
		element = C4_5DecisionNode(isplit - 1)
		element.gainratio = mgainrat
		# これ以上分割できない場合、正解率の高い方を適当に選ぶ
		if len(used) == ndecider:
			if t_count00 + t_count11 >= t_count01 + t_count10:
				element.branch0 = C4_5DecisionLeaf(False)
				element.branch1 = C4_5DecisionLeaf(True)
			else:
				element.branch0 = C4_5DecisionLeaf(True)
				element.branch1 = C4_5DecisionLeaf(False)
			return element
		# 教師データに基づいて値を決定
		if   t_count00 == 0:        # 決定器 False, 教師 False のデータが無い (決定器 False の場合、すべて教師 True)
			element.branch0 = C4_5DecisionLeaf(True)
		elif t_count01 == 0:
			element.branch0 = C4_5DecisionLeaf(False)
		else:
			element.branch0 = self.__make_tree_element([x for x in data if x[isplit] == False], used)
		if   t_count10 == 0:
			element.branch1 = C4_5DecisionLeaf(True)
		elif t_count11 == 0:
			element.branch1 = C4_5DecisionLeaf(False)
		else:
			element.branch1 = self.__make_tree_element([x for x in data if x[isplit] == False], used)
		return element
	def make_decision_tree(self):
		if self.learnedData is None:
			raise ValueError("事前に学習させることが必要です。")
		self.decisionTree = self.__make_tree_element(self.learnedData, set())
		return self.decisionTree


class C4_5Decision:
	def __init__(self, decisionObjects, decisionTree):
		self.decisionObjects = decisionObjects
		self.decisionTree    = decisionTree
	def decide(self, data):
		elem = self.decisionTree
		while True:
			if isinstance(elem, C4_5DecisionLeaf):
				return elem.value
			else: # isinstance(elem, C4_5DecisionBranch) == True
				d = self.decisionObjects[elem.idx].decide(data)
				if d:
					elem = elem.branch1
				else:
					elem = elem.branch0
