#
#
#	z2kit v2 : Security Camp track Z2 : sort of analysis framework
#
#	decisions.py
#	Various decisions (template)
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
import json
import ssdeep
from .decision import Decision
from .features import *

class VTDetectionNameDecision(Decision):
	def __init__(self, scansFile, softwareName, detectionName):
		self.scans = {}
		with open(scansFile, 'r', encoding='utf-8') as f:
			scans = json.load(f)
			for scan in scans:
				self.scans[scan['sha256']] = scan
		self.softwareName  = softwareName
		self.detectionName = detectionName
	def decide(self, data):
		if data.sha256 not in self.scans:
			return False
		scan = self.scans[data.sha256]
		if self.softwareName not in scan['scans']:
			return False
		if not scan['scans'][self.softwareName]['detected']:
			return False
		return scan['scans'][self.softwareName]['result'] == self.detectionName

class BinStringDecision(Decision):
	def __init__(self, pattern):
		self.pattern = pattern
	def decide(self, data):
		x = data.data.find(self.pattern)
		return x != -1

class LstrfuzzyMatchDecision(Decision):
	def __init__(self, fuzzyhash, threshold):
		self.fuzzyhash = fuzzyhash
		self.threshold = threshold
		self.feature   = LstrfuzzyFeature()
	def decide(self, data):
		feature = self.feature.get_feature(data)
		if not feature:
			return False
		return ssdeep.compare(feature, self.fuzzyhash) > self.threshold

class FuzzyHashMatchDecision(Decision):
	def __init__(self, fuzzyhash, threshold):
		self.fuzzyhash = fuzzyhash
		self.threshold = threshold
		self.feature   = FuzzyHashFeature()
	def decide(self, data):
		feature = self.feature.get_feature(data)
		if not feature:
			return False
		return ssdeep.compare(feature, self.fuzzyhash) > self.threshold

class StringsExistenceDecision(Decision):
	def __init__(self, match):
		self.match   = match
		self.feature = StringsFeature()
	def decide(self, data):
		feature = self.feature.get_feature(data)
		return (self.match in feature)

class StringsDecisionFast(Decision):
	def __init__(self, match):
		self.match = match.encode('ASCII')
		self.matchlen = len(self.match)
	def decide(self, data):
		x = data.data.find(self.match)
		if x == -1:
			return False
		if x > 0 and data.data[x-1] >= 0x20 and data.data[x-1] < 0x7f:
			return False
		if x + self.matchlen < len(data.data) and data.data[x+self.matchlen] >= 0x20 and data.data[x+self.matchlen] < 0x7f:
			return False
		return True

class PartialStringsDecisionFast(Decision):
	def __init__(self, match):
		self.match = match.encode('ASCII')
	def decide(self, data):
		return data.data.find(self.match) != -1
