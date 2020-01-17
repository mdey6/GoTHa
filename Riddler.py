#!/usr/bin/env python
# -*- coding: UTF-8 -*-

#########################################################################################################################
# Created on 01/15/2020 by Virag Doshi
# Copyright © 2020 Virag Doshi
#
#########################################################################################################################

import json
import os
import base64
from Crypto import *
from Tar import *
import unittest, random

# The answer to nth puzzle: 				a(n)
# The files for the nth puzzle: 			f(n)
# The hint for the nth puzzle:				ht(n)
# The key to the nth puzzle: 				k(n) = hash(data = a(n-1), salt = ''), k(1) = 0 (Initial key)
# The salt for the nth puzzle:				s(n) = encrypt(key = k(n), data = ht(n))
# The digest of a(n):						h(n) = hash(data = a(n), salt = s(n))
# The encrypted files for the nth puzzle:	ef(n) = encrypt(key = k(n), data = f(n))

# f(n), a(n), ht(n), k(n) -> ef(n), s(n), h(n), k(n+1)


def _getKey(inPrevAns = None):
	return '0' if inPrevAns is None else HashSuite.hash(inPrevAns, '')

def _getDigest(inAns, inSalt):
	return HashSuite.hash(inAns, inSalt)


class Riddler(object):
	def __init__(self, inLevel, inLevelDict, inKey = None):
		assert ('ans' in inLevelDict), "No answer found for the puzzle"
		assert (inLevel > 0), "Level must be greater than 0"
		assert ((inKey is None) is (inLevel is 1)),  ("Key cannot be 0 for level higher than 1" if inLevel is 1 
				 								   	  else "Key cannot be 0 for level higher than 1")

		answer 			= inLevelDict['ans']

		name 			= str(inLevel + 1)

		self.dir 		= name
		self.tarFile	= name + '.tgz'
		self.outFile	= name + '.enctgz'
		
		self.encryptor 	= CipherSuite(_getKey(inKey))

		pepper			= inLevelDict['hint'] if 'hint' in inLevelDict else ''

		assert (len(pepper) <= 128), "pepper too long"

		pepper			= pepper + os.urandom(128 - len(pepper))
		salt 			= self.encryptor.encrypt(pepper)
		self.nextKey 	= _getKey(answer)
		self.dict 		= { 'level' : str(inLevel), 
							'salt' : base64.urlsafe_b64encode(salt), 
							'digest' : base64.urlsafe_b64encode(_getDigest(answer, salt)) }
		
	def getNextKey(self):
		return self.nextKey

	def getInputDirName(self):
		return self.dir

	def encryptFiles(self):
		Tar.tarDir(self.dir, self.tarFile)
		self.encryptor.encryptFile(self.tarFile, self.outFile)

	def getEncDict(self):
		return self.dict


class Solver(object):
	def __init__(self, inLevel, inLevelDict):
		assert ('salt' in inLevelDict), "No salt found"
		assert ('digest' in inLevelDict), "No digest found"
		assert (inLevel > 0), "Level must be greater than 0"

		name 			= str(inLevel + 1)
		self.encFile 	= name + '.enctgz'
		self.tarFile	= name + '.tgz'
		self.outDir		= name

		try:
			self.digest 	= base64.urlsafe_b64decode(inLevelDict['digest'])
		except TypeError:
			assert False, "Incorrect digest"
		try:
			self.salt 		= base64.urlsafe_b64decode(inLevelDict['salt'])
		except TypeError:
			assert False, "Incorrect salt"

	@staticmethod
	def decryptSalt(inSalt, inPrevAns = None):
		return CipherSuite(_getKey(inPrevAns)).decrypt(inSalt)

	def getInputFileName(self):
		return self.encFile

	def isAnswerCorrect(self, inAns):
		return (self.digest == _getDigest(inAns, self.salt))

	def decryptNextFiles(self, inAns):
		CipherSuite(_getKey(inAns)).decryptFiles(self.file, self.tarFile)
		Tar.untar(self.tarFile, self.outDir)
		


#########################################################################################################################
# Testing
#########################################################################################################################


class _RiddlerSolverTests(unittest.TestCase):
	def test_getKey(self):
		self.assertEqual(_getKey(None), '0')
		randomAns = os.urandom(32)
		self.assertEqual(_getKey(randomAns), HashSuite.hash(randomAns, ''))

	def testRiddler(self):
		with self.assertRaises(AssertionError):
			r = Riddler(9, {'ans' : '1234'})
		with self.assertRaises(AssertionError):
			r = Riddler(5, {}, 12)
		with self.assertRaises(AssertionError):
			r = Riddler(1, {'ans' : '1234'}, 32)
		with self.assertRaises(AssertionError):
			r = Riddler(0, {'ans' : '1234'}, 32)
		with self.assertRaises(AssertionError):
			r = Riddler(-5, {'ans' : '1234'}, 32)

		randomAns 		= os.urandom(32)
		randomPepper	= os.urandom(32)
		r = Riddler(1, {'ans' : randomAns, 'hint' : randomPepper})
		self.assertEqual(r.getNextKey(), _getKey(randomAns))
		d = r.getEncDict()
		self.assertEqual('1', d['level'])
		salt = Solver.decryptSalt(base64.urlsafe_b64decode(d['salt']))
		self.assertTrue(randomPepper in salt)
		self.assertTrue(len(salt), 128)
		digest = base64.urlsafe_b64decode(d['digest'])
		self.assertEqual(digest, _getDigest(randomAns, base64.urlsafe_b64decode(d['salt'])))

		randomPepper	= os.urandom(128)
		r = Riddler(1, {'ans' : randomAns, 'hint' : randomPepper})
		d = r.getEncDict()
		salt = Solver.decryptSalt(base64.urlsafe_b64decode(d['salt']))
		self.assertEqual(randomPepper, salt)

		randomAns 		= os.urandom(32)
		randomPepper	= os.urandom(32)
		level 			= random.randint(2, 10)
		key 			= os.urandom(32)
		r = Riddler(level, {'ans' : randomAns, 'hint' : randomPepper}, key)
		self.assertEqual(r.getNextKey(), _getKey(randomAns))
		d = r.getEncDict()
		self.assertEqual(str(level), d['level'])
		salt = Solver.decryptSalt(base64.urlsafe_b64decode(d['salt']), key)
		self.assertTrue(randomPepper in salt)
		self.assertTrue(len(salt), 128)
		digest = base64.urlsafe_b64decode(d['digest'])
		self.assertEqual(digest, _getDigest(randomAns, base64.urlsafe_b64decode(d['salt'])))

	def testSolver(self):
		digest = base64.urlsafe_b64encode(os.urandom(128))
		salt = base64.urlsafe_b64encode(os.urandom(128))
		with self.assertRaises(AssertionError):
			s = Solver(2, {'digest' : digest})
		with self.assertRaises(AssertionError):
			s = Solver(2, {'salt' : salt})
		with self.assertRaises(AssertionError):
			s = Solver(2, {'salt' : '123', 'digest' : digest})
		with self.assertRaises(AssertionError):
			s = Solver(0, {'salt' : salt, 'digest' : digest})
		with self.assertRaises(AssertionError):
			s = Solver(-8, {'salt' : salt, 'digest' : digest})

		randomAns 		= os.urandom(32)
		randomsalt		= os.urandom(128)
		salt = base64.urlsafe_b64encode(randomsalt)
		digest = base64.urlsafe_b64encode(_getDigest(randomAns, randomsalt))
		s = Solver(2, {'level' : '2', 'salt' : salt, 'digest' : digest})
		self.assertFalse(s.isAnswerCorrect(os.urandom(32)))
		self.assertTrue(s.isAnswerCorrect(randomAns))

	def testRiddlerSolver(self):
		randomAns 		= os.urandom(32)
		randomPepper	= os.urandom(32)
		level 			= 1
		key 			= None

		r = Riddler(level, {'ans' : randomAns, 'hint' : randomPepper}, key)
		s = Solver(level, r.getEncDict())

		self.assertEqual(r.dir, s.outDir)
		self.assertEqual(r.tarFile, s.tarFile)
		self.assertEqual(r.outFile, s.encFile)

		self.assertFalse(s.isAnswerCorrect(os.urandom(32)))
		self.assertTrue(s.isAnswerCorrect(randomAns))

		randomAns 		= os.urandom(32)
		randomPepper	= os.urandom(32)
		level 			= random.randint(2, 10)
		key 			= os.urandom(32)

		r = Riddler(level, {'ans' : randomAns, 'hint' : randomPepper}, key)
		s = Solver(level, r.getEncDict())

		self.assertEqual(r.dir, s.outDir)
		self.assertEqual(r.tarFile, s.tarFile)
		self.assertEqual(r.outFile, s.encFile)

		self.assertFalse(s.isAnswerCorrect(os.urandom(32)))
		self.assertTrue(s.isAnswerCorrect(randomAns))		


if __name__ == '__main__':
	random.seed()
	unittest.main()
