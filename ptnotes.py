#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging

import ptnotes.importscan

logging.basicConfig(filename='server.log', level=logging.DEBUG)
log = logging.getLogger('SERVER')

i = ptnotes.importscan.Import('test.nessus')
