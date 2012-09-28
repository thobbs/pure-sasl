#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

import puresasl

setup(name='pure-sasl',
      version=puresasl.__version__,
      author='Tyler Hobbs',
      author_email='tylerlhobbs@gmail.com',
      description='Pure Python client SASL implementation',
      url='http://github.com/thobbs/pure-sasl',
      keywords='sasl',
      packages=['puresasl'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Topic :: Software Development :: Libraries :: Python Modules'
      ]
    )
