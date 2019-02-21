#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

import platform
import puresasl
import sys

setup(name='pure-sasl',
      version=puresasl.__version__,
      author='Tyler Hobbs',
      author_email='tylerlhobbs@gmail.com',
      maintainer='Alex Shafer',
      maintainer_email='ashafer01@gmail.com',
      description='Pure Python client SASL implementation',
      long_description=
"""This package provides a reasonably high-level SASL client written
in pure Python.  New mechanisms may be integrated easily, but by default,
support for PLAIN, ANONYMOUS, EXTERNAL, CRAM-MD5, DIGEST-MD5, and GSSAPI are
provided.""",
      license='MIT',
      url='http://github.com/thobbs/pure-sasl',
      keywords='sasl',
      packages=['puresasl'],
      extras_require={
          'GSSAPI':  ["winkerberos==0.7.0"] if platform.system() == 'Windows' else ['kerberos>=1.3.0']
      },
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Topic :: Software Development :: Libraries :: Python Modules'
      ]
    )
