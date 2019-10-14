0.6.2
=====
October 14th, 2019

* Fix GSSAPI wrapping using in Python 3 (#31)
* Remove Python 2.6 from testing matrix

0.6.1
=====
February 21st, 2019

* Import platform in setup.py

0.6.0
=====
February 21st, 2019

* Add support for Windows via winkerberos (#30)

Thanks to @ryan-pip for this release

0.5.1
=====
May 18th, 2018

* Fixes for DIGEST-MD5, server auth has been completed and is now tested
* Both DIGEST-MD5 and CRAM-MD5 properly set the complete flag now

Thanks to @ceache and @bjmb for this release

0.5.0
=====
March 8th, 2018

* Added EXTERNAL mechanism

0.4.1
=====
March 8th, 2018

* Fix QOP checks in python3 (#19)
* Improved error handling when the kerberos module is not installed (#20)
* Fix python3 bug using auth-conf with GSSAPI (#21)
* Add GSSAPI "extra" with kerberos dependency

0.4.0
=====
February 21st, 2017

* Add support for authorization_id to PlainMechanism and GSSAPIMechanism

0.3.0
=====
September 30th, 2016

* Reintroduce support for MD5DigestMechanism
* Restrict supported QOPs (Quality of Protection) for mechanisms
  up front

0.2.0
=====
February 1st, 2016

* Add support for Python 3
* Add unit tests
* Temporarily disable broken MD5DigestMechanism

0.1.7
=====
February 17th, 2015

* Add wrap and unwrap to PlainMechanism

0.1.6
=====
January 9th, 2015

* Add AUTHZID support for PLAIN mechanism
* Allow GSS to work with older versions of pykerberos

0.1.5
=====
November 15th, 2013

* Fix digest URI order for DigestMD5Mechanism
