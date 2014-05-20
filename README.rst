===
BTA
===

About BTA
=========

BTA is an open-source Active Directory security audit framework. Its goal is to help
auditors harvest the information they need to answer such questions as:

* Who has rights over a given object (computer, user account, etc.) ?
* Who can read a given mailbox ?
* Which are the accounts with domain admin rights ?
* Who has extended rights (``userForceChangePassword``, ``SendAs``, etc.) ?
* What are the changes done on an AD between two points in time ?

The framework is made of

* an importer able to translate a ``ntds.dit`` file, containing all the AD data, into a database
* tools to query the database

  + AD miner framework
  + AD diff utility
  + small utilities (list of databases, etc.)


The comprehensive set of attributes are imported and can be querried
including all schema extensions (Exchange, Sharepoint, etc.).

Each question can be crystallized by an AD expert as a miner, so that
it can be used during all audits without doing the hard work again.

Installing BTA
==============

Dependencies:

* mongodb (``apt-get install mongodb-server python-pymongo``)
* libesedb http://code.google.com/p/libesedb/
* openpyxl (>= 2.0.2)

Installation:

* ``python setup.py install`` 

Active Directory Security Analysis
==================================

Goal:

* Clean an AD or an AD forest, looking for

  + bad practices
  + forgotten entries
  + backdoors
  + recompromissions


* BTA is an operationnal tool, ought to be

  + deterministic, reliable
  + running a well established procedure


Protocol
========

Audit steps:

#. Extract  the ``ntds.dit`` file
#. Import the ``ntds.dit`` file in a database
#. Look for control points in the database

Extraction
----------


Here is a way to backup NTDS.dit file for a domain controller which is running on Windows 2008.
See [#SSTIC]_ for more information or for Windows 2003 method.

.. code-block ::

 ntdsutil
 activate instance ntds
 ifm
 create full c:{\bs}NTDS_saved
 quit
 quit


.. [#SSTIC] https://www.sstic.org/2012/presentation/audit_ace_active_directory/

Importing
---------

* ``ntds.dit`` is unusable as-is. 
* one ``ntds.dit`` is imported into one MongoDB *database*
* ability to import several ``ntds.dit`` in parallel

Examples:

.. code-block ::

 ntds2db -C ::mydb /path/to/ntds.dit
 ntds2db /path/to/*.dit  --multi             \
   --C-from-filename                         \ 
      "::%s" "basename rmext 'DB' swap plus"


Analysing
---------

* Querying the database

  + analysing control points of a database: **btaminer**
  + analysing differences between 2 bases: **btadiff**


Analysing control points
------------------------

* miners crystallize expertise

  + list of admin accounts
  + list of accounts with extended rights
  + list of accounts with password errors
  + list of various timelines

.. code-block ::

  btaminer -t ReST -C ::AD1 Schema --timelineCS created

  Analysis by miner [Schema]
  ==========================

  +---------------+-----------------------+
  | Date          | Affected class schema |
  +===============+=======================+
  | 2009-02-11 18 | 234                   |
  | 2011-12-20 00 | 267                   |
  | 2011-12-22 14 | 3                     |
  | 2011-12-23 18 | 46                    |
  +---------------+-----------------------+



Analysing differences
=====================

* diff

  + diff (naive for the moment) between 2 imports at different points in time
  + noise filtering

.. code-block ::

  $ btadiff --CA ::ADclean --CB ::ADbackdoor --ignore-defaults
  ===============
  Starting diffing sd_table
  ---------------
  AB,101: [] *sd_refcount['14'=>'15']
  AB,108: [] *sd_refcount['39'=>'41']
  A ,229: []
  A ,372: []
  AB,423: [] *sd_refcount['3'=>'2']
   B,424: []
   B,425: []
   B,428: []
  ---------------
  Table [sd_table]: 160 records checked, 2 disappeared, 3 appeared, 3 changed
  ===============
  [...]


.. code-block ::

  ===============
  Starting diffing datatable
  ---------------
  AB,3586: [DC001] *logonCount['116'=>'117'], *lastLogon['130052518207794051L'=>'130052535716737649L']
  AB,3639: [RID Set] *rIDNextRID['1153'=>'1154']
  AB,8784: [A:[gc]/B:[gc  DEL:346bf199-8567-4375-ac15-79ec4b42b270]] +isDeleted, 
           *name["u'gc'"=>"u'gc\\nDEL:346bf199-8"], *dc["u'gc'"=>"u'gc\\nDEL:346bf199-8"]
  AB,8785: [A:[DomainDnsZones]/B:[DomainDnsZones  DEL:58b2962b-708c-4c93-99ff-0b7e163131f9]]
           +isDeleted, *name["u'DomainDnsZones'"=>"u'DomainDnsZones\\nDE"], 
           *dc["u'DomainDnsZones'"=>"u'DomainDnsZones\\nDE"]
  AB,8786: [A:[ForestDnsZones]/B:[ForestDnsZones  DEL:87f7d8a2-4d05-48d0-8283-9ab084584470]]
           +isDeleted, *name["u'ForestDnsZones'"=>"u'ForestDnsZones\\nDE"], 
           *dc["u'ForestDnsZones'"=>"u'ForestDnsZones\\nDE"]
   B,8789: [snorky insomnihack]
   B,8790: [gc]
   B,8791: [DomainDnsZones]
   B,8792: [ForestDnsZones]
  ---------------
  Table [datatable]: 7636 records checked, 0 disappeared, 4 appeared, 5 changed
  ===============
  



Other features
==============

* can give reports in different formats:

  + live dump
  + ReST document
  + zipped tree of CSV files

* audit log of writings in a database
* table consistency checks before *mining*

Authors
=======

* Airbus Group CERT
* Airbus Group Innovations
* Airbus DS CyberSecurity

