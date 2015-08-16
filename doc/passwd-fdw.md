passwd-fdw
==========

Synopsis
--------

The passwd-fdw and group-fdw extensions provide access to the database server's
user information. This is traditionally /etc/passwd and /etc/group but could
include network resources via LDAP.

Description
-----------

These extensions provide access to the database server's user information.

In a well-managed system there's a 1-to-many relation from the password to
group tables, via the 'gid' field, and a many-to-many relation from the 
group to passwd table, via the 'members' field. This may not be the case 
on a poorly configured system.

There is a third table, 'shell', that contains programs that can be used 
as user shells. The 'shell' field in the password table should only refer
to entries in this table but this is widely violated in practice, esp. for
services.


Usage
-----

We must define the passwd and group tables.
Note: the group table is named 'grp' to avoid collisions with the SQL word.

FIXME: how to pass parameter to FDW to indicate if it's password or group...

```{sql}
CREATE SERVER passwd_svr FOREIGN DATA WRAPPER passwd_fdw;

CREATE FOREIGN TABLE passwd(
   name   text,
   passwd text,
   uid    int,
   gid    int,
   gecos  text,
   dir    text,
   shell  text
) SERVER passwd_svr;

CREATE FOREIGN TABLE grp(
   name    text,
   gid     int,
   members text[]
) SERVER passwd_svr;
```

We can now access the system files via standard SQL queries

```{sql}
$ SELECT * FROM passwd;

       name        | passwd |  uid  |  gid  |               gecos                |            dir             |       shell       
-------------------+--------+-------+-------+------------------------------------+----------------------------+-------------------
 root              | *      |     0 |     0 | root                               | /root                      | /bin/bash
 daemon            | *      |     1 |     1 | daemon                             | /usr/sbin                  | /usr/sbin/nologin
 bin               | *      |     2 |     2 | bin                                | /bin                       | /usr/sbin/nologin
 sys               | *      |     3 |     3 | sys                                | /dev                       | /usr/sbin/nologin
 sync              | *      |     4 | 65534 | sync                               | /bin                       | /bin/sync
 ....
(38 rows)

SELECT * FROM grp;

      name       |  gid  |     members     
-----------------+-------+-----------------
 root            |     0 | 
 daemon          |     1 | 
 bin             |     2 | 
 sys             |     3 | 
 adm             |     4 | {bgiles,syslog}
 ...
 postgres        |   128 | 
(68 rows)
```

It is possible to specify the minimum UID that will be reported in the password table,
typically 1000. This will exclude services.

Security
--------

The password and group tables can reveal sensitive information - valid usernames
with their home directories, installed services, etc. This FDW should only be used
when necessary and, if possible, the min_uid value should be set to a sufficiently
large value to exclude all services.

Support
-------

  There is issues tracker? Github? Put this information here.

Author
------

[Bear Giles <bgiles@coyotesong.com>]

Copyright and License
---------------------

Copyright (c) 2015 Bear Giles <bgiles@coyotesong.com>.

