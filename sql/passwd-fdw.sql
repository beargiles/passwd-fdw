/*
 * Author: Bear Giles <bgiles@coyotesong.com>
 * Created at: 2015-08-10 07:51:27 -0600
 *
 */

CREATE FUNCTION passwd_fdw_handler()
RETURNS fdw_handler
AS 'passwd_fdw', 'passwd_fdw_handler'
LANGUAGE C STRICT;

CREATE FUNCTION passwd_fdw_validator(text[], oid) RETURNS void
AS 'passwd_fdw', 'passwd_fdw_validator'
LANGUAGE C STRICT;

--
-- Define Foreign Data Wrapper (FDW)
--
CREATE FOREIGN DATA WRAPPER passwd_fdw
HANDLER passwd_fdw_handler
VALIDATOR passwd_fdw_validator;

--
-- Define server
--
CREATE SERVER passwd_svr FOREIGN DATA WRAPPER passwd_fdw;

--
-- Define standard 'password' table.
--
CREATE FOREIGN TABLE etc_passwd(
   name   text, -- unique not null
   passwd text,
   uid    int, -- unique not null
   gid    int, -- not null
   gecos  text, -- not null
   dir    text, -- not null
   shell  text -- not null
) SERVER passwd_svr OPTIONS (file 'passwd');

--
-- Define standard 'group' table.
--
CREATE FOREIGN TABLE etc_group(
   name    text, -- unique not null
   gid     int, -- unique not null
   members text[]
) SERVER passwd_svr OPTIONS (file 'group');


--
-- Define user mapping
--
CREATE USER MAPPING FOR bgiles SERVER passwd_svr;
