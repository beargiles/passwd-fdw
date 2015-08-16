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

CREATE FOREIGN DATA WRAPPER passwd_fdw
HANDLER passwd_fdw_handler
VALIDATOR passwd_fdw_validator;
