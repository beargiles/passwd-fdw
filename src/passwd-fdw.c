/**
 * Released under postgresql license.
 *
 * Author: Bear Giles <bgiles@coyotesong.com>
 *
 * Inspired by: https://github.com/slaught/dummy_fdw and https://github.com/wikrsh/hello_fdw.
 *
 */
#include "postgres.h"

#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "access/htup_details.h"
#include "access/reloptions.h"
#include "access/sysattr.h"
#include "catalog/pg_foreign_table.h"
#include "commands/copy.h"
#include "commands/defrem.h"
#include "commands/explain.h"
#include "commands/vacuum.h"
#include "foreign/fdwapi.h"
#include "foreign/foreign.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "optimizer/cost.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "optimizer/restrictinfo.h"
#include "optimizer/var.h"
#include "utils/memutils.h"
#include "utils/rel.h"

PG_MODULE_MAGIC
;

/*
 * SQL functions
 */
extern Datum passwd_fdw_handler(PG_FUNCTION_ARGS);
extern Datum passwd_fdw_validator(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(passwd_fdw_handler);
PG_FUNCTION_INFO_V1(passwd_fdw_validator);

/*
 * FDW callback routines
 */
static void passwdGetForeignRelSize(PlannerInfo *root, RelOptInfo *baserel,
		Oid foreigntableid);
static void passwdGetForeignPaths(PlannerInfo *root, RelOptInfo *baserel,
		Oid foreigntableid);
static ForeignScan *passwdGetForeignPlan(PlannerInfo *root, RelOptInfo *baserel,
		Oid foreigntableid, ForeignPath *best_path, List *tlist,
		List *scan_clauses);
static void passwdExplainForeignScan(ForeignScanState *node, ExplainState *es);
static void passwdBeginForeignScan(ForeignScanState *node, int eflags);
static TupleTableSlot *passwdIterateForeignScan(ForeignScanState *node);
static void passwdReScanForeignScan(ForeignScanState *node);
static void passwdEndForeignScan(ForeignScanState *node);
// static bool passwdAnalyzeForeignTable(Relation relation,
//		AcquireSampleRowsFunc *func, BlockNumber *totalpages);

#define BUFLEN 2048

/*
 * State information for FDW calls.
 */
typedef struct passwdFdwState {
	enum Mode {
		PASSWORD_MODE,
		GROUP_MODE
	} mode;
	int min_uid;

	int initialized;
	int rownum;
	int natts;

	// buffer used for getpwent_r() calls.
	int last_ret_value;
	char buf[BUFLEN];
	struct passwd *pwp;
	struct group *grp;

	// field used to map fields to columns.
	enum Field {
		NAME,
		PASSWORD,
		UID,
		GID,
		GECOS,
		DIR,
		SHELL,
		MEMBERS,
		LAST
	};
	int pos[LAST];
} PasswdFdwState;

/*
 * Passwd FDW handler. We only need to provide a few functions since
 * this is a read-only source.
 */
Datum passwd_fdw_handler(PG_FUNCTION_ARGS) {
	FdwRoutine *fdw_routine = makeNode(FdwRoutine);

#if (PG_VERSION_NUM >= 90200)
	fdw_routine->GetForeignRelSize = passwdGetForeignRelSize;
	fdw_routine->GetForeignPaths = passwdGetForeignPaths;
	fdw_routine->GetForeignPlan = passwdGetForeignPlan;
#endif

	fdw_routine->ExplainForeignScan = passwdExplainForeignScan;

	fdw_routine->BeginForeignScan = passwdBeginForeignScan;
	fdw_routine->IterateForeignScan = passwdIterateForeignScan;
	fdw_routine->ReScanForeignScan = passwdReScanForeignScan;
	fdw_routine->EndForeignScan = passwdEndForeignScan;

	// fdw_routine->AnalyzeForeignTable = passwdAnalyzeForeignTable;

	PG_RETURN_POINTER(fdw_routine);
}

/*
 * Passwd FDW validator. There is nothing to validate since the file
 * is in a standard location.
 */
Datum passwd_fdw_validator(PG_FUNCTION_ARGS) {
	PG_RETURN_VOID() ;
}

/*
 * Count the number of password entries. This won't be too expensive
 * if we're accessing a local /etc/passwd but it could become costly
 * if it's backed by LDAP and there are thousands of users.
 */
static void passwdGetForeignRelSize(PlannerInfo *root, RelOptInfo *baserel,
		Oid foreigntableid) {

	PasswdFdwState *state = (PasswdFdwState *) palloc(sizeof(PasswdFdwState));
	struct passwd pw;

	baserel->rows = 0;
	// fixme: handle groups
	setpwent();
	while (getpwent_r(&pw, state->buf, sizeof(state->buf), &state->pwp) == 0) {
		baserel->rows++;
	}
	endpwent();

	pfree(state);
}

/*
 * Create access path for a scan on the foreign table
 */
static void passwdGetForeignPaths(PlannerInfo *root, RelOptInfo *baserel,
		Oid foreigntableid) {
	Path *path;
	int startup_cost = 10;
	int total_cost = 100;
	path = (Path *) create_foreignscan_path(root, baserel, baserel->rows,
			startup_cost, total_cost,
			NIL, // no pathkeys
			NULL, // no outer rel
			NULL);
	add_path(baserel, path);
}

/*
 * Create a ForeignScan plan node
 */
static ForeignScan *
passwdGetForeignPlan(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid,
		ForeignPath *best_path, List *tlist, List *scan_clauses) {
	Index scan_relid = baserel->relid;
	Datum blob = 0;
	Const *blob2 = makeConst(INTERNALOID, 0, 0, sizeof(blob), blob,
	false, false);
	scan_clauses = extract_actual_clauses(scan_clauses, false);
	return make_foreignscan(tlist, scan_clauses, scan_relid, scan_clauses,
			(void *) blob2);
}

/*
 * Give brief explanation.
 */
static void passwdExplainForeignScan(ForeignScanState *node, ExplainState *es) {
	ExplainPropertyText("Passwd", "Scan /etc/passwd", es);
}

/*
 * BeginForeignScan
 *   called during executor startup. perform any initialization
 *   needed, but not start the actual scan.
 */
static void passwdBeginForeignScan(ForeignScanState *node, int eflags) {
	PasswdFdwState *state;
	Relation rel = node->ss.ss_currentRelation;
	AttInMetadata *attinmeta;
	int i;

	if (eflags & EXEC_FLAG_EXPLAIN_ONLY) {
		return;
	}

	state = (PasswdFdwState *) palloc(sizeof(PasswdFdwState));
	state->mode = PASSWORD_MODE;
	state->min_uid = 0;

	state->initialized = 1;
	state->last_ret_value = 0;
	state->rownum = 0;
	state->natts = rel->rd_att->natts;
	node->fdw_state = state;

	for (i = 0; i < LAST; i++) {
		state->pos[i] = -1;
	}

	// cache column mapping.
	attinmeta = TupleDescGetAttInMetadata(rel->rd_att);
	for (i = 0; i < state->natts; i++) {
		char *name = attinmeta->tupdesc->attrs[i]->attname.data;
		switch (tolower(name[0])) {
		case 'd':
			if (!strcasecmp(name, "dir")) {
				state->pos[DIR] = i;
			}
			break;
		case 'g':
			if (!strcasecmp(name, "gecos")) {
				state->pos[GECOS] = i;
			} else if (!strcasecmp(name, "gid")) {
				state->pos[GID] = i;
			}
			break;
		case 'm':
			if (!strcasecmp(name, "members")) {
				state->pos[MEMBERS] = i;
			}
			break;
		case 'n':
			if (!strcasecmp(name, "name")) {
				state->pos[NAME] = i;
			}
			break;
		case 'p':
			if (!strcasecmp(name, "passwd")) {
				state->pos[PASSWORD] = i;
				break;
				case 's':
				if (!strcasecmp(name, "shell")) {
					state->pos[SHELL] = i;
				}
				break;
				case 'u':
				if (!strcasecmp(name, "uid")) {
					state->pos[UID] = i;
				}
				break;
			}
		}
	}

	if (state->mode == PASSWORD_MODE) {
		setpwent();
	} else {
		setgrent();
	}
}

/*
 * Retrieve next password entry.
 */
static TupleTableSlot *
passwdIterateForeignScan(ForeignScanState *node) {
	TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
	PasswdFdwState *state = (PasswdFdwState *) node->fdw_state;
	Relation rel = node->ss.ss_currentRelation;
	AttInMetadata *attinmeta = TupleDescGetAttInMetadata(rel->rd_att);
	HeapTuple tuple;
	struct passwd pw;
	struct group gr;
	int i;
	char **values;

	// check for valid state.
	if (!state->initialized || state->last_ret_value != 0) {
		return NULL;
	}

	// read next entry. Note that we may have to read multple password
	// entries if we have a minimum UID specified.
	if (state->mode == PASSWORD_MODE) {
		do {
			state->last_ret_value = getpwent_r(&pw, state->buf, sizeof(state->buf),
					&state->pwp);
		} while (state->last_ret_value != 0 && pw.pw_uid < state->min_uid);
	} else {
		state->last_ret_value = getgrent_r(&gr, state->buf, sizeof(state->buf),
				&state->grp);
	}

	// check for EOF.
	if (state->last_ret_value != 0) {
		return NULL;
	}
	state->rownum++;

	ExecClearTuple(slot);

	// initialize results to null.
	values = (char **) malloc(state->natts * sizeof(char *));
	for (i = 0; i < state->natts; i++) {
		values[i] = NULL;
	}

	// populate fields.
	if (state->pos[NAME] > -1) {
		values[state->pos[NAME]] =
				(state->mode == PASSWORD_MODE) ? pw.pw_name : gr.gr_name;
	}
	if (state->pos[PASSWORD] > -1) {
		values[state->pos[PASSWORD]] = "*";
	}
	if (state->pos[UID] > -1) {
		if (state->mode == PASSWORD_MODE) {
			char *buf = palloc(10);
			snprintf(buf, 10, "%d", pw.pw_uid);
			values[state->pos[UID]] = buf;
		}
	}
	if (state->pos[GID] > -1) {
		char *buf = palloc(10);
		snprintf(buf, 10, "%d", (state->mode == PASSWORD_MODE) ? pw.pw_gid : gr.gr_gid);
		values[state->pos[GID]] = buf;
	}
	if (state->pos[GECOS] > -1) {
		if (state->mode == PASSWORD_MODE) {
			values[state->pos[GECOS]] = pw.pw_gecos;
		}
	}
	if (state->pos[DIR] > -1) {
		if (state->mode == PASSWORD_MODE) {
			values[state->pos[DIR]] = pw.pw_dir;
		}
	}
	if (state->pos[SHELL] > -1) {
		if (state->mode == PASSWORD_MODE) {
		values[state->pos[SHELL]] = pw.pw_shell;
		}
	}
	if (state->pos[MEMBERS] > -1 && gr.gr_mem != NULL && gr.gr_mem[0] != NULL) {
		if (state->mode == GROUP_MODE) {
		int n, len = 0;
		char *p;
		for (i = 0; gr.gr_mem[i] != NULL; i++) {
			len += strlen(gr.gr_mem[i]) + 3;
		}
		values[state->pos[MEMBERS]] = p = palloc(len);
		*p++ = '{';
		len--;
		for (i = 0; gr.gr_mem[i] != NULL; i++) {
			n = strlen(gr.gr_mem[i]);
			if (n + 1 > len) {
				break;
			}
			strncpy(p, gr.gr_mem[i], n);
			p += n;
			*p++ = ',';
			len -= n + 1;
		}
		p[-1] = '}';
		*p++ = '\0';
		}
	}

	attinmeta = TupleDescGetAttInMetadata(rel->rd_att);
	tuple = BuildTupleFromCStrings(attinmeta, values);
	ExecStoreTuple(tuple, slot, InvalidBuffer, false);

	return slot;
}

/*
 * Reset scan.
 */
static void passwdReScanForeignScan(ForeignScanState *node) {
	PasswdFdwState *state = (PasswdFdwState *) node->fdw_state;

	// check for valid state.
	if (state->initialized) {
		if (state->mode == PASSWORD_MODE) {
			endpwent();
		} else {
			endgrent();
		}
	}

	state->initialized = 1;
	state->last_ret_value = 0;
	state->rownum = 0;

	if (state->mode == PASSWORD_MODE) {
		setpwent();
	} else {
		setgrent();
	}
}

/*
 * End scan and release resources.
 */
static void passwdEndForeignScan(ForeignScanState *node) {
	PasswdFdwState *state = (PasswdFdwState *) node->fdw_state;

	if (state->initialized) {
		if (state->mode == PASSWORD_MODE) {
			endpwent();
		} else {
			endgrent();
		}
	}

	pfree(state);
	node->fdw_state = NULL;
}
