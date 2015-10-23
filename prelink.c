/*
 * Copyright (C) 2015 Ross Lagerwall <ross.lagerwall@citrix.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This tool takes a generated patch and a xen-syms file and fills in the
 * undefined symbols (i.e. it does static partial linking).
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <argp.h>
#include <error.h>
#include <unistd.h>
#include <gelf.h>

#include "list.h"
#include "lookup.h"
#include "asm/insn.h"
#include "common.h"

char *childobj;
enum loglevel loglevel = NORMAL;

/* Resolve symbols using xen-syms */
void xsplice_resolve_symbols(struct xsplice_elf *kelf,
                            struct lookup_table *table)
{
	struct symbol *sym;
	struct lookup_result result;
	char *curfile = NULL;

	list_for_each_entry(sym, &kelf->symbols, list) {
		/* ignore NULL symbol */
		if (!strlen(sym->name))
			continue;

		if (sym->type == STT_FILE) {
			curfile = sym->name;
			log_debug("Local file is %s\n", curfile);
		}

		if (sym->sec)
			continue;
		if (sym->sym.st_shndx != SHN_UNDEF)
			continue;

		if (sym->bind == STB_LOCAL) {
			if (lookup_local_symbol(table, sym->name,
						curfile, &result))
				ERROR("lookup_local_symbol %s (%s)",
				      sym->name, curfile);
		} else {
			if (lookup_global_symbol(table, sym->name,
						&result))
				ERROR("lookup_global_symbol %s",
				      sym->name);
		}
		log_debug("lookup for %s @ 0x%016lx len %lu\n",
			  sym->name, result.value, result.size);
		sym->sym.st_value = result.value;
		sym->sym.st_shndx = SHN_ABS;
	}
}

struct arguments {
	char *args[3];
	int debug;
};

static char args_doc[] = "original.o resolved.o xen-syms";

static struct argp_option options[] = {
	{"debug", 'd', 0, 0, "Show debug output" },
	{ 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
	   know is a pointer to our arguments structure. */
	struct arguments *arguments = state->input;

	switch (key)
	{
		case 'd':
			arguments->debug = 1;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num >= 3)
				/* Too many arguments. */
				argp_usage (state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 3)
				/* Not enough arguments. */
				argp_usage (state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, 0 };

int main(int argc, char *argv[])
{
	struct xsplice_elf *kelf;
	struct arguments arguments;
	struct lookup_table *lookup;
	struct section *sec, *symtab;

	arguments.debug = 0;
	argp_parse (&argp, argc, argv, 0, 0, &arguments);
	if (arguments.debug)
		loglevel = DEBUG;

	elf_version(EV_CURRENT);

	childobj = basename(arguments.args[0]);

	log_debug("Open elf\n");
	kelf = xsplice_elf_open(arguments.args[0]);

	/* create symbol lookup table */
	log_debug("Lookup xen-syms\n");
	lookup = lookup_open(arguments.args[2]);

	log_debug("Resolve symbols\n");
	xsplice_resolve_symbols(kelf, lookup);

	/*
	 * Update rela section headers and rebuild the rela section data
	 * buffers from the relas lists.
	 */
	symtab = find_section_by_name(&kelf->sections, ".symtab");
	list_for_each_entry(sec, &kelf->sections, list) {
		if (!is_rela_section(sec))
			continue;
		sec->sh.sh_link = symtab->index;
		sec->sh.sh_info = sec->base->index;
		log_debug("Rebuild rela section data for %s\n", sec->name);
		xsplice_rebuild_rela_section_data(sec);
	}

	log_debug("Create shstrtab\n");
	xsplice_create_shstrtab(kelf);
	log_debug("Create strtab\n");
	xsplice_create_strtab(kelf);
	log_debug("Create symtab\n");
	xsplice_create_symtab(kelf);

	log_debug("Dump elf status\n");
	xsplice_dump_kelf(kelf);

	log_debug("Write out elf\n");
	xsplice_write_output_elf(kelf, kelf->elf, arguments.args[1]);

	log_debug("Elf teardown\n");
	xsplice_elf_teardown(kelf);
	log_debug("Elf free\n");
	xsplice_elf_free(kelf);

	return 0;
}
