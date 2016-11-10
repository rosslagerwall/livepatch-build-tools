/*
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
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

/* Large amounts of this code have been copied from kpatch.
 * The insn directory is copied from kpatch, which was in turn copied
 * from the Linux kernel's arch/x86/lib.
 */

/*
 * This file contains the heart of the ELF object differencing engine.
 *
 * The tool takes two ELF objects from two versions of the same source
 * file; a "base" object and a "patched" object.  These object need to have
 * been compiled with the -ffunction-sections and -fdata-sections GCC options.
 *
 * The tool compares the objects at a section level to determine what
 * sections have changed.  Once a list of changed sections has been generated,
 * various rules are applied to determine any object local sections that
 * are dependencies of the changed section and also need to be included in
 * the output object.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <argp.h>
#include <error.h>
#include <unistd.h>
#include <time.h>
#include <gelf.h>

#include "list.h"
#include "lookup.h"
#include "asm/insn.h"
#include "common.h"

char *childobj;
enum loglevel loglevel = NORMAL;

static void kpatch_compare_elf_headers(Elf *elf1, Elf *elf2)
{
	GElf_Ehdr eh1, eh2;

	if (!gelf_getehdr(elf1, &eh1))
		ERROR("gelf_getehdr");

	if (!gelf_getehdr(elf2, &eh2))
		ERROR("gelf_getehdr");

	if (memcmp(eh1.e_ident, eh2.e_ident, EI_NIDENT) ||
	    eh1.e_type != eh2.e_type ||
	    eh1.e_machine != eh2.e_machine ||
	    eh1.e_version != eh2.e_version ||
	    eh1.e_entry != eh2.e_entry ||
	    eh1.e_phoff != eh2.e_phoff ||
	    eh1.e_flags != eh2.e_flags ||
	    eh1.e_ehsize != eh2.e_ehsize ||
	    eh1.e_phentsize != eh2.e_phentsize ||
	    eh1.e_shentsize != eh2.e_shentsize)
		DIFF_FATAL("ELF headers differ");
}

static void kpatch_check_program_headers(Elf *elf)
{
	size_t ph_nr;

	if (elf_getphdrnum(elf, &ph_nr))
		ERROR("elf_getphdrnum");

	if (ph_nr != 0)
		DIFF_FATAL("ELF contains program header");
}

static void kpatch_mark_grouped_sections(struct kpatch_elf *kelf)
{
	struct section *groupsec, *sec;
	unsigned int *data, *end;

	list_for_each_entry(groupsec, &kelf->sections, list) {
		if (groupsec->sh.sh_type != SHT_GROUP)
			continue;
		data = groupsec->data->d_buf;
		end = groupsec->data->d_buf + groupsec->data->d_size;
		data++; /* skip first flag word (e.g. GRP_COMDAT) */
		while (data < end) {
			sec = find_section_by_index(&kelf->sections, *data);
			if (!sec)
				ERROR("group section not found");
			sec->grouped = 1;
			log_debug("marking section %s (%d) as grouped\n",
			          sec->name, sec->index);
			data++;
		}
	}
}

/*
 * Mangle the relas a little.  The compiler will sometimes use section symbols
 * to reference local objects and functions rather than the object or function
 * symbols themselves.  We substitute the object/function symbols for the
 * section symbol in this case so that the relas can be properly correlated and
 * so that the existing object/function in vmlinux can be linked to.
 */
static void kpatch_replace_sections_syms(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct rela *rela;
	struct symbol *sym;
	int add_off;

	log_debug("\n");

	list_for_each_entry(sec, &kelf->sections, list) {
		if (!is_rela_section(sec) ||
		    is_debug_section(sec))
			continue;

		list_for_each_entry(rela, &sec->relas, list) {

			if (rela->sym->type != STT_SECTION)
				continue;

			/*
			 * Replace references to bundled sections with their
			 * symbols.
			 */
			if (rela->sym->sec && rela->sym->sec->sym) {
				rela->sym = rela->sym->sec->sym;
				continue;
			}

			if (rela->type == R_X86_64_PC32 ||
			    rela->type == R_X86_64_PLT32) {
				struct insn insn;
				rela_insn(sec, rela, &insn);
				add_off = (long)insn.next_byte -
					  (long)sec->base->data->d_buf -
					  rela->offset;
			} else if (rela->type == R_X86_64_64 ||
				   rela->type == R_X86_64_32S)
				add_off = 0;
			else
				continue;

			/*
			 * Attempt to replace references to unbundled sections
			 * with their symbols.
			 */
			list_for_each_entry(sym, &kelf->symbols, list) {
				int start, end;

				if (sym->type == STT_SECTION ||
				    sym->sec != rela->sym->sec)
					continue;

				start = sym->sym.st_value;
				end = sym->sym.st_value + sym->sym.st_size;

				if (!is_text_section(sym->sec) &&
				    (rela->type == R_X86_64_32S ||
				     rela->type == R_X86_64_PC32 ||
				     rela->type == R_X86_64_PLT32) &&
				    (rela->addend + add_off) == sym->sec->sh.sh_size &&
				    end == sym->sec->sh.sh_size) {

					/*
					 * A special case where gcc needs a
					 * pointer to the address at the end of
					 * a data section.
					 *
					 * This is usually used with a compare
					 * instruction to determine when to end
					 * a loop.  The code doesn't actually
					 * dereference the pointer so this is
					 * "normal" and we just replace the
					 * section reference with a reference
					 * to the last symbol in the section.
					 *
					 * Note that this only catches the
					 * issue when it happens at the end of
					 * a section.  It can also happen in
					 * the middle of a section.  In that
					 * case, the wrong symbol will be
					 * associated with the reference.  But
					 * that's ok because:
					 *
					 * 1) This situation only occurs when
					 *    gcc is trying to get the address
					 *    of the symbol, not the contents
					 *    of its data; and
					 *
					 * 2) Because kpatch doesn't allow data
					 *    sections to change,
					 *    &(var1+sizeof(var1)) will always
					 *    be the same as &var2.
					 */

				} else if (rela->addend + add_off < start ||
					   rela->addend + add_off >= end)
					continue;

				log_debug("%s: replacing %s+%d reference with %s+%d\n",
					  sec->name,
					  rela->sym->name, rela->addend,
					  sym->name, rela->addend - start);

				rela->sym = sym;
				rela->addend -= start;
				break;
			}
		}
	}
	log_debug("\n");
}

/*
 * This is like strcmp, but for gcc-mangled symbols.  It skips the comparison
 * of any substring which consists of '.' followed by any number of digits.
 */
static int kpatch_mangled_strcmp(char *s1, char *s2)
{
	while (*s1 == *s2) {
		if (!*s1)
			return 0;
		if (*s1 == '.' && isdigit(s1[1])) {
			if (!isdigit(s2[1]))
				return 1;
			while (isdigit(*++s1))
				;
			while (isdigit(*++s2))
				;
		} else {
			s1++;
			s2++;
		}
	}
	return 1;
}

/*
 * When gcc makes compiler optimizations which affect a function's calling
 * interface, it mangles the function's name.  For example, sysctl_print_dir is
 * renamed to sysctl_print_dir.isra.2.  The problem is that the trailing number
 * is chosen arbitrarily, and the patched version of the function may end up
 * with a different trailing number.  Rename any mangled patched functions to
 * match their base counterparts.
 */
static void kpatch_rename_mangled_functions(struct kpatch_elf *base,
				            struct kpatch_elf *patched)
{
	struct symbol *sym, *basesym;
	char name[256], *origname;
	struct section *sec, *basesec;
	int found;

	list_for_each_entry(sym, &patched->symbols, list) {
		if (sym->type != STT_FUNC)
			continue;

		if (!strstr(sym->name, ".isra.") &&
		    !strstr(sym->name, ".constprop.") &&
		    !strstr(sym->name, ".part."))
			continue;

		found = 0;
		list_for_each_entry(basesym, &base->symbols, list) {
			if (!kpatch_mangled_strcmp(basesym->name, sym->name)) {
				found = 1;
				break;
			}
		}

		if (!found)
			continue;

		if (!strcmp(sym->name, basesym->name))
			continue;

		log_debug("renaming %s to %s\n", sym->name, basesym->name);
		origname = sym->name;
		sym->name = strdup(basesym->name);

		if (sym != sym->sec->sym)
			continue;

		sym->sec->name = strdup(basesym->sec->name);
		if (sym->sec->rela)
			sym->sec->rela->name = strdup(basesym->sec->rela->name);

		/*
		 * When function foo.isra.1 has a switch statement, it might
		 * have a corresponding bundled .rodata.foo.isra.1 section (in
		 * addition to .text.foo.isra.1 which we renamed above).
		 */
		sprintf(name, ".rodata.%s", origname);
		sec = find_section_by_name(&patched->sections, name);
		if (!sec)
			continue;
		sprintf(name, ".rodata.%s", basesym->name);
		basesec = find_section_by_name(&base->sections, name);
		if (!basesec)
			continue;
		sec->name = strdup(basesec->name);
		sec->secsym->name = sec->name;
		if (sec->rela)
			sec->rela->name = strdup(basesec->rela->name);
	}
}

/*
 * This function detects whether the given symbol is a "special" static local
 * variable (for lack of a better term).
 *
 * Special static local variables should never be correlated and should always
 * be included if they are referenced by an included function.
 */
static int is_special_static(struct symbol *sym)
{
	static char *prefixes[] = {
		"__key.",
		"__warned.",
		"descriptor.",
		"__func__.",
		"_rs.",
		NULL,
	};
	char **prefix;

	if (!sym)
		return 0;

	if (sym->type == STT_SECTION) {
		/* __verbose section contains the descriptor variables */
		if (!strcmp(sym->name, "__verbose"))
			return 1;

		/* otherwise make sure section is bundled */
		if (!sym->sec->sym)
			return 0;

		/* use bundled object/function symbol for matching */
		sym = sym->sec->sym;
	}

	if (sym->type != STT_OBJECT || sym->bind != STB_LOCAL)
		return 0;

	for (prefix = prefixes; *prefix; prefix++)
		if (!strncmp(sym->name, *prefix, strlen(*prefix)))
			return 1;

	return 0;
}

static int is_constant_label(struct symbol *sym)
{
	const char *str;

	if (sym->bind != STB_LOCAL)
		return 0;

	if (strncmp(sym->name, ".LC", 3))
		return 0;

	str = sym->name + 3;
	do {
		if (!isdigit(*str))
			return 0;
	} while (*++str);

	return 1;
}

static void kpatch_correlate_sections(struct list_head *seclist1,
				      struct list_head *seclist2)
{
	struct section *sec1, *sec2;

	list_for_each_entry(sec1, seclist1, list) {
		list_for_each_entry(sec2, seclist2, list) {
			if (strcmp(sec1->name, sec2->name))
				continue;

			if (is_special_static(is_rela_section(sec1) ?
					      sec1->base->secsym :
					      sec1->secsym))
				continue;

			/*
			 * Group sections must match exactly to be correlated.
			 * Changed group sections are currently not supported.
			 */
			if (sec1->sh.sh_type == SHT_GROUP) {
				if (sec1->data->d_size != sec2->data->d_size)
					continue;
				if (memcmp(sec1->data->d_buf, sec2->data->d_buf,
				           sec1->data->d_size))
					continue;
			}
			log_debug("Found section twins: %s\n", sec1->name);
			sec1->twin = sec2;
			sec2->twin = sec1;
			/* set initial status, might change */
			sec1->status = sec2->status = SAME;
			break;
		}
	}
}

static void kpatch_correlate_symbols(struct list_head *symlist1,
				     struct list_head *symlist2)
{
	struct symbol *sym1, *sym2;

	list_for_each_entry(sym1, symlist1, list) {
		list_for_each_entry(sym2, symlist2, list) {
			if (strcmp(sym1->name, sym2->name) ||
			    sym1->type != sym2->type)
				continue;

			if (is_special_static(sym1))
				continue;

			if (is_constant_label(sym1))
				continue;

			/* group section symbols must have correlated sections */
			if (sym1->sec &&
			    sym1->sec->sh.sh_type == SHT_GROUP &&
			    sym1->sec->twin != sym2->sec)
				continue;

			log_debug("Found symbol twins: %s\n", sym1->name);
			sym1->twin = sym2;
			sym2->twin = sym1;
			/* set initial status, might change */
			sym1->status = sym2->status = SAME;
			break;
		}
	}
}

static void kpatch_correlate_elfs(struct kpatch_elf *kelf1,
				  struct kpatch_elf *kelf2)
{
	kpatch_correlate_sections(&kelf1->sections, &kelf2->sections);
	kpatch_correlate_symbols(&kelf1->symbols, &kelf2->symbols);
}

static char *kpatch_section_function_name(struct section *sec)
{
	if (is_rela_section(sec))
		sec = sec->base;
	return sec->sym ? sec->sym->name : sec->name;
}

/*
 * Given a static local variable symbol and a rela section which references it
 * in the base object, find a corresponding usage of a similarly named symbol
 * in the patched object.
 */
static struct symbol *kpatch_find_static_twin(struct section *sec,
					      struct symbol *sym)
{
	struct rela *rela;

	if (!sec->twin)
		return NULL;

	/* find the patched object's corresponding variable */
	list_for_each_entry(rela, &sec->twin->relas, list) {

		if (rela->sym->twin)
			continue;

		if (kpatch_mangled_strcmp(rela->sym->name, sym->name))
			continue;

		return rela->sym;
	}

	return NULL;
}

/*
 * gcc renames static local variables by appending a period and a number.  For
 * example, __foo could be renamed to __foo.31452.  Unfortunately this number
 * can arbitrarily change.  Correlate them by comparing which functions
 * reference them, and rename the patched symbols to match the base symbol
 * names.
 */
void kpatch_correlate_static_local_variables(struct kpatch_elf *base,
					     struct kpatch_elf *patched)
{
	struct symbol *sym, *patched_sym, *tmpsym;
	struct section *sec;
	struct rela *rela;
	int bundled, patched_bundled;

	list_for_each_entry(sym, &base->symbols, list) {

		if (sym->type != STT_OBJECT || sym->bind != STB_LOCAL)
			continue;

		if (!strchr(sym->name, '.'))
			continue;

		if (is_special_static(sym))
			continue;

		/*
		 * Undo any previous correlation.  Two static locals can have
		 * the same numbered suffix in the base and patched objects by
		 * coincidence.
		 */
		if (sym->twin) {
			sym->twin->twin = NULL;
			sym->twin = NULL;
		}
		bundled = sym == sym->sec->sym;
		if (bundled && sym->sec->twin) {
			sym->sec->twin->twin = NULL;
			sym->sec->twin = NULL;
		}

		/*
		 *
		 * Some surprising facts about static local variable symbols:
		 *
		 * - It's possible for multiple functions to use the same
		 *   static local variable if the variable is defined in an
		 *   inlined function.
		 *
		 * - It's also possible for multiple static local variables
		 *   with the same name to be used in the same function if they
		 *   have different scopes.  (We have to assume that in such
		 *   cases, the order in which they're referenced remains the
		 *   same between the base and patched objects, as there's no
		 *   other way to distinguish them.)
		 *
		 * - Static locals are usually referenced by functions, but
		 *   they can occasionally be referenced by data sections as
		 *   well.
		 *
		 * For each section which references the variable in the base
		 * object, look for a corresponding reference in the section's
		 * twin in the patched object.
		 */
		patched_sym = NULL;
		list_for_each_entry(sec, &base->sections, list) {

			if (!is_rela_section(sec) ||
			    is_debug_section(sec))
				continue;

			list_for_each_entry(rela, &sec->relas, list) {

				if (rela->sym != sym)
					continue;

				if (bundled && sym->sec == sec->base) {
					/*
					 * A rare case where a static local
					 * data structure references itself.
					 * There's no reliable way to correlate
					 * this.  Hopefully there's another
					 * reference to the symbol somewhere
					 * that can be used.
					 */
					log_debug("can't correlate static local %s's reference to itself\n",
						  sym->name);
					break;
				}

				tmpsym = kpatch_find_static_twin(sec, sym);
				if (!tmpsym)
					DIFF_FATAL("reference to static local variable %s in %s was removed",
						   sym->name,
						   kpatch_section_function_name(sec));

				if (patched_sym && patched_sym != tmpsym)
					DIFF_FATAL("found two twins for static local variable %s: %s and %s",
						   sym->name, patched_sym->name,
						   tmpsym->name);

				patched_sym = tmpsym;

				break;
			}
		}

		/*
		 * Check if the symbol is unused.  This is possible if multiple
		 * static locals in the file refer to the same read-only data,
		 * and their symbols point to the same bundled section.  In
		 * such a case we can ignore the extra symbol.
		 */
		if (!patched_sym) {
			log_debug("ignoring base unused static local %s\n",
				  sym->name);
			continue;
		}

		patched_bundled = patched_sym == patched_sym->sec->sym;
		if (bundled != patched_bundled)
			ERROR("bundle mismatch for symbol %s", sym->name);
		if (!bundled && sym->sec->twin != patched_sym->sec)
			ERROR("sections %s and %s aren't correlated",
			      sym->sec->name, patched_sym->sec->name);

		log_debug("renaming and correlating static local %s to %s\n",
			  patched_sym->name, sym->name);

		patched_sym->name = strdup(sym->name);
		sym->twin = patched_sym;
		patched_sym->twin = sym;

		if (bundled) {
			sym->sec->twin = patched_sym->sec;
			patched_sym->sec->twin = sym->sec;

			if (sym->sec->rela && patched_sym->sec->rela) {
				sym->sec->rela->twin = patched_sym->sec->rela;
				patched_sym->sec->rela->twin = sym->sec->rela;
			}
		}
	}

	/*
	 * All the base object's static local variables have been correlated.
	 * Now go through the patched object and look for any uncorrelated
	 * static locals to see if we need to print some warnings.
	 */
	list_for_each_entry(sym, &patched->symbols, list) {

		if (sym->type != STT_OBJECT || sym->bind != STB_LOCAL ||
		    sym->twin)
			continue;

		if (!strchr(sym->name, '.'))
			continue;

		if (is_special_static(sym))
			continue;

		list_for_each_entry(sec, &patched->sections, list) {

			if (!is_rela_section(sec) ||
			    is_debug_section(sec))
				continue;

			list_for_each_entry(rela, &sec->relas, list) {

				if (rela->sym != sym)
					continue;

				log_normal("WARNING: unable to correlate static local variable %s used by %s, assuming variable is new\n",
					   sym->name,
					   kpatch_section_function_name(sec));
				return;
			}
		}

		/*
		 * This symbol is unused by any functions.  This is possible if
		 * multiple static locals in the file refer to the same
		 * read-only data, and their symbols point to the same bundled
		 * section.  In such a case we can ignore the extra symbol.
		 */
		log_debug("ignoring patched unused static local %s\n",
			  sym->name);
	}
}

static int rela_equal(struct rela *rela1, struct rela *rela2)
{
	log_debug("Comparing rela %s with %s\n", rela1->sym->name, rela2->sym->name);
	if (rela1->type != rela2->type ||
	    rela1->offset != rela2->offset)
		return 0;

	if (rela1->string)
		return rela2->string && !strcmp(rela1->string, rela2->string);

	if (rela1->addend != rela2->addend)
		return 0;

	if (is_constant_label(rela1->sym) && is_constant_label(rela2->sym))
		return 1;

	if (is_special_static(rela1->sym))
		return !kpatch_mangled_strcmp(rela1->sym->name,
					      rela2->sym->name);

	return !strcmp(rela1->sym->name, rela2->sym->name);
}

static void kpatch_compare_correlated_rela_section(struct section *sec)
{
	struct rela *rela1, *rela2 = NULL;

	rela2 = list_entry(sec->twin->relas.next, struct rela, list);
	list_for_each_entry(rela1, &sec->relas, list) {
		if (rela_equal(rela1, rela2)) {
			rela2 = list_entry(rela2->list.next, struct rela, list);
			continue;
		}
		sec->status = CHANGED;
		return;
	}

	sec->status = SAME;
}

static void kpatch_compare_correlated_nonrela_section(struct section *sec)
{
	struct section *sec1 = sec, *sec2 = sec->twin;

	if (sec1->sh.sh_type != SHT_NOBITS &&
	    memcmp(sec1->data->d_buf, sec2->data->d_buf, sec1->data->d_size))
		sec->status = CHANGED;
	else
		sec->status = SAME;
}

static void kpatch_compare_correlated_section(struct section *sec)
{
	struct section *sec1 = sec, *sec2 = sec->twin;

	log_debug("Compare correlated section: %s\n", sec->name);

	/* Compare section headers (must match or fatal) */
	if (sec1->sh.sh_type != sec2->sh.sh_type ||
	    sec1->sh.sh_flags != sec2->sh.sh_flags ||
	    sec1->sh.sh_addr != sec2->sh.sh_addr ||
	    sec1->sh.sh_addralign != sec2->sh.sh_addralign ||
	    sec1->sh.sh_entsize != sec2->sh.sh_entsize)
		DIFF_FATAL("%s section header details differ", sec1->name);

	if (sec1->sh.sh_size != sec2->sh.sh_size ||
	    sec1->data->d_size != sec2->data->d_size) {
		sec->status = CHANGED;
		goto out;
	}

	if (is_rela_section(sec))
		kpatch_compare_correlated_rela_section(sec);
	else
		kpatch_compare_correlated_nonrela_section(sec);
out:
	if (sec->status == CHANGED)
		log_debug("section %s has changed\n", sec->name);
}

static void kpatch_compare_sections(struct list_head *seclist)
{
	struct section *sec;

	/* compare all sections */
	list_for_each_entry(sec, seclist, list) {
		if (sec->twin)
			kpatch_compare_correlated_section(sec);
		else
			sec->status = NEW;
	}

	/* sync symbol status */
	list_for_each_entry(sec, seclist, list) {
		if (is_rela_section(sec)) {
			if (sec->base->sym && sec->base->sym->status != CHANGED)
				sec->base->sym->status = sec->status;
		} else {
			if (sec->sym && sec->sym->status != CHANGED)
				sec->sym->status = sec->status;
		}
	}
}

static void kpatch_compare_correlated_symbol(struct symbol *sym)
{
	struct symbol *sym1 = sym, *sym2 = sym->twin;

	if (sym1->sym.st_info != sym2->sym.st_info ||
	    sym1->sym.st_other != sym2->sym.st_other ||
	    (sym1->sec && !sym2->sec) ||
	    (sym2->sec && !sym1->sec))
		DIFF_FATAL("symbol info mismatch: %s", sym1->name);

	/*
	 * If two symbols are correlated but their sections are not, then the
	 * symbol has changed sections.  This is only allowed if the symbol is
	 * moving out of an ignored section.
	 */
	if (sym1->sec && sym2->sec && sym1->sec->twin != sym2->sec) {
		if (sym2->sec->twin && sym2->sec->twin->ignore)
			sym->status = CHANGED;
		else
			DIFF_FATAL("symbol changed sections: %s, %s, %s, %s", sym1->name, sym2->name, sym1->sec->name, sym2->sec->name);
	}

	if (sym1->type == STT_OBJECT &&
	    sym1->sym.st_size != sym2->sym.st_size)
		DIFF_FATAL("object size mismatch: %s", sym1->name);

	if (sym1->sym.st_shndx == SHN_UNDEF ||
	     sym1->sym.st_shndx == SHN_ABS)
		sym1->status = SAME;

	/*
	 * The status of LOCAL symbols is dependent on the status of their
	 * matching section and is set during section comparison.
	 */
}

static void kpatch_compare_symbols(struct list_head *symlist)
{
	struct symbol *sym;

	list_for_each_entry(sym, symlist, list) {
		if (sym->twin)
			kpatch_compare_correlated_symbol(sym);
		else
			sym->status = NEW;

		log_debug("symbol %s is %s\n", sym->name, status_str(sym->status));
	}
}

static void kpatch_compare_correlated_elements(struct kpatch_elf *kelf)
{
	/* lists are already correlated at this point */
	log_debug("Compare sections\n");
	kpatch_compare_sections(&kelf->sections);
	log_debug("Compare symbols\n");
	kpatch_compare_symbols(&kelf->symbols);
}

static void kpatch_mark_ignored_functions_same(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct rela *rela;

	sec = find_section_by_name(&kelf->sections, ".livepatch.ignore.functions");
	if (!sec)
		return;

	list_for_each_entry(rela, &sec->rela->relas, list) {
		if (!rela->sym->sec)
			ERROR("expected bundled symbol");
		if (rela->sym->type != STT_FUNC)
			ERROR("expected function symbol");
		log_normal("ignoring function: %s\n", rela->sym->name);
		if (rela->sym->status != CHANGED)
			log_normal("NOTICE: no change detected in function %s, unnecessary KPATCH_IGNORE_FUNCTION()?\n", rela->sym->name);
		rela->sym->status = SAME;
		rela->sym->sec->status = SAME;
		if (rela->sym->sec->secsym)
			rela->sym->sec->secsym->status = SAME;
		if (rela->sym->sec->rela)
			rela->sym->sec->rela->status = SAME;
	}
}

static void kpatch_mark_ignored_sections(struct kpatch_elf *kelf)
{
	struct section *sec, *strsec, *ignoresec;
	struct rela *rela;
	char *name;

	sec = find_section_by_name(&kelf->sections, ".livepatch.ignore.sections");
	if (!sec)
		return;

	list_for_each_entry(rela, &sec->rela->relas, list) {
		strsec = rela->sym->sec;
		strsec->status = CHANGED;
		/*
		 * Include the string section here.  This is because the
		 * KPATCH_IGNORE_SECTION() macro is passed a literal string
		 * by the patch author, resulting in a change to the string
		 * section.  If we don't include it, then we will potentially
		 * get a "changed section not included" error in
		 * kpatch_verify_patchability() if no other function based change
		 * also changes the string section.  We could try to exclude each
		 * literal string added to the section by KPATCH_IGNORE_SECTION()
		 * from the section data comparison, but this is a simpler way.
		 */
		strsec->include = 1;
		name = strsec->data->d_buf + rela->addend;
		ignoresec = find_section_by_name(&kelf->sections, name);
		if (!ignoresec)
			ERROR("KPATCH_IGNORE_SECTION: can't find %s", name);
		log_normal("ignoring section: %s\n", name);
		if (is_rela_section(ignoresec))
			ignoresec = ignoresec->base;
		ignoresec->ignore = 1;
		if (ignoresec->twin)
			ignoresec->twin->ignore = 1;
	}
}

static void kpatch_mark_ignored_sections_same(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;

	list_for_each_entry(sec, &kelf->sections, list) {
		if (!sec->ignore)
			continue;
		sec->status = SAME;
		if (sec->secsym)
			sec->secsym->status = SAME;
		if (sec->rela)
			sec->rela->status = SAME;
		list_for_each_entry(sym, &kelf->symbols, list) {
			if (sym->sec != sec)
				continue;
			sym->status = SAME;
		}
	}
}

static void kpatch_mark_constant_labels_same(struct kpatch_elf *kelf)
{
	struct symbol *sym;

	list_for_each_entry(sym, &kelf->symbols, list) {
		if (is_constant_label(sym))
			sym->status = SAME;
	}
}

static int bug_frames_0_group_size(struct kpatch_elf *kelf, int offset) { return 8; }
static int bug_frames_1_group_size(struct kpatch_elf *kelf, int offset) { return 8; }
static int bug_frames_2_group_size(struct kpatch_elf *kelf, int offset) { return 8; }
static int bug_frames_3_group_size(struct kpatch_elf *kelf, int offset) { return 16; }
static int ex_table_group_size(struct kpatch_elf *kelf, int offset) { return 8; }
static int altinstructions_group_size(struct kpatch_elf *kelf, int offset) { return 12; }

/*
 * The rela groups in the .fixup section vary in size.  The beginning of each
 * .fixup rela group is referenced by the .ex_table section. To find the size
 * of a .fixup rela group, we have to traverse the .ex_table relas.
 */
static int fixup_group_size(struct kpatch_elf *kelf, int offset)
{
	struct section *sec;
	struct rela *rela;
	int found;

	sec = find_section_by_name(&kelf->sections, ".rela.ex_table");
	if (!sec)
		ERROR("missing .rela.ex_table section");

	/* find beginning of this group */
	found = 0;
	list_for_each_entry(rela, &sec->relas, list) {
		if (!strcmp(rela->sym->name, ".fixup") &&
		    rela->addend == offset) {
				found = 1;
				break;
		}
	}

	if (!found)
		ERROR("can't find .fixup rela group at offset %d\n", offset);

	/* find beginning of next group */
	found = 0;
	list_for_each_entry_continue(rela, &sec->relas, list) {
		if (!strcmp(rela->sym->name, ".fixup") &&
		    rela->addend > offset) {
			found = 1;
			break;
		}
	}

	if (!found) {
		/* last group */
		struct section *fixupsec;
		fixupsec = find_section_by_name(&kelf->sections, ".fixup");
		return fixupsec->sh.sh_size - offset;
	}

	return rela->addend - offset;
}

static struct special_section special_sections[] = {
	{
		.name		= ".bug_frames.0",
		.group_size	= bug_frames_0_group_size,
	},
	{
		.name		= ".bug_frames.1",
		.group_size	= bug_frames_1_group_size,
	},
	{
		.name		= ".bug_frames.2",
		.group_size	= bug_frames_2_group_size,
	},
	{
		.name		= ".bug_frames.3",
		.group_size	= bug_frames_3_group_size,
	},
	{
		.name		= ".fixup",
		.group_size	= fixup_group_size,
	},
	{
		.name		= ".ex_table",
		.group_size	= ex_table_group_size,
	},
	{
		.name		= ".altinstructions",
		.group_size	= altinstructions_group_size,
	},
	{},
};

static int should_keep_rela_group(struct section *sec, int start, int size)
{
	struct rela *rela;
	int found = 0;

	/* check if any relas in the group reference any changed functions */
	list_for_each_entry(rela, &sec->relas, list) {
		if (rela->offset >= start &&
		    rela->offset < start + size &&
		    rela->sym->type == STT_FUNC &&
		    rela->sym->sec->include) {
			found = 1;
			log_debug("new/changed symbol %s found in special section %s\n",
				  rela->sym->name, sec->name);
		}
	}

	return found;
}

static void kpatch_regenerate_special_section(struct kpatch_elf *kelf,
				              struct special_section *special,
				              struct section *sec)
{
	struct rela *rela, *safe;
	char *src, *dest;
	int group_size, src_offset, dest_offset, include, align, aligned_size;

	LIST_HEAD(newrelas);

	src = sec->base->data->d_buf;
	/* alloc buffer for new base section */
	dest = malloc(sec->base->sh.sh_size);
	if (!dest)
		ERROR("malloc");

	group_size = 0;
	src_offset = 0;
	dest_offset = 0;
	for ( ; src_offset < sec->base->sh.sh_size; src_offset += group_size) {

		group_size = special->group_size(kelf, src_offset);
		include = should_keep_rela_group(sec, src_offset, group_size);

		if (!include)
			continue;

		/*
		 * Copy all relas in the group.  It's possible that the relas
		 * aren't sorted (e.g. .rela.fixup), so go through the entire
		 * rela list each time.
		 */
		list_for_each_entry_safe(rela, safe, &sec->relas, list) {
			if (rela->offset >= src_offset &&
			    rela->offset < src_offset + group_size) {
				/* copy rela entry */
				list_del(&rela->list);
				list_add_tail(&rela->list, &newrelas);

				rela->offset -= src_offset - dest_offset;
				rela->rela.r_offset = rela->offset;

				rela->sym->include = 1;
			}
		}

		/* copy base section group */
		memcpy(dest + dest_offset, src + src_offset, group_size);
		dest_offset += group_size;
	}

	/* verify that group_size is a divisor of aligned section size */
	align = sec->base->sh.sh_addralign;
	aligned_size = ((sec->base->sh.sh_size + align - 1) / align) * align;
	if (src_offset != aligned_size)
		ERROR("group size mismatch for section %s\n", sec->base->name);

	if (!dest_offset) {
		/* no changed or global functions referenced */
		sec->status = sec->base->status = SAME;
		sec->include = sec->base->include = 0;
		free(dest);
		return;
	}

	/* overwrite with new relas list */
	list_replace(&newrelas, &sec->relas);

	/* include both rela and base sections */
	sec->include = 1;
	sec->base->include = 1;

	/*
	 * Update text section data buf and size.
	 *
	 * The rela section's data buf and size will be regenerated in
	 * kpatch_rebuild_rela_section_data().
	 */
	sec->base->data->d_buf = dest;
	sec->base->data->d_size = dest_offset;
}

static void kpatch_process_special_sections(struct kpatch_elf *kelf)
{
	struct special_section *special;
	struct section *sec;
	struct symbol *sym;
	struct rela *rela;

	for (special = special_sections; special->name; special++) {
		sec = find_section_by_name(&kelf->sections, special->name);
		if (!sec)
			continue;

		sec = sec->rela;
		if (!sec)
			continue;

		kpatch_regenerate_special_section(kelf, special, sec);
	}

	/*
	 * The following special sections don't have relas which reference
	 * non-included symbols, so their entire rela section can be included.
	 */
	list_for_each_entry(sec, &kelf->sections, list) {
		if (strcmp(sec->name, ".altinstr_replacement"))
			continue;

		/* include base section */
		sec->include = 1;

		/* include all symbols in the section */
		list_for_each_entry(sym, &kelf->symbols, list)
			if (sym->sec == sec)
				sym->include = 1;

		/* include rela section */
		if (sec->rela) {
			sec->rela->include = 1;
			/* include all symbols referenced by relas */
			list_for_each_entry(rela, &sec->rela->relas, list)
				rela->sym->include = 1;
		}
	}
}

/* Returns true if s is a string of only numbers with length > 0. */
static int isnumber(const char *s)
{
	do {
		if (!*s || !isdigit(*s))
			return 0;
	} while (*++s);

	return 1;
}

/*
 * String sections are always included even if unchanged.
 * The format is either:
 * .rodata.<func>.str1.[0-9]+ (new in GCC 6.1.0)
 * or .rodata.str1.[0-9]+ (older versions of GCC)
 * For the new format we could be smarter and only include the needed
 * strings sections.
 */
static int should_include_str_section(const char *name)
{
	const char *s;

	if (strncmp(name, ".rodata.", 8))
		return 0;

	/* Check if name matches ".rodata.str1.[0-9]+" */
	if (!strncmp(name, ".rodata.str1.", 13))
		return isnumber(name + 13);

	/* Check if name matches ".rodata.<func>.str1.[0-9]+" */
	s = strstr(name, ".str1.");
	if (!s)
		return 0;
	return isnumber(s + 6);
}

static void kpatch_include_standard_elements(struct kpatch_elf *kelf)
{
	struct section *sec;

	list_for_each_entry(sec, &kelf->sections, list) {
		/* include these sections even if they haven't changed */
		if (!strcmp(sec->name, ".shstrtab") ||
		    !strcmp(sec->name, ".strtab") ||
		    !strcmp(sec->name, ".symtab") ||
		    should_include_str_section(sec->name)) {
			sec->include = 1;
			if (sec->secsym)
				sec->secsym->include = 1;
		}
	}

	/* include the NULL symbol */
	list_entry(kelf->symbols.next, struct symbol, list)->include = 1;
}

#define inc_printf(fmt, ...) \
	log_debug("%*s" fmt, recurselevel, "", ##__VA_ARGS__);

static void kpatch_include_symbol(struct symbol *sym, int recurselevel)
{
	struct rela *rela;
	struct section *sec;

	inc_printf("start include_symbol(%s)\n", sym->name);
	sym->include = 1;
	inc_printf("symbol %s is included\n", sym->name);
	/*
	 * Check if sym is a non-local symbol (sym->sec is NULL) or
	 * if an unchanged local symbol.  This a base case for the
	 * inclusion recursion.
	 */
	if (!sym->sec || sym->sec->include ||
	    (sym->type != STT_SECTION && sym->status == SAME))
		goto out;
	sec = sym->sec;
	sec->include = 1;
	inc_printf("section %s is included\n", sec->name);
	if (sec->secsym && sec->secsym != sym) {
		sec->secsym->include = 1;
		inc_printf("section symbol %s is included\n", sec->secsym->name);
	}
	if (!sec->rela)
		goto out;
	sec->rela->include = 1;
	inc_printf("section %s is included\n", sec->rela->name);
	list_for_each_entry(rela, &sec->rela->relas, list)
		kpatch_include_symbol(rela->sym, recurselevel+1);
out:
	inc_printf("end include_symbol(%s)\n", sym->name);
	return;
}

static int kpatch_include_changed_functions(struct kpatch_elf *kelf)
{
	struct symbol *sym;
	int changed_nr = 0;

	log_debug("\n=== Inclusion Tree ===\n");

	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->status == CHANGED &&
		    sym->type == STT_FUNC) {
			changed_nr++;
			kpatch_include_symbol(sym, 0);
		}

		if (sym->type == STT_FILE)
			sym->include = 1;
	}

	return changed_nr;
}

static void kpatch_include_debug_sections(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct rela *rela, *saferela;

	/* include all .debug_* sections */
	list_for_each_entry(sec, &kelf->sections, list) {
		if (is_debug_section(sec)) {
			sec->include = 1;
			if (!is_rela_section(sec))
				sec->secsym->include = 1;
		}
	}

	/*
	 * Go through the .rela.debug_ sections and strip entries
	 * referencing unchanged symbols
	 */
	list_for_each_entry(sec, &kelf->sections, list) {
		if (!is_rela_section(sec) || !is_debug_section(sec))
			continue;
		list_for_each_entry_safe(rela, saferela, &sec->relas, list)
			if (!rela->sym->sec->include)
				list_del(&rela->list);
	}
}

static void kpatch_include_hook_elements(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;
	struct rela *rela;

	/* include load/unload sections */
	list_for_each_entry(sec, &kelf->sections, list) {
		if (!strcmp(sec->name, ".livepatch.hooks.load") ||
		    !strcmp(sec->name, ".livepatch.hooks.unload") ||
		    !strcmp(sec->name, ".rela.livepatch.hooks.load") ||
		    !strcmp(sec->name, ".rela.livepatch.hooks.unload")) {
			sec->include = 1;
			if (is_rela_section(sec)) {
				/* include hook dependencies */
				rela = list_entry(sec->relas.next,
			                         struct rela, list);
				sym = rela->sym;
				log_normal("found hook: %s\n",sym->name);
				kpatch_include_symbol(sym, 0);
				/* strip the hook symbol */
				sym->include = 0;
				sym->sec->sym = NULL;
				/* use section symbol instead */
				rela->sym = sym->sec->secsym;
			} else {
				sec->secsym->include = 1;
			}
		}
	}

	/*
	 * Strip temporary global load/unload function pointer objects
	 * used by the kpatch_[load|unload]() macros.
	 */
	list_for_each_entry(sym, &kelf->symbols, list)
		if (!strcmp(sym->name, "livepatch_load_data") ||
		    !strcmp(sym->name, "livepatch_unload_data"))
			sym->include = 0;
}

static int kpatch_include_new_globals(struct kpatch_elf *kelf)
{
	struct symbol *sym;
	int nr = 0;

	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->bind == STB_GLOBAL && sym->sec &&
		    sym->status == NEW) {
			kpatch_include_symbol(sym, 0);
			nr++;
		}
	}

	return nr;
}

static void kpatch_print_changes(struct kpatch_elf *kelf)
{
	struct symbol *sym;

	list_for_each_entry(sym, &kelf->symbols, list) {
		if (!sym->include || !sym->sec || sym->type != STT_FUNC)
			continue;
		if (sym->status == NEW)
			log_normal("new function: %s\n", sym->name);
		else if (sym->status == CHANGED)
			log_normal("changed function: %s\n", sym->name);
	}
}

static void kpatch_verify_patchability(struct kpatch_elf *kelf)
{
	struct section *sec;
	int errs = 0;

	list_for_each_entry(sec, &kelf->sections, list) {
		if (sec->status == CHANGED && !sec->include) {
			log_normal("changed section %s not selected for inclusion\n",
				   sec->name);
			errs++;
		}

		if (sec->status != SAME && sec->grouped) {
			log_normal("changed section %s is part of a section group\n",
				   sec->name);
			errs++;
		}

		if (sec->sh.sh_type == SHT_GROUP && sec->status == NEW) {
			log_normal("new/changed group sections are not supported\n");
			errs++;
		}

		/*
		 * ensure we aren't including .data.* or .bss.*
		 * (.data.unlikely is ok b/c it only has __warned vars)
		 */
		if (sec->include && sec->status != NEW &&
		    (!strncmp(sec->name, ".data", 5) ||
		     !strncmp(sec->name, ".bss", 4)) &&
		    strcmp(sec->name, ".data.unlikely")) {
			log_normal("data section %s selected for inclusion\n",
				   sec->name);
			errs++;
		}
	}

	if (errs)
		DIFF_FATAL("%d unsupported section change(s)", errs);
}

static void kpatch_migrate_included_elements(struct kpatch_elf *kelf,
					     struct kpatch_elf **kelfout)
{
	struct section *sec, *safesec;
	struct symbol *sym, *safesym;
	struct kpatch_elf *out;

	/* allocate output kelf */
	out = malloc(sizeof(*out));
	if (!out)
		ERROR("malloc");
	memset(out, 0, sizeof(*out));
	INIT_LIST_HEAD(&out->sections);
	INIT_LIST_HEAD(&out->symbols);
	INIT_LIST_HEAD(&out->strings);

	/* migrate included sections from kelf to out */
	list_for_each_entry_safe(sec, safesec, &kelf->sections, list) {
		if (!sec->include)
			continue;
		list_del(&sec->list);
		list_add_tail(&sec->list, &out->sections);
		sec->index = 0;
		if (!is_rela_section(sec) && sec->secsym && !sec->secsym->include)
			/* break link to non-included section symbol */
			sec->secsym = NULL;
	}

	/* migrate included symbols from kelf to out */
	list_for_each_entry_safe(sym, safesym, &kelf->symbols, list) {
		if (!sym->include)
			continue;
		list_del(&sym->list);
		list_add_tail(&sym->list, &out->symbols);
		sym->index = 0;
		sym->strip = 0;
		if (sym->sec && !sym->sec->include)
			/* break link to non-included section */
			sym->sec = NULL;
	}

	*kelfout = out;
}

static void kpatch_migrate_symbols(struct list_head *src,
				   struct list_head *dst,
				   int (*select)(struct symbol *))
{
	struct symbol *sym, *safe;

	list_for_each_entry_safe(sym, safe, src, list) {
		if (select && !select(sym))
			continue;

		list_del(&sym->list);
		list_add_tail(&sym->list, dst);
	}
}

static void kpatch_create_strings_elements(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;

	/* create .kpatch.strings */

	/* allocate section resources */
	ALLOC_LINK(sec, &kelf->sections);
	sec->name = ".livepatch.strings";

	/* set data */
	sec->data = malloc(sizeof(*sec->data));
	if (!sec->data)
		ERROR("malloc");
	sec->data->d_type = ELF_T_BYTE;

	/* set section header */
	sec->sh.sh_type = SHT_PROGBITS;
	sec->sh.sh_entsize = 1;
	sec->sh.sh_addralign = 1;
	sec->sh.sh_flags = SHF_ALLOC;

	/* create .kpatch.strings section symbol (reuse sym variable) */

	ALLOC_LINK(sym, &kelf->symbols);
	sym->sec = sec;
	sym->sym.st_info = GELF_ST_INFO(STB_LOCAL, STT_SECTION);
	sym->type = STT_SECTION;
	sym->bind = STB_LOCAL;
	sym->name = ".livepatch.strings";
}

static void kpatch_build_strings_section_data(struct kpatch_elf *kelf)
{
	struct string *string;
	struct section *sec;
	int size;
	char *strtab;

	sec = find_section_by_name(&kelf->sections, ".livepatch.strings");
	if (!sec)
		ERROR("can't find .kpatch.strings");

	/* determine size */
	size = 0;
	list_for_each_entry(string, &kelf->strings, list)
		size += strlen(string->name) + 1;

	/* allocate section resources */
	strtab = malloc(size);
	if (!strtab)
		ERROR("malloc");
	sec->data->d_buf = strtab;
	sec->data->d_size = size;

	/* populate strings section data */
	list_for_each_entry(string, &kelf->strings, list) {
		strcpy(strtab, string->name);
		strtab += strlen(string->name) + 1;
	}
}

/*
 * If __func__ is used, it generates a symbol like __func__.5432
 * Since this is always included (see is_special_static), it will generate
 * duplicate symbol conflicts if GCC happens to use the same number (which
 * happens quite often since it doesn't appear to be random). To work around
 * this, rename the symbol to use a completely random number.
 */
static char *rename_func_symbol(void)
{
	char *s;

	if (asprintf(&s, "__func__.%d", rand()) == -1)
		ERROR("malloc");

	return s;
}

static char *mangle_local_symbol(char *filename, char *symname)
{
	char *s, *ptr;

	/* filename + # + symbolname */
	ptr = s = malloc(strlen(filename) + 1 + strlen(symname) + 1);
	if (!s)
		ERROR("malloc");

	ptr = stpcpy(ptr, filename);
	*ptr++ = '#';
	strcpy(ptr, symname);

	return s;
}

/*
 * Rename local symbols to the filename#symbol format used by Xen's "special"
 * symbol table.
 */
static void livepatch_rename_local_symbols(struct kpatch_elf *kelf, char *hint)
{
	struct symbol *sym;

	list_for_each_entry(sym, &kelf->symbols, list) {
		/* ignore NULL symbol */
		if (!strlen(sym->name))
			continue;

		if (sym->type != STT_FUNC && sym->type != STT_OBJECT)
			continue;

		if (sym->bind != STB_LOCAL)
			continue;

                if (!strncmp(sym->name, "__func__.", 9))
                    sym->name = rename_func_symbol();
		sym->name = mangle_local_symbol(hint, sym->name);
		log_debug("Local symbol mangled to: %s\n", sym->name);
	}
}

static struct section *create_section_pair(struct kpatch_elf *kelf,
					   char *name, int entsize, int nr)
{
	char *relaname;
	struct section *sec, *relasec;
	int size = entsize * nr;

	relaname = malloc(strlen(name) + strlen(".rela") + 1);
	if (!relaname)
		ERROR("malloc");
	strcpy(relaname, ".rela");
	strcat(relaname, name);

	/* allocate text section resources */
	ALLOC_LINK(sec, &kelf->sections);
	sec->name = name;

	/* set data */
	sec->data = malloc(sizeof(*sec->data));
	if (!sec->data)
		ERROR("malloc");
	sec->data->d_buf = malloc(size);
	if (!sec->data->d_buf)
		ERROR("malloc");
	sec->data->d_size = size;
	sec->data->d_type = ELF_T_BYTE;

	/* set section header */
	sec->sh.sh_type = SHT_PROGBITS;
	sec->sh.sh_entsize = entsize;
	sec->sh.sh_addralign = 8;
	sec->sh.sh_flags = SHF_ALLOC;
	sec->sh.sh_size = size;

	/* allocate rela section resources */
	ALLOC_LINK(relasec, &kelf->sections);
	relasec->name = relaname;
	relasec->base = sec;
	INIT_LIST_HEAD(&relasec->relas);

	/* set data, buffers generated by kpatch_rebuild_rela_section_data() */
	relasec->data = malloc(sizeof(*relasec->data));
	if (!relasec->data)
		ERROR("malloc");

	/* set section header */
	relasec->sh.sh_type = SHT_RELA;
	relasec->sh.sh_entsize = sizeof(GElf_Rela);
	relasec->sh.sh_addralign = 8;

	/* set text rela section pointer */
	sec->rela = relasec;

	return sec;
}

static void livepatch_create_patches_sections(struct kpatch_elf *kelf,
					    struct lookup_table *table,
					    char *hint, int resolve)
{
	int nr, index;
	struct section *sec, *relasec;
	struct symbol *sym, *strsym;
	struct rela *rela;
	struct lookup_result result;
	struct livepatch_patch_func *funcs;
	char *funcname;

	/* count patched functions */
	nr = 0;
	list_for_each_entry(sym, &kelf->symbols, list)
		if (sym->type == STT_FUNC && sym->status == CHANGED)
			nr++;

	/* create text/rela section pair */
	sec = create_section_pair(kelf, ".livepatch.funcs", sizeof(*funcs), nr);
	relasec = sec->rela;
	funcs = sec->data->d_buf;

	/* lookup strings symbol */
	strsym = find_symbol_by_name(&kelf->symbols, ".livepatch.strings");
	if (!strsym)
		ERROR("can't find .livepatch.strings symbol");

	/* populate sections */
	index = 0;
	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->type == STT_FUNC && sym->status == CHANGED) {
			if (sym->bind == STB_LOCAL) {
				funcname = mangle_local_symbol(hint, sym->name);
				if (lookup_local_symbol(table, sym->name,
				                        hint, &result))
					ERROR("lookup_local_symbol %s (%s)",
					      sym->name, hint);
			} else {
				funcname = sym->name;
				if (lookup_global_symbol(table, sym->name,
				                        &result))
					ERROR("lookup_global_symbol %s",
					      sym->name);
			}
			log_debug("lookup for %s @ 0x%016lx len %lu\n",
			          sym->name, result.value, result.size);

			if (result.size < PATCH_INSN_SIZE)
				ERROR("%s too small to patch", sym->name);

			/* add entry in text section */
			funcs[index].name = NULL;
			if (resolve)
				funcs[index].old_addr = result.value;
			else
				/* This will be filled in at module load time */
				funcs[index].old_addr = 0;
			funcs[index].old_size = result.size;
			funcs[index].new_addr = 0;
			funcs[index].new_size = sym->sym.st_size;
			funcs[index].version = 1;
			memset(funcs[index].pad, 0, sizeof funcs[index].pad);

			/*
			 * Add a relocation that will populate
			 * the funcs[index].new_addr field at
			 * module load time.
			 */
			ALLOC_LINK(rela, &relasec->relas);
			rela->sym = sym;
			rela->type = R_X86_64_64;
			rela->addend = 0;
			rela->offset = index * sizeof(*funcs);
			rela->offset = index * sizeof(*funcs) +
			               offsetof(struct livepatch_patch_func, new_addr);

			/*
			 * Add a relocation that will populate
			 * the funcs[index].name field.
			 */
			ALLOC_LINK(rela, &relasec->relas);
			rela->sym = strsym;
			rela->type = R_X86_64_64;
			rela->addend = offset_of_string(&kelf->strings, funcname);
			rela->offset = index * sizeof(*funcs) +
			               offsetof(struct livepatch_patch_func, name);

			index++;
		}
	}

	/* sanity check, index should equal nr */
	if (index != nr)
		ERROR("size mismatch in funcs sections");

}

static int is_null_sym(struct symbol *sym)
{
	return !strlen(sym->name);
}

static int is_file_sym(struct symbol *sym)
{
	return sym->type == STT_FILE;
}

static int is_local_func_sym(struct symbol *sym)
{
	return sym->bind == STB_LOCAL && sym->type == STT_FUNC;
}

static void kpatch_reorder_symbols(struct kpatch_elf *kelf)
{
	LIST_HEAD(symbols);

	/* migrate NULL sym */
	kpatch_migrate_symbols(&kelf->symbols, &symbols, is_null_sym);
	/* migrate LOCAL FILE sym */
	kpatch_migrate_symbols(&kelf->symbols, &symbols, is_file_sym);
	/* migrate LOCAL FUNC syms */
	kpatch_migrate_symbols(&kelf->symbols, &symbols, is_local_func_sym);
	/* migrate all other LOCAL syms */
	kpatch_migrate_symbols(&kelf->symbols, &symbols, is_local_sym);
	/* migrate all other (GLOBAL) syms */
	kpatch_migrate_symbols(&kelf->symbols, &symbols, NULL);

	list_replace(&symbols, &kelf->symbols);
}

static void kpatch_reindex_elements(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;
	int index;

	index = 1; /* elf write function handles NULL section 0 */
	list_for_each_entry(sec, &kelf->sections, list)
		sec->index = index++;

	index = 0;
	list_for_each_entry(sym, &kelf->symbols, list) {
		sym->index = index++;
		if (sym->sec)
			sym->sym.st_shndx = sym->sec->index;
		else if (sym->sym.st_shndx != SHN_ABS)
			sym->sym.st_shndx = SHN_UNDEF;
	}
}

struct arguments {
	char *args[4];
	int debug;
	int resolve;
};

static char args_doc[] = "original.o patched.o kernel-object output.o";

static struct argp_option options[] = {
	{"debug", 'd', 0, 0, "Show debug output" },
	{"resolve", 'r', 0, 0, "Resolve to-be-patched function addresses" },
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
		case 'r':
			arguments->resolve = 1;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num >= 4)
				/* Too many arguments. */
				argp_usage (state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 4)
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
	struct kpatch_elf *kelf_base, *kelf_patched, *kelf_out;
	struct arguments arguments;
	int num_changed, new_globals_exist;
	struct lookup_table *lookup;
	struct section *sec, *symtab;
	struct symbol *sym;
	char *hint = NULL;

	srand(time(NULL));

	arguments.debug = 0;
	arguments.resolve = 0;
	argp_parse (&argp, argc, argv, 0, 0, &arguments);
	if (arguments.debug)
		loglevel = DEBUG;

	elf_version(EV_CURRENT);

	childobj = basename(arguments.args[0]);

	log_debug("Open base\n");
	kelf_base = kpatch_elf_open(arguments.args[0]);
	log_debug("Open patched\n");
	kelf_patched = kpatch_elf_open(arguments.args[1]);

	log_debug("Compare elf headers\n");
	kpatch_compare_elf_headers(kelf_base->elf, kelf_patched->elf);
	log_debug("Check program headers of base\n");
	kpatch_check_program_headers(kelf_base->elf);
	log_debug("Check program headers of patched\n");
	kpatch_check_program_headers(kelf_patched->elf);

	log_debug("Mark grouped sections\n");
	kpatch_mark_grouped_sections(kelf_patched);
	log_debug("Replace sections syms base\n");
	kpatch_replace_sections_syms(kelf_base);
	log_debug("Replace sections syms patched\n");
	kpatch_replace_sections_syms(kelf_patched);
	log_debug("Rename mangled functions\n");
	kpatch_rename_mangled_functions(kelf_base, kelf_patched);

	log_debug("Correlate elfs\n");
	kpatch_correlate_elfs(kelf_base, kelf_patched);
	log_debug("Correlate static local variables\n");
	kpatch_correlate_static_local_variables(kelf_base, kelf_patched);

	/*
	 * After this point, we don't care about kelf_base anymore.
	 * We access its sections via the twin pointers in the
	 * section, symbol, and rela lists of kelf_patched.
	 */
	log_debug("Mark ignored sections\n");
	kpatch_mark_ignored_sections(kelf_patched);
	log_debug("Compare correlated elements\n");
	kpatch_compare_correlated_elements(kelf_patched);
	log_debug("Elf teardown base\n");
	kpatch_elf_teardown(kelf_base);
	log_debug("Elf free base\n");
	kpatch_elf_free(kelf_base);

	log_debug("Mark ignored functions same\n");
	kpatch_mark_ignored_functions_same(kelf_patched);
	log_debug("Mark ignored sections same\n");
	kpatch_mark_ignored_sections_same(kelf_patched);
	log_debug("Mark constant labels same\n");
	kpatch_mark_constant_labels_same(kelf_patched);

	log_debug("Include standard elements\n");
	kpatch_include_standard_elements(kelf_patched);
	log_debug("Include changed functions\n");
	num_changed = kpatch_include_changed_functions(kelf_patched);
	log_debug("num_changed = %d\n", num_changed);
	log_debug("Include debug sections\n");
	kpatch_include_debug_sections(kelf_patched);
	log_debug("Include hook elements\n");
	kpatch_include_hook_elements(kelf_patched);
	log_debug("Include new globals\n");
	new_globals_exist = kpatch_include_new_globals(kelf_patched);
	log_debug("new_globals_exist = %d\n", new_globals_exist);

	log_debug("Print changes\n");
	kpatch_print_changes(kelf_patched);
	log_debug("Dump patched elf status\n");
	kpatch_dump_kelf(kelf_patched);

	if (!num_changed && !new_globals_exist) {
		log_debug("no changed functions were found\n");
		return 3; /* 1 is ERROR, 2 is DIFF_FATAL */
	}

	log_debug("Process special sections\n");
	kpatch_process_special_sections(kelf_patched);
	log_debug("Verify patchability\n");
	kpatch_verify_patchability(kelf_patched);

	/* this is destructive to kelf_patched */
	log_debug("Migrate included elements\n");
	kpatch_migrate_included_elements(kelf_patched, &kelf_out);

	/*
	 * Teardown kelf_patched since we shouldn't access sections or symbols
	 * through it anymore.  Don't free however, since our section and symbol
	 * name fields still point to strings in the Elf object owned by
	 * kpatch_patched.
	 */
	log_debug("Elf teardown patched\n");
	kpatch_elf_teardown(kelf_patched);

	log_debug("Search for source file name\n");
	list_for_each_entry(sym, &kelf_out->symbols, list) {
		if (sym->type == STT_FILE) {
			hint = sym->name;
			break;
		}
	}
	if (!hint)
		ERROR("FILE symbol not found in output. Stripped?\n");
	log_debug("hint = %s\n", hint);

	/* create symbol lookup table */
	log_debug("Lookup xen-syms\n");
	lookup = lookup_open(arguments.args[2]);

	/* create strings, patches, and dynrelas sections */
	log_debug("Create strings elements\n");
	kpatch_create_strings_elements(kelf_out);
	log_debug("Create patches sections\n");
	livepatch_create_patches_sections(kelf_out, lookup, hint,
			                arguments.resolve);
	kpatch_build_strings_section_data(kelf_out);

	log_debug("Rename local symbols\n");
	livepatch_rename_local_symbols(kelf_out, hint);

	/*
	 *  At this point, the set of output sections and symbols is
	 *  finalized.  Reorder the symbols into linker-compliant
	 *  order and index all the symbols and sections.  After the
	 *  indexes have been established, update index data
	 *  throughout the structure.
	 */
	log_debug("Reorder symbols\n");
	kpatch_reorder_symbols(kelf_out);
	log_debug("Reindex elements\n");
	kpatch_reindex_elements(kelf_out);

	/*
	 * Update rela section headers and rebuild the rela section data
	 * buffers from the relas lists.
	 */
	symtab = find_section_by_name(&kelf_out->sections, ".symtab");
	list_for_each_entry(sec, &kelf_out->sections, list) {
		if (!is_rela_section(sec))
			continue;
		sec->sh.sh_link = symtab->index;
		sec->sh.sh_info = sec->base->index;
		log_debug("Rebuild rela section data for %s\n", sec->name);
		kpatch_rebuild_rela_section_data(sec);
	}

	log_debug("Create shstrtab\n");
	kpatch_create_shstrtab(kelf_out);
	log_debug("Create strtab\n");
	kpatch_create_strtab(kelf_out);
	log_debug("Create symtab\n");
	kpatch_create_symtab(kelf_out);
	log_debug("Dump out elf status\n");
	kpatch_dump_kelf(kelf_out);
	log_debug("Write out elf\n");
	kpatch_write_output_elf(kelf_out, kelf_patched->elf, arguments.args[3]);

	log_debug("Elf free patched\n");
	kpatch_elf_free(kelf_patched);
	log_debug("Elf teardown out\n");
	kpatch_elf_teardown(kelf_out);
	log_debug("Elf free out\n");
	kpatch_elf_free(kelf_out);

	return 0;
}
