#ifndef _COMMON_H_
#define _COMMON_H_

#include <error.h>

extern char *childobj;

#define ERROR(format, ...) \
	error(1, 0, "ERROR: %s: %s: %d: " format, childobj, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define DIFF_FATAL(format, ...) \
({ \
	fprintf(stderr, "ERROR: %s: " format "\n", childobj, ##__VA_ARGS__); \
	error(2, 0, "unreconcilable difference"); \
})

#define log_debug(format, ...) log(DEBUG, format, ##__VA_ARGS__)
#define log_normal(format, ...) log(NORMAL, "%s: " format, childobj, ##__VA_ARGS__)

#define log(level, format, ...) \
({ \
	if (loglevel <= (level)) \
		printf(format, ##__VA_ARGS__); \
})

#define ALLOC_LINK(_new, _list) \
{ \
	(_new) = malloc(sizeof(*(_new))); \
	if (!(_new)) \
		ERROR("malloc"); \
	memset((_new), 0, sizeof(*(_new))); \
	INIT_LIST_HEAD(&(_new)->list); \
	list_add_tail(&(_new)->list, (_list)); \
}

enum loglevel {
	DEBUG,
	NORMAL
};

extern enum loglevel loglevel;

/*******************
 * Data structures
 * ****************/
struct section;
struct symbol;
struct rela;

enum status {
	NEW,
	CHANGED,
	SAME
};

struct section {
	struct list_head list;
	struct section *twin;
	GElf_Shdr sh;
	Elf_Data *data;
	char *name;
	int index;
	enum status status;
	int include;
	int ignore;
	int grouped;
	union {
		struct { /* if (is_rela_section()) */
			struct section *base;
			struct list_head relas;
		};
		struct { /* else */
			struct section *rela;
			struct symbol *secsym, *sym;
		};
	};
};

struct symbol {
	struct list_head list;
	struct symbol *twin;
	struct section *sec;
	GElf_Sym sym;
	char *name;
	int index;
	unsigned char bind, type;
	enum status status;
	union {
		int include; /* used in the patched elf */
		int strip; /* used in the output elf */
	};
};

struct rela {
	struct list_head list;
	GElf_Rela rela;
	struct symbol *sym;
	unsigned int type;
	int addend;
	int offset;
	char *string;
};

struct string {
	struct list_head list;
	char *name;
};

struct kpatch_elf {
	Elf *elf;
	struct list_head sections;
	struct list_head symbols;
	struct list_head strings;
	int fd;
};

#define PATCH_INSN_SIZE 5

struct xsplice_patch_func {
	char *name;
	unsigned long new_addr;
	unsigned long old_addr;
	uint32_t new_size;
	uint32_t old_size;
	unsigned char pad[32];
};

struct special_section {
	char *name;
	int (*group_size)(struct kpatch_elf *kelf, int offset);
};

struct kpatch_elf *kpatch_elf_open(const char *name);
void kpatch_elf_free(struct kpatch_elf *kelf);
void kpatch_elf_teardown(struct kpatch_elf *kelf);
void kpatch_write_output_elf(struct kpatch_elf *kelf,
			      Elf *elf, char *outfile);
void kpatch_dump_kelf(struct kpatch_elf *kelf);
void kpatch_create_symtab(struct kpatch_elf *kelf);
void kpatch_create_strtab(struct kpatch_elf *kelf);
void kpatch_create_shstrtab(struct kpatch_elf *kelf);
void kpatch_rebuild_rela_section_data(struct section *sec);

struct section *find_section_by_index(struct list_head *list, unsigned int index);
struct section *find_section_by_name(struct list_head *list, const char *name);
struct symbol *find_symbol_by_index(struct list_head *list, size_t index);
struct symbol *find_symbol_by_name(struct list_head *list, const char *name);

int is_text_section(struct section *sec);
int is_debug_section(struct section *sec);
int is_rela_section(struct section *sec);
int is_local_sym(struct symbol *sym);

void rela_insn(struct section *sec, struct rela *rela, struct insn *insn);

int offset_of_string(struct list_head *list, char *name);

char *status_str(enum status status);

#endif /* _COMMON_H_ */
