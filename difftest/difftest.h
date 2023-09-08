#ifndef _DIFFTEST_DIFFTEST_H
#define _DIFFTEST_DIFFTEST_H

#include <memory>
#include "../riscv/cfg.h"
#include "../riscv/devices.h"
#include "../riscv/processor.h"

#define CONFIG_MSIZE (16 * 1024 * 1024 * 1024UL)

typedef uint64_t word_t;
typedef int64_t sword_t;
#define FMT_WORD "0x%016lx"

typedef uint64_t paddr_t;
#define FMT_PADDR "0x%08x"

enum { DIFFTEST_TO_DUT, DIFFTEST_TO_REF };

#ifndef DIFFTEST_LOG_FILE
#define DIFFTEST_LOG_FILE nullptr
#endif

namespace spike_main {
void help(int exit_code = 1); 

void suggest_help(); 

bool check_file_exists(const char *fileName); 

std::ifstream::pos_type get_file_size(const char *filename); 

void read_file_bytes(const char *filename, size_t fileoff,
                            abstract_mem_t *mem, size_t memoff,
                            size_t read_sz); 

bool sort_mem_region(const mem_cfg_t &a, const mem_cfg_t &b); 

bool check_mem_overlap(const mem_cfg_t &L, const mem_cfg_t &R); 

bool check_if_merge_covers_64bit_space(const mem_cfg_t &L,
                                              const mem_cfg_t &R); 

mem_cfg_t merge_mem_regions(const mem_cfg_t &L, const mem_cfg_t &R); 

std::vector<mem_cfg_t>
merge_overlapping_memory_regions(std::vector<mem_cfg_t> mems); 

std::vector<mem_cfg_t> parse_mem_layout(const char *arg); 

std::vector<std::pair<reg_t, abstract_mem_t *>>
make_mems(const std::vector<mem_cfg_t> &layout); 

unsigned long atoul_safe(const char *s); 

unsigned long atoul_nonzero_safe(const char *s); 

std::vector<size_t> parse_hartids(const char *s); 
} // namespace spike_main

using namespace spike_main;

class difftest_t
{
public:
  void diff_memcpy(size_t p, reg_t dest, void* src, size_t n);
  void diff_set_regs(size_t p, void* diff_context);
  void diff_get_regs(size_t p, void* diff_context);
  void diff_step(size_t p, uint64_t n);
  void diff_debugmode(size_t p);
  void diff_display(size_t p);
  void diff_mmio_store(reg_t addr, void *buf, size_t n);
  std::unique_ptr<sim_t> sim;
};

struct diff_context_t {
  word_t gpr[32];
  word_t fpr[32];
  word_t pc;
  word_t mstatus;
  word_t mcause;
  word_t mepc;
  word_t sstatus;
  word_t scause;
  word_t sepc;
  word_t satp;
  word_t mip;
  word_t mie;
  word_t mscratch;
  word_t sscratch;
  word_t mideleg;
  word_t medeleg;
  word_t mtval;
  word_t stval;
  word_t mtvec;
  word_t stvec;
  word_t priv;
  word_t debugMode;
  word_t dcsr;
  word_t dpc;
  word_t dscratch0;
  word_t dscratch1;
};

#endif