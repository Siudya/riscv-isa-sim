#ifndef _DIFFTEST_DIFFTEST_H
#define _DIFFTEST_DIFFTEST_H

#include <memory>
#include "../riscv/cfg.h"
#include "../riscv/devices.h"
#include "../riscv/processor.h"

#define CONFIG_MSIZE (8 * 1024 * 1024 * 1024UL)

#define XS_VLEN 128
#define VENUM64 (XS_VLEN/64)
#define VENUM32 (XS_VLEN/32)
#define VENUM16 (XS_VLEN/16)
#define VENUM8  (XS_VLEN/8)

#define CONFIG_RVV
#define CONFIG_RV_FDI

typedef uint64_t word_t;
typedef int64_t sword_t;
#define FMT_WORD "0x%016lx"

typedef uint64_t paddr_t;
#define FMT_PADDR "0x%08x"

enum { REF_TO_DUT, DUT_TO_REF };

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
  void diff_set_regs(size_t p, void* diff_context, bool on_demand);
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
  uint64_t priviledgeMode;
  uint64_t mstatus;
  uint64_t sstatus;
  uint64_t mepc;
  uint64_t sepc;
  uint64_t mtval;
  uint64_t stval;
  uint64_t mtvec;
  uint64_t stvec;
  uint64_t mcause;
  uint64_t scause;
  uint64_t satp;
  uint64_t mip;
  uint64_t mie;
  uint64_t mscratch;
  uint64_t sscratch;
  uint64_t mideleg;
  uint64_t medeleg;
#ifdef CONFIG_RV_FDI
  uint64_t dumcfg, dumbound0, dumbound1;
  uint64_t dlcfg0;
  uint64_t dlbound0, dlbound1, dlbound2, dlbound3;
  uint64_t dlbound4, dlbound5, dlbound6, dlbound7;
  uint64_t dmaincall, dretpc;
  uint64_t djcfg, djbound0lo, djbound0hi;
#endif
  uint64_t pc;
#ifdef CONFIG_RVV
  //vector
  union {
    uint64_t _64[VENUM64];
    uint32_t _32[VENUM32];
    uint16_t _16[VENUM16];
    uint8_t  _8[VENUM8];
  } vpr[32];

  uint64_t vstart;
  uint64_t vxsat;
  uint64_t vxrm;
  uint64_t vcsr;
  uint64_t vl;
  uint64_t vtype;
  uint64_t vlenb;
#endif // CONFIG_RVV
#ifdef CONFIG_DIFF_DEBUG_MODE
  uint64_t debugMode;
  uint64_t dcsr;
  uint64_t dpc;
  uint64_t dscratch0;
  uint64_t dscratch1;
#endif // CONFIG_DIFF_DEBUG_MODE
};

struct sync_state_t {
  uint64_t lrscValid;
  uint64_t lrscAddr;
};

#endif