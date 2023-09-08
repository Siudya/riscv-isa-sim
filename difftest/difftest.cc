#include "config.h"
#include "cfg.h"
#include "sim.h"
#include "mmu.h"
#include "arith.h"
#include "remote_bitbang.h"
#include "cachesim.h"
#include "extension.h"
#include "decode_macros.h"
#include <cassert>
#include <cstddef>
#include <dlfcn.h>
#include <fesvr/option_parser.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <memory>
#include <fstream>
#include <limits>
#include <cinttypes>
#include "../VERSION"

#include "difftest.h"
#include <utility>
#include "../riscv/decode.h"
#include "../riscv/disasm.h"

static std::unique_ptr<difftest_t> diff = std::make_unique<difftest_t>();

void difftest_t::diff_step(size_t p, uint64_t n) {
  sim->get_core(p)->step(n);
  // also tick all devices
  for (auto &dev : sim->devices) dev->tick(n);
}

void difftest_t::diff_get_regs(size_t p, void* diff_context) {
  struct diff_context_t *ctx = (struct diff_context_t *)diff_context;
  state_t * state = sim->get_core(p)->get_state();
  for (int i = 0; i < NXPR; i++) {
    ctx->gpr[i] = state->XPR[i];
  }
  for (int i = 0; i < NFPR; i++) {
    ctx->fpr[i] = unboxF64(state->FPR[i]);
  }
  ctx->pc = state->pc;
  ctx->mstatus = state->mstatus->read();
  ctx->mcause = state->mcause->read();
  ctx->mepc = state->mepc->read();
  ctx->sstatus = state->sstatus->read();
  ctx->scause = state->scause->read();
  ctx->sepc = state->sepc->read();
  ctx->satp = state->satp->read();
  ctx->mip = state->mip->read();
  ctx->mie = state->mie->read();
  ctx->mscratch = state->csrmap[CSR_MSCRATCH]->read();
  ctx->sscratch = state->csrmap[CSR_SSCRATCH]->read();
  ctx->mideleg = state->mideleg->read();
  ctx->medeleg = state->medeleg->read();
  ctx->mtval = state->mtval->read();
  ctx->stval = state->stval->read();
  ctx->mtvec = state->mtvec->read();
  ctx->stvec = state->stvec->read();
  ctx->priv = state->prv;
  ctx->debugMode = state->debug_mode;
  ctx->dcsr = state->dcsr->read();
  ctx->dpc = state->dpc->read();
  ctx->dscratch0 = state->csrmap[CSR_DSCRATCH0]->read();
  ctx->dscratch1 = state->csrmap[CSR_DSCRATCH1]->read();
}

void difftest_t::diff_set_regs(size_t p, void* diff_context) {
  struct diff_context_t* ctx = (struct diff_context_t*)diff_context;
  state_t * state = sim->get_core(p)->get_state();
  for (int i = 0; i < NXPR; i++) {
    state->XPR.write(i, (sword_t)ctx->gpr[i]);
  }
  for (int i = 0; i < NFPR; i++) {
    state->FPR.write(i, freg(f64(ctx->fpr[i])));
  }
  state->pc = ctx->pc;
  state->mstatus->write(ctx->mstatus);
  state->mcause->write(ctx->mcause);
  state->mepc->write(ctx->mepc);
  state->sstatus->write(ctx->sstatus);
  state->scause->write(ctx->scause);
  state->sepc->write(ctx->sepc);
  state->satp->write(ctx->satp);
  state->mip->write(ctx->mip);
  state->mie->write(ctx->mie);
  state->csrmap[CSR_MSCRATCH]->write(ctx->mscratch);
  state->csrmap[CSR_SSCRATCH]->write(ctx->sscratch);
  state->mideleg->write(ctx->mideleg);
  state->medeleg->write(ctx->medeleg);
  state->mtval->write(ctx->mtval);
  state->stval->write(ctx->stval);
  state->mtvec->write(ctx->mtvec);
  state->stvec->write(ctx->stvec);
  state->prv = ctx->priv;
  state->debug_mode = ctx->debugMode;
  state->dcsr->write(ctx->dcsr);
  state->dpc->write(ctx->dpc);
  state->csrmap[CSR_DSCRATCH0]->write(ctx->dscratch0);
  state->csrmap[CSR_DSCRATCH1]->write(ctx->dscratch1);
}

void difftest_t::diff_memcpy(size_t p, reg_t dest, void* src, size_t n) {
  mmu_t* mmu = sim->get_core(p)->get_mmu();
  for (size_t i = 0; i < n; i++) {
    mmu->store(dest+i, *((uint8_t*)src+i));
  }
}

void difftest_t::diff_debugmode(size_t p){
  // Debug Intr causes entry to debug mode
  processor_t *proc = sim->get_core(p);
  proc->halt_request = proc->HR_REGULAR;
  proc->step(0); // just force processor to enter debug mode
  proc->halt_request = proc->HR_NONE;
}

void difftest_t::diff_display(size_t p) {
  state_t *state = sim->get_core(p)->get_state();
  int i;
  for (i = 0; i < 32; i++) {
    printf("%4s: " FMT_WORD " ", xpr_name[i], state->XPR[i]);
    if (i % 4 == 3) {
      printf("\n");
    }
  }
  for (i = 0; i < 32; i++) {
    printf("%4s: " FMT_WORD " ", fpr_name[i],
           f128_to_ui64_r_minMag(state->FPR[i], true));
    if (i % 4 == 3) {
      printf("\n");
    }
  }
  printf("pc: " FMT_WORD " mstatus: " FMT_WORD " mcause: " FMT_WORD
         " mepc: " FMT_WORD "\n",
         state->pc, state->mstatus->read(), state->mcause->read(),
         state->mepc->read());
  printf("%22s sstatus: " FMT_WORD " scause: " FMT_WORD " sepc: " FMT_WORD "\n",
         "", state->sstatus->read(), state->scause->read(),
         state->sepc->read());
  printf("satp: " FMT_WORD "\n", state->satp->read());
  printf("mip: " FMT_WORD " mie: " FMT_WORD " mscratch: " FMT_WORD
         " sscratch: " FMT_WORD "\n",
         state->mip->read(), state->mie->read(),
         state->csrmap[CSR_MSCRATCH]->read(),
         state->csrmap[CSR_MSCRATCH]->read());
  printf("mideleg: " FMT_WORD " medeleg: " FMT_WORD "\n",
         state->mideleg->read(), state->medeleg->read());
  printf("mtval: " FMT_WORD " stval: " FMT_WORD " mtvec: " FMT_WORD
         " stvec: " FMT_WORD "\n",
         state->mtval->read(), state->stval->read(), state->mtvec->read(),
         state->stvec->read());
  printf("privilege mode:%ld\n", state->prv);
  fflush(stdout);
}

void difftest_t::diff_mmio_store(reg_t addr, void *buf, size_t n) {
  sim->mmio_store(addr, n, (uint8_t *)buf);
}

extern "C" {

void difftest_init() {

  //======  Constructing cfg ======//

  char mem_layout_str[100];
  sprintf(mem_layout_str, "0x%x:0x%lx", DRAM_BASE, CONFIG_MSIZE);

  cfg_arg_t<size_t> nprocs(NUM_CORES);
  std::vector<size_t> default_hartids;
  default_hartids.reserve(nprocs());
  for(size_t i = 0; i < nprocs(); ++i) {
    default_hartids.push_back(i);
  }

  cfg_t cfg(/*default_initrd_bounds=*/std::make_pair((reg_t)0, (reg_t)0),
            /*default_bootargs=*/nullptr,
            /*default_isa=*/
            "RV64IMAFDCV_zba_zbb_zbc_zbs_zbkb_zbkc_zbkx_zknd_zkne_zknh_zksed_"
            "zksh_svinval",
            /*default_priv=*/"MSU",
            /*default_varch=*/"vlen:128,elen:64",
            /*default_misaligned=*/false,
            /*default_endianness*/ endianness_little,
            /*default_pmpregions=*/16,
            /*default_mem_layout=*/parse_mem_layout(mem_layout_str),
            /*default_hartids=*/default_hartids,
            /*default_real_time_clint=*/false,
            /*default_trigger_count=*/4);

  //===== Constructing sim_t object =====//

  std::vector<std::string> difftest_htif_args;
  difftest_htif_args.push_back("");

  debug_module_config_t difftest_dm_config = {.progbufsize = 2,
                                              .max_sba_data_width = 0,
                                              .require_authentication = false,
                                              .abstract_rti = 0,
                                              .support_hasel = true,
                                              .support_abstract_csr_access =
                                                  true,
                                              .support_haltgroups = true,
                                              .support_impebreak = false};

  std::vector<const device_factory_t*> plugin_device_factories;
  // dummy_debug
  auto it = mmio_device_map().find(std::string("dummy_debug"));
  assert(it != mmio_device_map().end());
  plugin_device_factories.push_back(it->second);
  
  diff->sim = std::make_unique<sim_t>(
      /* *cfg=*/&cfg,
      /* halted=*/false,
      /* mems=*/make_mems(cfg.mem_layout()),
      /* plugin_devices=*/plugin_device_factories,
      /* args=*/difftest_htif_args,
      /* dm_config=*/difftest_dm_config,
      /* *log_path=*/DIFFTEST_LOG_FILE,
      /* dtb_enabled=*/true,
      /* *dtb_file=*/nullptr,
      /* socket_enable=*/false,
      /* *cmd_file=*/nullptr);

  // In case it is used for tracing multi-core, choose no buffering mode
  setvbuf(diff->sim->get_core(0)->get_log_file(), NULL, _IONBF, 0);
}

void difftest_memcpy(size_t p, paddr_t addr, void *buf, size_t n, bool direction) {
  if (direction == DIFFTEST_TO_REF) {
    diff->diff_memcpy(p, addr, buf, n);
  } else {
    assert(0);
  }
}

void difftest_regcpy(size_t p, void* dut, bool direction) {
  if (direction == DIFFTEST_TO_REF) {
    diff->diff_set_regs(p, dut);
  } else {
    diff->diff_get_regs(p, dut);
  }
}

void difftest_csrcpy(size_t p, void *dut, bool direction) {
  // TODO
}

void difftest_uarchstatus_cpy(size_t p, void *dut, bool direction) {
  // TODO
}

void update_dynamic_config(size_t p, void* config) {
  // TODO
}

void difftest_exec(size_t p, uint64_t n) {
  diff->diff_step(p, n);
}

// Refer to backend/fu/util/CSRConst.scala:245 for IRQs:
// val IntPriority = Seq(
//    IRQ_DEBUG(12),
//    IRQ_MEIP(3), IRQ_MSIP(11), IRQ_MTIP(7),
//    IRQ_SEIP(1), IRQ_SSIP(9), IRQ_STIP(5),
//    IRQ_UEIP(0), IRQ_USIP(8), IRQ_UTIP(4)
//  )
void difftest_raise_intr(size_t p, uint64_t NO) {
  if (NO == 0xc) {
    diff->diff_debugmode(p);  // Debug Intr
  } else {
    state_t * state = diff->sim->get_core(p)->get_state();
    uint64_t mip_bit = 0x1UL << (NO & 0xf);
    bool is_timer_interrupt = mip_bit & 0xa0UL;
    bool is_external_interrupt = mip_bit & 0xb00UL;
    bool from_outside = !(mip_bit & state->mip->read());
    bool external_set = (is_timer_interrupt || is_external_interrupt) && from_outside;
    if (external_set) {
      state->mip->backdoor_write_with_mask(mip_bit, mip_bit);
      difftest_exec(p, 1);
      state->mip->backdoor_write_with_mask(mip_bit, ~mip_bit);
    } else {
      difftest_exec(p, 1);
    }
  }
}

void isa_reg_display(size_t p) {
  diff->diff_display(p);
}

int difftest_store_commit(size_t p, uint64_t *addr, uint64_t *data, uint8_t *mask) {
  // TODO: enable store commit checking after implementing a store commit queue
  return 0;
}

uint64_t difftest_guided_exec(size_t p, void * guide) {
  // TODO: enable guided execution to make Spike enter page fault handler when necessory
  difftest_exec(p, 1);
  return 0;
}

void debug_mem_sync(reg_t addr, void* buf, size_t n) {
  diff->diff_mmio_store(addr, buf, n);
}

void difftest_load_flash(void *flash_bin, size_t size) {
  // TODO
}

void difftest_query_ref(size_t p, void *result_buffer, uint64_t type){
  // TODO
}

void difftest_put_gmaddr(void* addr){
  // TODO
}

}