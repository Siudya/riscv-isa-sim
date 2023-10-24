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

#ifdef CONFIG_USE_SPARSEMM
#include "sparseram.h"
#endif

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
  ctx->priviledgeMode = state->prv;
  ctx->pc = state->pc;
#ifdef CONFIG_RVV
  for (int i = 0; i < NVPR; i++) {
    for (int j = 0; j < (XS_VLEN/64); j++) {
      ctx->vpr[i]._64[j] = sim->get_core(0)->VU.elt<type_sew_t<e64>::type>(i, j, false);
    }
  }

  ctx->vstart = sim->get_core(0)->VU.vstart->read();
  ctx->vxsat = sim->get_core(0)->VU.vxsat->read();
  ctx->vxrm = sim->get_core(0)->VU.vxrm->read();
  //ctx->vcsr = sim->get_core(0)->vcsr->read();
  ctx->vl = sim->get_core(0)->VU.vl->read();
  ctx->vtype = sim->get_core(0)->VU.vtype->read();
  ctx->vlenb = sim->get_core(0)->VU.vlenb;
#endif
  // ctx->debugMode = state->debug_mode;
  // ctx->dcsr = state->dcsr->read();
  // ctx->dpc = state->dpc->read();
  // ctx->dscratch0 = state->csrmap[CSR_DSCRATCH0]->read();
  // ctx->dscratch1 = state->csrmap[CSR_DSCRATCH1]->read();
}

void difftest_t::diff_set_regs(size_t p, void* diff_context, bool on_demand) {
  struct diff_context_t* ctx = (struct diff_context_t*)diff_context;
  state_t * state = sim->get_core(p)->get_state();
  for (int i = 0; i < NXPR; i++) {
    if (!on_demand || state->XPR[i] != ctx->gpr[i]) {
      state->XPR.write(i, ctx->gpr[i]);
    }
  }

  if (!on_demand || state->prv != ctx->priviledgeMode) {
    state->prv = ctx->priviledgeMode;
  }
  if (!on_demand || state->mstatus->read() != ctx->mstatus) {
    state->mstatus->write(ctx->mstatus);
  }
  if (!on_demand || state->sstatus->read() != ctx->sstatus) {
    state->sstatus->write(ctx->sstatus);
  }
  if (!on_demand || state->mepc->read() != ctx->mepc) {
    state->mepc->write(ctx->mepc);
  }
  if (!on_demand || state->sepc->read() != ctx->sepc) {
    state->sepc->write(ctx->sepc);
  }
  if (!on_demand || state->mtval->read() != ctx->mtval) {
    state->mtval->write(ctx->mtval);
  }
  if (!on_demand || state->stval->read() != ctx->stval) {
    state->stval->write(ctx->stval);
  }
  if (!on_demand || state->mtvec->read() != ctx->mtvec) {
    state->mtvec->write(ctx->mtvec);
  }
  if (!on_demand || state->stvec->read() != ctx->stvec) {
    state->stvec->write(ctx->stvec);
  }
  if (!on_demand || state->scause->read() != ctx->scause) {
    state->scause->write(ctx->scause);
  }
  if (!on_demand || state->mcause->read() != ctx->mcause) {
    state->mcause->write(ctx->mcause);
  }
  if (!on_demand || state->satp->read() != ctx->satp) {
    state->satp->write(ctx->satp);
  }
  if (!on_demand || state->mip->read() != ctx->mip) {
    state->mip->write(ctx->mip);
  }
  if (!on_demand || state->mie->read() != ctx->mie) {
    state->mie->write(ctx->mie);
  }
  if (!on_demand || state->csrmap[CSR_MSCRATCH]->read() != ctx->mscratch) {
    state->csrmap[CSR_MSCRATCH]->write(ctx->mscratch);
  }
  if (!on_demand || state->csrmap[CSR_SSCRATCH]->read() != ctx->sscratch) {
    state->csrmap[CSR_SSCRATCH]->write(ctx->sscratch);
  }
  if (!on_demand || state->mideleg->read() != ctx->mideleg) {
    state->mideleg->write(ctx->mideleg);
  }
  if (!on_demand || state->medeleg->read() != ctx->medeleg) {
    state->medeleg->write(ctx->medeleg);
  }
  if (!on_demand || state->pc != ctx->pc) {
    state->pc = ctx->pc;
  }

  for (int i = 0; i < NFPR; i++) {
    if (!on_demand || unboxF64(state->FPR[i]) != ctx->fpr[i]) {
      state->FPR.write(i, freg(f64(ctx->fpr[i])));
    }
  }
#ifdef CONFIG_RVV
for (int i = 0; i < NVPR; i++) {
    for (int j = 0; j < (XS_VLEN/64); j++) {
      sim->get_core(p)->VU.elt<type_sew_t<e64>::type>(i, j, false) = ctx->vpr[i]._64[j];
    }
  }

  if (!on_demand || sim->get_core(p)->VU.vxsat->read() != ctx->vxsat) {
    //sim->get_core(p)->VU.vxsat->write(ctx->vxsat);
    //state->csrmap[CSR_VXSAT]->write(ctx->vxsat);
  }

  if (!on_demand || sim->get_core(p)->VU.vstart->read() != ctx->vstart) {
    sim->get_core(p)->VU.vstart->write_raw(ctx->vstart);
  }
  if (!on_demand || sim->get_core(p)->VU.vxrm->read() != ctx->vxrm) {
    sim->get_core(p)->VU.vxrm->write_raw(ctx->vxrm);
  }
#if 0
  if (!on_demand || sim->get_core(p)->VU.vcsr->read() != ctx->vcsr) {
    sim->get_core(p)->vcsr->write_raw(ctx->vcsr);
  }
#endif
  if (!on_demand || sim->get_core(p)->VU.vl->read() != ctx->vl) {
    sim->get_core(p)->VU.vl->write_raw(ctx->vl);
  }
  if (!on_demand || sim->get_core(p)->VU.vtype->read() != ctx->vtype) {
    sim->get_core(p)->VU.vtype->write_raw(ctx->vtype);
  }
  if (!on_demand || sim->get_core(p)->VU.vlenb != ctx->vlenb) {
    sim->get_core(p)->VU.vlenb = ctx->vlenb;
  }
#endif
  // state->debug_mode = ctx->debugMode;
  // state->dcsr->write(ctx->dcsr);
  // state->dpc->write(ctx->dpc);
  // state->csrmap[CSR_DSCRATCH0]->write(ctx->dscratch0);
  // state->csrmap[CSR_DSCRATCH1]->write(ctx->dscratch1);
}

void difftest_t::diff_memcpy(size_t p, reg_t dest, void* src, size_t n) {
  #ifdef CONFIG_USE_SPARSEMM
  printf("[sp-ram] start sync RAM from dut, please wait ...\n");
  float dsize = 0;
  SparseRam *sp_mem = (SparseRam *)src;
  auto fc = [&](paddr_t addr, size_t len, void* buff){
    reg_t mem_start;
    dsize += len;
    auto desc = this->sim->bus.find_device(addr);
    auto mem = dynamic_cast<mem_t*>(desc.second);
    if (mem == NULL){
      mem = new mem_t(len);
      mem_start = addr;
      this->sim->bus.add_device(mem_start, mem);
    }else{
      mem_start = desc.first;
    }
    assert(addr >= mem_start);
    auto mem_write_addr = addr - mem_start;
    int64_t mem_remain_size = mem->size() - mem_write_addr;
    if (mem_remain_size >= len){
      mem->store(mem_write_addr, len, (const uint8_t* )buff);
      return;
    }
    mem->store(mem_write_addr, mem_remain_size, (const uint8_t* )buff);
    // need add new mem
    auto n_size = - mem_remain_size;
    auto new_mem = new mem_t(n_size);
    this->sim->bus.add_device(mem_start + mem->size(), new_mem);
    new_mem->store(0, n_size, (const uint8_t* )((reg_t)buff + mem_remain_size));
  };

  sp_mem->copy_bytes(fc);
  printf("[sp-ram] copy data (%.2f kB) from dut complete\n", dsize/1024.0);
  #else
  mmu_t* mmu = sim->get_core(p)->get_mmu();
  for (size_t i = 0; i < n; i++) {
    mmu->store(dest+i, *((uint8_t*)src+i));
  }
  #endif
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
  #ifdef CONFIG_RVV
  vectorUnit_t vu = sim->get_core(p)->VU;
  for (i = 0; i < 32; i++) {
    printf("%4s: " FMT_WORD "_%016lx" " ",
      vr_name[i],
      vu.elt<type_sew_t<e64>::type>(i, 1, false),
      vu.elt<type_sew_t<e64>::type>(i, 0, false));
    if (i % 2 == 1) {
      printf("\n");
    }
  }
  #endif
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
            /*default_varch=*/"vlen:128,elen:64,vstartalu:1",
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

  for(auto const& pair : diff->sim->get_harts()) {
    pair.second->set_pmp_granularity(1UL << 12);  // 4KB PMP granularity
  }
}

void difftest_memcpy(size_t p, paddr_t addr, void *buf, size_t n, bool direction) {
  if (direction == DUT_TO_REF) {
    diff->diff_memcpy(p, addr, buf, n);
  } else {
    assert(0);
  }
}

void difftest_regcpy(size_t p, void* dut, bool direction, bool on_demand) {
  if (direction == DUT_TO_REF) {
    diff->diff_set_regs(p, dut, on_demand);
  } else {
    diff->diff_get_regs(p, dut);
  }
}

void difftest_csrcpy(size_t p, void *dut, bool direction) {
  // TODO
}

void difftest_uarchstatus_cpy(size_t p, void *dut, bool direction) {
  // set LR-SC status
  if (direction == DUT_TO_REF) {
    struct sync_state_t* ms = (struct sync_state_t*)dut;
    // XS core does not give address information
    // If DUT lrsc is valid, we just assume REF MMU has the same address
    // If DUT lrsc is invalid, we clear the reservation
    if (!ms->lrscValid)
      diff->sim->get_core(p)->get_mmu()->yield_load_reservation();
  } else {
    // This is not used in normal difftest, not tested for now
    struct sync_state_t ms;
    ms.lrscAddr = diff->sim->get_core(p)->get_mmu()->get_load_reservation_address();
    ms.lrscValid = (ms.lrscAddr == (reg_t)-1) ? 0 : 1;
  }
}

void difftest_uarchstatus_sync(size_t p, void *dut) {
  //ref->update_uarch_status(dut);
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

void difftest_display(size_t p) {
  diff->diff_display(p);
}

int difftest_store_commit(size_t p, uint64_t *addr, uint64_t *data, uint8_t *mask) {
  // TODO: enable store commit checking after implementing a store commit queue
  return 0;
}

void difftest_guided_exec(size_t p, void * guide) {
  // TODO: enable guided execution to make Spike enter page fault handler when necessory
  difftest_exec(p, 1);
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
