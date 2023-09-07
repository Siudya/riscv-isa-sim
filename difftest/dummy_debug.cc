#include "dummy_debug.h"
#include <string>
#include <cassert>


dummy_debug_t::~dummy_debug_t()
{

}

bool dummy_debug_t::load(reg_t addr, size_t len, uint8_t* bytes)
{
  // addr is internal addr!
  assert(addr >= DM_BASE_ADDR);
  assert(addr + len < DM_END_ADDR);
  int offset = (addr - DM_BASE_ADDR) / sizeof(uint8_t);
  memcpy(bytes, &dummy_debug_mem[offset], len);

  return true;
}


// FIXME: from Xiangshan's comment, debug mem should be updated by DUT.
// Here it is written through Spike for easily implementing interface
// debug_mem_sync.
// Find a better way to implement it.
bool dummy_debug_t::store(reg_t addr, size_t len, const uint8_t* bytes)
{
  // nothing is actually stored 
  // because currently spike dm does not need to be working
  assert(addr >= DM_BASE_ADDR);
  assert(addr + len < DM_END_ADDR);
  int offset = (addr - DM_BASE_ADDR) / sizeof(uint8_t);
  memcpy((void *) (&dummy_debug_mem[offset]), bytes, len);
  return true;
}

// bool dummy_debug_t::update_dummy_mem(reg_t addr, size_t len, const uint8_t* bytes)
// {
//   assert(addr >= DM_BASE_ADDR);
//   assert(addr + len < DM_END_ADDR);
//   return memcpy((void *) (addr - DM_BASE_ADDR + dummy_debug_mem), bytes, len);
// }

std::string dummy_debug_generate_dts(const sim_t *sim) { return ""; }

dummy_debug_t *dummy_debug_parse_from_fdt(const void *fdt, const sim_t *sim,
                                          reg_t *base) {
  *base = DM_BASE_ADDR;
  return new dummy_debug_t();
}

REGISTER_DEVICE(dummy_debug, dummy_debug_parse_from_fdt, dummy_debug_generate_dts)