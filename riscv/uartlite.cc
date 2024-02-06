#include <sstream>
#include "devices.h"
#include "processor.h"
#include "term.h"
#include "sim.h"
#include "dts.h"

#define UARTLITE_BASE_ADDR 0x37000000L
#define UARTLITE_END_ADDR 0x37000010L
#define CH_OFFSET 0
#define UARTLITE_RX_FIFO  0x0
#define UARTLITE_TX_FIFO  0x4
#define UARTLITE_STAT_REG 0x8
#define UARTLITE_CTRL_REG 0xc

#define UARTLITE_MEM_SIZE_BYTE (UARTLITE_END_ADDR - UARTLITE_BASE_ADDR) / sizeof(uint8_t)

uartlite_t::~uartlite_t(){}

bool uartlite_t::load(reg_t addr, size_t len, uint8_t* bytes){
  switch (addr) {
    case UARTLITE_STAT_REG:
      memset(bytes, 0, len);
  }
  return true;
}

bool uartlite_t::store(reg_t addr, size_t len, const uint8_t* bytes) {
  switch (addr) {
    case UARTLITE_TX_FIFO:
      putc(*bytes, stdout);
  }
  return true;
}


std::string uartlite_generate_dts(const sim_t *sim) {
  std::stringstream s;
  s << std::hex
    << "    SERIAL0: uartlite@" << UARTLITE_BASE_ADDR << " {\n"
       "      compatiable = \"xilinx,uartlite\";\n"
       "      reg = <0x0 0x" << UARTLITE_BASE_ADDR << " 0x0 0x10>;\n"
       "      };\n";
  return s.str();
}

uartlite_t* uartlite_parse_from_fdt(const void *fdt, const sim_t *sim,
                                          reg_t *base, const std::vector<std::string>& sargs) {
  *base = UARTLITE_BASE_ADDR;
  return new uartlite_t();
}

REGISTER_DEVICE(uartlite, uartlite_parse_from_fdt, uartlite_generate_dts)