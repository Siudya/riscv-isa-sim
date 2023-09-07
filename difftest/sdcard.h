#include <sstream>
#include "../riscv/abstract_device.h"

#define SDCARD_BASE        0x40002000
#define SDCARD_SIZE        0x80

class sdcard_t : public abstract_device_t {
public:
  sdcard_t();
  bool load(reg_t addr, size_t len, uint8_t *bytes);
  bool store(reg_t addr, size_t len, const uint8_t *bytes);
  size_t size() { return SDCARD_SIZE; }
  void init();
};
