// See LICENSE for license details.
#ifndef _RISCV_PLATFORM_H
#define _RISCV_PLATFORM_H

#define DEFAULT_KERNEL_BOOTARGS "console=ttyS0 earlycon"
#define DEFAULT_RSTVEC     0x00100000
#define CLINT_BASE         0x38000000
#define CLINT_SIZE         0x000c0000
#define PLIC_BASE          0x3c000000
#define PLIC_SIZE          0x04000000
#define PLIC_NDEV          31
#define PLIC_PRIO_BITS     4
#define NS16550_BASE       0x10000000
#define NS16550_SIZE       0x100
#define NS16550_REG_SHIFT  0
#define NS16550_REG_IO_WIDTH 1
#define NS16550_INTERRUPT_ID 1
#define EXT_IO_BASE        0x40000000
#define DRAM_BASE          0x1000000000

#endif
