REPO_PATH ?= ..
GUEST_ISA = riscv64
BUILD_DIR = ./build
NAME = $(GUEST_ISA)-spike-so
BINARY = $(BUILD_DIR)/$(NAME)

SPIKE = $(REPO_BUILD_PATH)/spike
REPO_BUILD_PATH = $(REPO_PATH)/build
REPO_MAKEFILE = $(REPO_BUILD_PATH)/Makefile

NUM_CORES  ?= 1

CONFIGURE_FLAGS =         \
	-q --enable-dirty     \
	--with-boost=no       \
	--with-boost-asio=no  \
	--with-boost-regex=no

INC_DEPENDENCIES = fesvr riscv disasm customext fdt softfloat spike_main spike_dasm build
INC_PATH  = -I$(REPO_PATH) $(addprefix -I$(REPO_PATH)/, $(INC_DEPENDENCIES))
LIB_DEPENDENCIES = libspike_main.a libriscv.a libdisasm.a libsoftfloat.a libfesvr.a libfdt.a
INC_LIBS  = $(addprefix $(REPO_PATH)/build/, $(LIB_DEPENDENCIES))
SRCS = $(shell find . -name '*.cc') $(shell find . -name '*.h')
SRCS += $(REPO_PATH)/spike_main/spike.cc
CXXFLAGS = -O3 --std=c++17 -shared -fPIC -DNUM_CORES=$(NUM_CORES)

ifneq ($(CONFIG_USE_SPARSEMM),)
CXXFLAGS += -DCONFIG_USE_SPARSEMM
$(warning "Use Sparse Ram, when make difftest, plase use: CONFIG_USE_SPARSEMM=1")
endif

ifneq ($(DEBUG),)
CONFIGURE_FLAGS += --enable-commitlog
CXXFLAGS += -DDIFFTEST_LOG_FILE=\"$(NOOP_HOME)/build/spike.log\"
endif

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(REPO_MAKEFILE): $(REPO_PATH)/configure
	mkdir -p $(@D)
	cd $(@D) && $(abspath $(REPO_PATH))/configure $(CONFIGURE_FLAGS)

$(SPIKE): $(REPO_MAKEFILE)
	$(MAKE) -C $(^D)

$(BINARY): $(BUILD_DIR) $(SPIKE) $(SRCS)
	g++ $(CXXFLAGS) $(INC_PATH) $(SRCS) $(INC_LIBS) -o $@

clean:
	rm -rf $(BUILD_DIR) $(REPO_BUILD_PATH)

.DEFAULT_GOAL = $(BINARY)

.PHONY: clean $(SPIKE)
