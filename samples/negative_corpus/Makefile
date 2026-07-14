CC ?= clang
CFLAGS ?= -O0 -g0 -fno-stack-protector -fno-builtin-memcpy -Wall -Wextra
LDFLAGS ?= -no-pie
SRC_DIR := src
BUILD_ROOT ?= ../../tmp/negative_overflow_sources
BUILD_DIR := $(BUILD_ROOT)/guarded_heartbleed
TARGET := $(BUILD_DIR)/guarded_heartbleed
STRIPPED := $(BUILD_DIR)/guarded_heartbleed_stripped
SRCS := $(SRC_DIR)/guarded_heartbleed.c

UNAME_S := $(shell uname -s)
STRIP_FLAGS := --strip-all

ifeq ($(UNAME_S),Darwin)
STRIP_FLAGS := -u -r
LDFLAGS :=
endif

.PHONY: all clean

all: $(TARGET) $(STRIPPED)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

$(STRIPPED): $(TARGET)
	strip $(STRIP_FLAGS) -o $@ $(TARGET)

clean:
	rm -rf $(BUILD_DIR)
