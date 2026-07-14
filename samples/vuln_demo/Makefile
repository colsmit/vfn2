CC ?= clang
CFLAGS ?= -O2 -fno-stack-protector -Wall -Wextra
LDFLAGS ?=
SRC_DIR := src
BUILD_DIR := build
TARGET := $(BUILD_DIR)/vuln_demo
STRIPPED := $(BUILD_DIR)/vuln_demo_stripped
FORTIFIED_TARGET := $(BUILD_DIR)/vuln_demo_fortified
FORTIFIED_STRIPPED := $(BUILD_DIR)/vuln_demo_fortified_stripped
SRCS := $(wildcard $(SRC_DIR)/*.c)

UNAME_S := $(shell uname -s)
STRIP_FLAGS := --strip-all

ifeq ($(UNAME_S),Darwin)
STRIP_FLAGS := -u -r
endif

.PHONY: all clean run

all: $(TARGET) $(STRIPPED) $(FORTIFIED_TARGET) $(FORTIFIED_STRIPPED)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 $(SRCS) -o $@ $(LDFLAGS)

$(STRIPPED): $(TARGET)
	strip $(STRIP_FLAGS) -o $@ $(TARGET)

$(FORTIFIED_TARGET): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 $(SRCS) -o $@ $(LDFLAGS)

$(FORTIFIED_STRIPPED): $(FORTIFIED_TARGET)
	strip $(STRIP_FLAGS) -o $@ $(FORTIFIED_TARGET)

run: $(STRIPPED)
	$(STRIPPED) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

clean:
	rm -rf $(BUILD_DIR)
