# pam_atlas.so and its tests. macOS only (OpenDirectory, CFOpenDirectory).
#   make            build pam_atlas.so (universal when the toolchain allows)
#   make test       unit tests of the conversation logic (no PAM, no root)
#   sudo make itest integration test through the real PAM stack with a fake helper (needs root to write /etc/pam.d)
CC      ?= clang
ARCHS   ?= -arch arm64 -arch x86_64
MINVER  ?= -mmacosx-version-min=13.0
CFLAGS  ?= -O2 -g -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 $(MINVER)
OUT     ?= build

all: $(OUT)/pam_atlas.so

$(OUT):
	mkdir -p $(OUT)

$(OUT)/pam_atlas.so: pam_atlas.c atlas_pam_core.c atlas_pam_core.h | $(OUT)
	$(CC) $(ARCHS) $(CFLAGS) -fPIC -bundle -o $@ pam_atlas.c atlas_pam_core.c -lpam -framework CoreFoundation -framework OpenDirectory

# The test module swaps the password check and the helper path; it is never installed.
$(OUT)/pam_atlas_test.so: pam_atlas.c atlas_pam_core.c atlas_pam_core.h | $(OUT)
	$(CC) $(CFLAGS) -DATLAS_PAM_TESTING -DATLAS_BEGIN_TIMEOUT_MS=1500 -DATLAS_PUSH_TIMEOUT_MS=1500 -DATLAS_CODE_TIMEOUT_MS=1500 \
	  -fPIC -bundle -o $@ pam_atlas.c atlas_pam_core.c -lpam -framework CoreFoundation -framework OpenDirectory

$(OUT)/core_test: tests/core_test.c atlas_pam_core.c atlas_pam_core.h | $(OUT)
	$(CC) $(CFLAGS) -I. -o $@ tests/core_test.c atlas_pam_core.c

$(OUT)/harness: tests/harness.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ tests/harness.c -lpam

test: $(OUT)/core_test
	$(OUT)/core_test

itest: $(OUT)/pam_atlas_test.so $(OUT)/harness
	sh tests/itest.sh $(OUT)

clean:
	rm -rf $(OUT)

.PHONY: all test itest clean
