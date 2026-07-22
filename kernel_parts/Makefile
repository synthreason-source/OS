# ============================================================
#  Makefile – Bare-metal OS with Bochs CPU emulation + BusyBox
# ============================================================

ISODIR   := iso
MULTIBOOT := $(ISODIR)/boot/main.elf
MAIN     := main.iso
DISK_IMG := disk.img

# ── Compiler flags ───────────────────────────────────────────
CXXFLAGS := -ffreestanding -O2 -Wall -Wextra \
            -fno-use-cxa-atexit -std=c++17    \
            -fno-exceptions -fno-rtti -m32    \
            -fno-stack-protector              \
            -fno-pie -fno-pic                 \
            -include fixes.h                  \
            -include instrument_stub.h

# ── Bochs 2.0 ────────────────────────────────────────────────
# Source: the official bochs-emu/Bochs GitHub mirror, tag REL_2_0_FINAL
# (verified to exist and download correctly; the old SourceForge
# "bochs-2.0.tar.gz" path used previously could not be confirmed to
# exist and was producing bad downloads). The tag archive's top-level
# layout is Bochs-REL_2_0_FINAL/bochs/... , so extraction strips 2
# path components to land the real source tree directly at $(BOCHS_DIR).
#
# Bochs 2.0's internals are structurally different from what
# bochs_glue.cpp/bochs_infra.cpp were written against (Bochs 2.7):
#   - no gui/paramtree.cc split (param-tree classes live in
#     gui/siminterface.cc instead, with an older API)
#   - no cpu/cpudb/ (CPU model database; added in 2.5)
#   - fpu/ is a top-level directory here, not cpu/fpu/ (that move
#     happened in 2.6.1)
# The $(BOCHS_CPU_LIB) recipe below also applies several small source
# patches (via patch-bochs-2.0.sh) needed to build this 2003-era code
# with a modern (GCC 13 / glibc) toolchain - see that script for the
# details of each fix. cpu/, fpu/, and memory/ have been verified to
# build cleanly after these patches; the remaining glue-code port
# (paramtree API -> siminterface API) is still in progress.
BOCHS_VERSION   := 2.0
BOCHS_TAG       := REL_$(subst .,_,$(BOCHS_VERSION))_FINAL
BOCHS_DIR       := bochs-$(BOCHS_VERSION)
BOCHS_ARCHIVE   := $(BOCHS_DIR)-src.tar.gz
BOCHS_URL       := https://codeload.github.com/bochs-emu/Bochs/tar.gz/refs/tags/$(BOCHS_TAG)
BOCHS_CPU_LIB   := $(BOCHS_DIR)/cpu/libcpu.a

# Base64-encoded copy of the Bochs 2.0 patch script, embedded directly
# so the fix can never go stale relative to a separate file on disk -
# this IS the source of truth; patch-bochs-2.0.sh is (re)written from it
# fresh on every build. See the comments inside the script (or run it
# with no args after decoding) for what each numbered fix addresses.
define BOCHS_PATCH_SCRIPT_B64
IyEvYmluL3NoCiMgcGF0Y2gtYm9jaHMtMi4wLnNoIOKAlCBmaXggQm9jaHMgMi4wICgyMDAzKSBzb3VyY2UgdG8gYnVpbGQgd2l0aCBhCiMgbW9kZXJuIEdDQy9nbGliYyB0b29sY2hhaW4uIFJ1biBvbmNlLCByaWdodCBhZnRlciBleHRyYWN0aW5nIHRoZQojIHRhcmJhbGwgYW5kIGJlZm9yZSAuL2NvbmZpZ3VyZS4gSWRlbXBvdGVudCAoc2FmZSB0byByZS1ydW4pLgojCiMgVXNhZ2U6IC4vcGF0Y2gtYm9jaHMtMi4wLnNoIDxib2Nocy0yLjAtZGlyPgpzZXQgLWUKRElSPSIkMSIKaWYgWyAteiAiJERJUiIgXSB8fCBbICEgLWQgIiRESVIiIF07IHRoZW4KICAgIGVjaG8gInVzYWdlOiAkMCA8Ym9jaHMtMi4wLXNvdXJjZS1kaXI+IiA+JjIKICAgIGV4aXQgMQpmaQpTRU5USU5FTD0iJERJUi8uY2xhdWRlLXBhdGNoZWQiCmlmIFsgLWYgIiRTRU5USU5FTCIgXTsgdGhlbgogICAgZWNobyAiPj4+ICRESVIgYWxyZWFkeSBwYXRjaGVkLCBza2lwcGluZy4iCiAgICBleGl0IDAKZmkKCmVjaG8gIj4+PiBQYXRjaGluZyAkRElSIGZvciBtb2Rlcm4tdG9vbGNoYWluIGNvbXBhdGliaWxpdHkuLi4iCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIEZpeCAxICYgMjogZnB1L3N0dWJzL2xpbnV4L3R5cGVzLmggYW5kIGZwdS9zdHVicy9hc20vdHlwZXMuaCBzaGFkb3cKIyB0aGUgcmVhbCBzeXN0ZW0gPGxpbnV4L3R5cGVzLmg+IC8gPGFzbS90eXBlcy5oPiAodGhleSBjbGFpbSB0aGUKIyBzYW1lIGluY2x1ZGUgZ3VhcmQgd2l0aG91dCBwcm92aWRpbmcgdGhlIF9fdTY0L19fczY0L2V0YyB0eXBlZGVmcwojIHRoYXQgbW9kZXJuIGdsaWJjJ3MgPGJpdHMvc3RhdHguaD4gbmVlZHMpLiBCb2NocyB3cm90ZSB0aGVzZSBpbgojIDIwMDMgZm9yIHBsYXRmb3JtcyBsYWNraW5nIExpbnV4IGtlcm5lbCBoZWFkZXJzOyBvbiBhIHJlYWwgTGludXgKIyBob3N0IHRoZXkgbXVzdCBmYWxsIHRocm91Z2ggdG8gdGhlIHJlYWwgaGVhZGVycyBpbnN0ZWFkLgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQpjYXQgPiAiJERJUi9mcHUvc3R1YnMvbGludXgvdHlwZXMuaCIgPDwgJ0VPRicKI2lmIGRlZmluZWQoX19saW51eF9fKQovKiBPbiBhIHJlYWwgTGludXggaG9zdCB0aGUgc3lzdGVtIGFscmVhZHkgaGFzIGEgY29tcGxldGUsIGNvcnJlY3QKICogPGxpbnV4L3R5cGVzLmg+IChuZWVkZWQgdHJhbnNpdGl2ZWx5IGJ5IG1vZGVybiBnbGliYydzCiAqIDxiaXRzL3N0YXR4Lmg+IGZvciBfX3U2NC9fX3M2NC9ldGMpLiBUaGlzIDIwMDMtZXJhIHN0dWIgcHJlZGF0ZXMKICogdGhhdCBkZXBlbmRlbmN5OyBpdCB1c2VkIHRvIGRlZmluZSB0aGUgU0FNRSBpbmNsdWRlIGd1YXJkCiAqIChfTElOVVhfVFlQRVNfSCkgYXMgdGhlIHJlYWwgaGVhZGVyIHdpdGhvdXQgcHJvdmlkaW5nIHRob3NlCiAqIHR5cGVkZWZzLCB3aGljaCBtYWRlIHRoZSByZWFsIGhlYWRlciBlZmZlY3RpdmVseSB1bnJlYWNoYWJsZQogKiAoaXRzIG93biBndWFyZCBhbHJlYWR5IGxvb2tlZCAiY2xhaW1lZCIpIGFuZCBsZWZ0IF9fdTY0IGV0Yy4KICogdW5kZWZpbmVkLiBGaXg6IGxldCB0aGUgcmVhbCBoZWFkZXIgY2xhaW0gaXRzIG93biBndWFyZCB2aWEKICogI2luY2x1ZGVfbmV4dCBGSVJTVCwgdGhlbiBhZGQgYm9jaHMncyBleHRyYSBCU0Qtc3R5bGUgYWxpYXNlcwogKiBiZWxvdyB1bmRlciBhIGRpZmZlcmVudCBndWFyZCBzbyB3ZSBuZXZlciBjb2xsaWRlIGFnYWluLiAqLwojaW5jbHVkZV9uZXh0IDxsaW51eC90eXBlcy5oPgojZW5kaWYKCiNpZm5kZWYgX0JYX0xJTlVYX1RZUEVTX1NUVUJfSAojZGVmaW5lIF9CWF9MSU5VWF9UWVBFU19TVFVCX0gKCiNpZm5kZWYgX19BU1NFTUJMWV9fCgojZGVmaW5lIHVfY2hhciBieF91X2NoYXIKI2RlZmluZSB1X3Nob3J0IGJ4X3Vfc2hvcnQKI2RlZmluZSB1X2ludCBieF91X2ludAojZGVmaW5lIHVfbG9uZyBieF91X2xvbmcKI2RlZmluZSB1bmNoYXIgYnhfdW5jaGFyCiNkZWZpbmUgdXNob3J0IGJ4X3VzaG9ydAojZGVmaW5lIHVpbnQgYnhfdWludAojZGVmaW5lIHVsb25nIGJ4X3Vsb25nCgovKiBic2QgKi8KdHlwZWRlZiB1bnNpZ25lZCBjaGFyICAgICAgICAgICB1X2NoYXI7CnR5cGVkZWYgdW5zaWduZWQgc2hvcnQgICAgICAgICAgdV9zaG9ydDsKdHlwZWRlZiB1bnNpZ25lZCBpbnQgICAgICAgICAgICB1X2ludDsKdHlwZWRlZiB1bnNpZ25lZCBsb25nICAgICAgICAgICB1X2xvbmc7CgovKiBzeXN2ICovCnR5cGVkZWYgdW5zaWduZWQgY2hhciAgICAgICAgICAgdW5jaGFyOwp0eXBlZGVmIHVuc2lnbmVkIHNob3J0ICAgICAgICAgIHVzaG9ydDsKdHlwZWRlZiB1bnNpZ25lZCBpbnQgICAgICAgICAgICB1aW50Owp0eXBlZGVmIHVuc2lnbmVkIGxvbmcgICAgICAgICAgIHVsb25nOwoKI2lmbmRlZiBOVUxMCiNkZWZpbmUgTlVMTCAoKHZvaWQgKikgMCkKI2VuZGlmCgojZW5kaWYKCiNlbmRpZiAvKiBfQlhfTElOVVhfVFlQRVNfU1RVQl9IICovCkVPRgoKY2F0ID4gIiRESVIvZnB1L3N0dWJzL2FzbS90eXBlcy5oIiA8PCAnRU9GJwojaWZuZGVmIF9JMzg2X1RZUEVTX0gKI2RlZmluZSBfSTM4Nl9UWVBFU19ICgojaWZuZGVmIF9fQVNTRU1CTFlfXwojaWYgZGVmaW5lZChfX2xpbnV4X18pCi8qIFNhbWUgaXNzdWUgYXMgZnB1L3N0dWJzL2xpbnV4L3R5cGVzLmg6IHRoaXMgMjAwMy1lcmEgZW1wdHkgc3R1YgogKiBzaGFkb3dzIHRoZSByZWFsIHN5c3RlbSA8YXNtL3R5cGVzLmg+ICh3aGljaCBkZWZpbmVzIF9fdTY0L19fczY0LwogKiBldGMpIHZpYSAtSS4vc3R1YnMgY29taW5nIGJlZm9yZSB0aGUgc3lzdGVtIGluY2x1ZGUgcGF0aC4gRmFsbAogKiB0aHJvdWdoIHRvIHRoZSByZWFsIGhlYWRlciBpbnN0ZWFkIG9mIHNpbGVudGx5IHByb3ZpZGluZyBub3RoaW5nLiAqLwojaW5jbHVkZV9uZXh0IDxhc20vdHlwZXMuaD4KI2VuZGlmCiNlbmRpZgoKI2VuZGlmICAvKiBfSTM4Nl9UWVBFU19IICovCkVPRgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KIyBGaXggMzogYm9jaHMncyBvd24gdG9wLWxldmVsIGRlYnVnLyBkaXJlY3RvcnkgKHRoZSBpbnRlcmFjdGl2ZQojIGRlYnVnZ2VyIHN1YnN5c3RlbSkgY29udGFpbnMgYSBkZWJ1Zy5oIGZpbGUgdGhhdCBjb2xsaWRlcyB3aXRoCiMgbGlic3RkYysrJ3Mgb3duIDxkZWJ1Zy9kZWJ1Zy5oPiAodXNlZCBpbnRlcm5hbGx5IGJ5IDxiaXRzLwojIHN0bF9hbGdvYmFzZS5oPiBmb3IgaXRlcmF0b3IgZGVidWctbW9kZSBkZWNsYXJhdGlvbnMpLiBCZWNhdXNlIC1JLi4KIyBwdXRzIHRoZSBib2NocyByb290IG9uIHRoZSBpbmNsdWRlIHBhdGgsIGFueSBDKysgZmlsZSB0aGF0IHB1bGxzIGluCiMgPG1hdGguaD4vPGNtYXRoPiBlbmRzIHVwIGZpbmRpbmcgQk9DSFMncyBkZWJ1Zy9kZWJ1Zy5oIGluc3RlYWQgb2YKIyB0aGUgcmVhbCBzeXN0ZW0gb25lLCB3aGljaCBzaWxlbnRseSBkcm9wcyB0aGUgZm9yd2FyZCBkZWNsYXJhdGlvbgojIG9mICJuYW1lc3BhY2UgX19nbnVfZGVidWciIGFuZCBicmVha3MgdGhlIFNUTCBoZWFkZXJzIHdpdGgKIyBjb25mdXNpbmcgImV4cGVjdGVkIGluaXRpYWxpemVyIGJlZm9yZSAnPCcgdG9rZW4iIGVycm9ycy4KIyBHQ0MgYWx3YXlzIHByZWZlcnMgaXRzIG93biBkZWZhdWx0IHN5c3RlbSBkaXJzJyAqcG9zaXRpb24qIGZvcgojIHBhdGhzIHRoYXQgbWF0Y2ggdGhlbSwgc28gcmVvcmRlcmluZyAtSSBmbGFncyBjYW5ub3QgZml4IHRoaXMgLSB0aGUKIyBjb2xsaWRpbmcgZmlsZW5hbWUgaGFzIHRvIGdvLiBSZW5hbWluZyBqdXN0IHRoZSBmaWxlIChub3QgdGhlCiMgd2hvbGUgZGVidWcvIGRpcmVjdG9yeSwgd2hpY2ggY29uZmlndXJlJ3MgQUNfT1VUUFVUIHN0aWxsIGV4cGVjdHMKIyB0byBmaW5kIGF0IHRoYXQgcGF0aCkgaXMgdGhlIG1pbmltYWwgZml4LgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQppZiBbIC1mICIkRElSL2RlYnVnL2RlYnVnLmgiIF07IHRoZW4KICAgIG12ICIkRElSL2RlYnVnL2RlYnVnLmgiICIkRElSL2RlYnVnL2J4ZGVidWcuaCIKICAgIHNlZCAtaSAncyNpbmNsdWRlICJkZWJ1Zy9kZWJ1Z1wuaCIjaW5jbHVkZSAiZGVidWcvYnhkZWJ1Zy5oIiMnICIkRElSL2JvY2hzLmgiCiAgICAjIFVwZGF0ZSB0aGUgKG5vbi1mdW5jdGlvbmFsLCBkZXBlbmRlbmN5LXRyYWNraW5nLW9ubHkpIE1ha2VmaWxlLmluCiAgICAjIHJlZmVyZW5jZXMgdG9vLCBzbyBgbWFrZWAgZG9lc24ndCBjaG9rZSBsb29raW5nIGZvciBhIHJ1bGUgdG8KICAgICMgYnVpbGQgYSBmaWxlIHRoYXQgbm8gbG9uZ2VyIGV4aXN0cy4KICAgIGdyZXAgLXJsICJkZWJ1Zy9kZWJ1Z1wuaCIgIiRESVIiLyovTWFrZWZpbGUuaW4gIiRESVIiL01ha2VmaWxlLmluIDI+L2Rldi9udWxsIHwgXAogICAgICAgIHhhcmdzIC1yIHNlZCAtaSAncyNkZWJ1Zy9kZWJ1Z1wuaCNkZWJ1Zy9ieGRlYnVnLmgjZycKZmkKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgRml4IDQ6IGZwdS9zdHVicy9saW51eC9saW5rYWdlLmgncyAiYXNtbGlua2FnZSIgbWFjcm8gYWRkcwojIF9fYXR0cmlidXRlX18oKHJlZ3Bhcm0oMCkpKSBvbiBpMzg2LCBtaW1pY2tpbmcgdGhlIExpbnV4IGtlcm5lbCdzCiMgY2FsbGluZyBjb252ZW50aW9uIGZvciBhc21saW5rYWdlIGZ1bmN0aW9ucy4gZnB1X3Byb3RvLmggZGVjbGFyZXMKIyBmdW5jdGlvbnMgbGlrZSBhcml0aF9vdmVyZmxvdygpIFdJVEhPVVQgdGhpcyBhdHRyaWJ1dGUsIGJ1dCB0aGUKIyBjb3JyZXNwb25kaW5nIGRlZmluaXRpb25zIGluIGVycm9ycy5jIHVzZSAiYXNtbGlua2FnZSIgYW5kIHNvCiMgRE8gaGF2ZSBpdC4gT2xkZXIgR0NDIHRvbGVyYXRlZCB0aGUgbWlzbWF0Y2g7IEdDQyAxMyB0cmVhdHMgYQojIHJlZ3Bhcm0gZGlmZmVyZW5jZSBiZXR3ZWVuIGEgZGVjbGFyYXRpb24gYW5kIGl0cyBkZWZpbml0aW9uIGFzIGEKIyBoYXJkICJjb25mbGljdGluZyB0eXBlcyIgZXJyb3IuIFNpbmNlIGZwdS8gaGVyZSBpcyBhIHBsYWluCiMgdXNlcnNwYWNlIHN0YXRpYyBsaWJyYXJ5IChub3QgbGlua2VkIGFnYWluc3QgcmVhbCBrZXJuZWwgb2JqZWN0CiMgY29kZSksIHRoZSBrZXJuZWwtQUJJIGF0dHJpYnV0ZSBzZXJ2ZXMgbm8gcHVycG9zZSAtIGRyb3AgaXQuCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmlmIFsgLWYgIiRESVIvZnB1L3N0dWJzL2xpbnV4L2xpbmthZ2UuaCIgXTsgdGhlbgogICAgc2VkIC1pIFwKICAgICAgICAncy9eI2lmIGRlZmluZWQgX19pMzg2X18gXCZcJiAoX19HTlVDX18gPiAyIHx8IF9fR05VQ19NSU5PUl9fID4gNykkLyNpZiAwIFwmXCYgZGVmaW5lZCBfX2kzODZfXyBcJlwmIChfX0dOVUNfXyA+IDIgfHwgX19HTlVDX01JTk9SX18gPiA3KSBcLyogcmVncGFybSgwKSBkaXNhYmxlZDogc2VlIHBhdGNoLWJvY2hzLTIuMC5zaCAqXC8vJyBcCiAgICAgICAgIiRESVIvZnB1L3N0dWJzL2xpbnV4L2xpbmthZ2UuaCIKZmkKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgRml4IDU6IGNvbmZpZ3VyZSdzIHJlYWRsaW5lIGRldGVjdGlvbiAoImNoZWNraW5nIGlmIHJlYWRsaW5lIHdvcmtzCiMgd2l0aG91dC93aXRoIC1sY3Vyc2VzIikgdXNlcyBBQ19UUllfUlVOLCB3aGljaCBuZWVkcyB0byBhY3R1YWxseQojIEVYRUNVVEUgYSBjb21waWxlZCAzMi1iaXQgdGVzdCBwcm9ncmFtLiBQYXNzaW5nIC0taG9zdD1pNjg2LWxpbnV4LWdudQojIGRvZXNuJ3QgYnkgaXRzZWxmIG1ha2UgYXV0b2NvbmYgcmVmdXNlIHRoaXMgKGl0IGRlY2lkZXMgYmFzZWQgb24KIyB3aGV0aGVyIGEgY29tcGlsZWQgdGVzdCBiaW5hcnkgYWN0dWFsbHkgcnVucywgbm90IG9uIHRoZSAtLWhvc3QKIyBzdHJpbmcpLCBidXQgb24gaG9zdHMgdGhhdCBjYW4gY29tcGlsZSAzMi1iaXQgYmluYXJpZXMgeWV0IGNhbid0CiMgZXhlY3V0ZSB0aGVtIChlLmcuIG5vIGkzODYgZXhlY3V0aW9uIHN1cHBvcnQgYXQgYWxsKSwgYXV0b2NvbmYKIyBjb25jbHVkZXMgInllcywgY3Jvc3MgY29tcGlsaW5nIiBhbmQgdGhpcyBzcGVjaWZpYyBjaGVjayAtIHVubGlrZQojIG1vc3QgYXV0b2NvbmYgY2hlY2tzIC0gaGFzIG5vIGNyb3NzLWNvbXBpbGUgZmFsbGJhY2ssIHNvIGl0IGhhcmQtCiMgYWJvcnRzIGNvbmZpZ3VyZSB3aXRoICJjYW5ub3QgcnVuIHRlc3QgcHJvZ3JhbSB3aGlsZSBjcm9zcwojIGNvbXBpbGluZyIgaW5zdGVhZCBvZiBqdXN0IGFuc3dlcmluZyAibm8iIGxpa2UgZXZlcnl0aGluZyBlbHNlIGRvZXMuCiMgV2UgZG9uJ3QgdXNlIHRoZSBpbnRlcmFjdGl2ZSBkZWJ1Z2dlciAoYW5kIHRoZXJlZm9yZSBuZXZlciBuZWVkCiMgcmVhZGxpbmUpIGluIHRoaXMgaGVhZGxlc3MgYnVpbGQsIHNvIGp1c3QgbWFrZSB0aGVzZSB0d28gY2hlY2tzCiMgZmFsbCB0aHJvdWdoIGFuZCB0cnkgZXhlY3V0aW9uIHVuY29uZGl0aW9uYWxseTsgaWYgdGhlIGJpbmFyeSBjYW4ndAojIHJ1biB0aGV5IGxhbmQgb24gdGhlIHNhbWUgIm5vIiByZXN1bHQgdGhpcyB3b3VsZCBoYXZlIHByb2R1Y2VkCiMgYW55d2F5LCB3aXRob3V0IHRoZSBoYXJkIGFib3J0LgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQppZiBbIC1mICIkRElSL2NvbmZpZ3VyZSIgXTsgdGhlbgogICAgcHl0aG9uMyAtICIkRElSL2NvbmZpZ3VyZSIgPDwgJ1BZRU9GJwppbXBvcnQgc3lzCnBhdGggPSBzeXMuYXJndlsxXQp3aXRoIG9wZW4ocGF0aCkgYXMgZjoKICAgIHRleHQgPSBmLnJlYWQoKQptYXJrZXIgPSAnaWYgdGVzdCAiJGNyb3NzX2NvbXBpbGluZyIgPSB5ZXM7IHRoZW4nCiMgU2NvcGUgc3RyaWN0bHkgdG8gdGhlIHJlYWRsaW5lIHRlc3QgcHJvZ3JhbSAocmxfaW5pdGlhbGl6ZSksIG5vdCB0aGUKIyBnZW5lcmljIGNyb3NzLWNvbXBpbGUgZXJyb3IgdGV4dCwgd2hpY2ggaXMgc2hhcmVkIGJvaWxlcnBsYXRlIHVzZWQKIyBieSBtYW55IE9USEVSIEFDX1RSWV9SVU4gY2hlY2tzIGluIHRoaXMgY29uZmlndXJlIHNjcmlwdCAoc2l6ZW9mLAojIGVuZGlhbm5lc3MsIGV0Yy4pIHRoYXQgbXVzdCBrZWVwIGZhaWxpbmcgbG91ZGx5IGlmIHRoZXkgY2FuJ3QKIyBhY3R1YWxseSBleGVjdXRlIGEgdGVzdCBiaW5hcnkgLSBvbmx5IHJlYWRsaW5lJ3MgaXMgc2FmZSB0byBza2lwLgpuZWVkbGUgPSAncmxfaW5pdGlhbGl6ZScKY291bnQgPSAwCm91dCA9IFtdCmkgPSAwCndoaWxlIFRydWU6CiAgICBqID0gdGV4dC5maW5kKG1hcmtlciwgaSkKICAgIGlmIGogPT0gLTE6CiAgICAgICAgb3V0LmFwcGVuZCh0ZXh0W2k6XSkKICAgICAgICBicmVhawogICAgd2luZG93ID0gdGV4dFtqOmorNjAwXQogICAgaWYgbmVlZGxlIGluIHdpbmRvdzoKICAgICAgICBvdXQuYXBwZW5kKHRleHRbaTpqXSkKICAgICAgICBvdXQuYXBwZW5kKCdpZiBmYWxzZTsgdGhlbicpCiAgICAgICAgY291bnQgKz0gMQogICAgICAgIGkgPSBqICsgbGVuKG1hcmtlcikKICAgIGVsc2U6CiAgICAgICAgb3V0LmFwcGVuZCh0ZXh0W2k6aitsZW4obWFya2VyKV0pCiAgICAgICAgaSA9IGogKyBsZW4obWFya2VyKQp3aXRoIG9wZW4ocGF0aCwgJ3cnKSBhcyBmOgogICAgZi53cml0ZSgnJy5qb2luKG91dCkpCnByaW50KGYiPj4+IG5ldXRyYWxpemVkIHtjb3VudH0gcmVhZGxpbmUgY3Jvc3MtY29tcGlsZSBjaGVjayhzKSBpbiBjb25maWd1cmUiKQppZiBjb3VudCAhPSAyOgogICAgcHJpbnQoZiJXQVJOSU5HOiBleHBlY3RlZCBleGFjdGx5IDIgcmVhZGxpbmUgY2hlY2tzLCBuZXV0cmFsaXplZCB7Y291bnR9IC0gdmVyaWZ5IGNvbmZpZ3VyZS5pbiBzdHJ1Y3R1cmUgaGFzbid0IGNoYW5nZWQiKQpQWUVPRgpmaQoKdG91Y2ggIiRTRU5USU5FTCIKZWNobyAiPj4+IFBhdGNoaW5nIGNvbXBsZXRlLiIK
endef


# ── BusyBox 32-bit static (musl) ─────────────────────────────
BUSYBOX_URL := https://busybox.net/downloads/binaries/1.35.0-i686-linux-musl/busybox
BUSYBOX_BIN := busybox

# ============================================================
#  Top-level targets
# ============================================================
all: $(MAIN) $(DISK_IMG)

# world: one-shot bootstrap for a totally fresh checkout.
#   1. Downloads + builds Bochs 2.0 (cpu/fpu/memory static libs)
#   2. Downloads + builds TCC (i386-tcc, libtcc.a, and the in-kernel
#      i386-libtcc-kern.a)
#   3. Links the kernel against both and produces main.iso + disk.img
# Equivalent to running setup-tcc then `make BOCHS=1`, but as a single
# command with clear ordering. Safe to re-run: each step is skipped
# automatically once its outputs already exist.
world: $(BOCHS_CPU_LIB) setup-tcc $(MAIN) $(DISK_IMG)
	@echo ">>> world build complete: main.iso + disk.img are ready."
	@echo "    Run: qemu-system-i386 -M q35 -m 2048M -vga std \\"
	@echo "             -drive id=cd0,file=main.iso,format=raw,if=none,media=cdrom \\"
	@echo "             -drive id=disk0,file=disk.img,format=raw,if=none \\"
	@echo "             -device ahci,id=ahci \\"
	@echo "             -device ide-cd,drive=cd0,bus=ahci.0 \\"
	@echo "             -device ide-hd,drive=disk0,bus=ahci.1 -boot d"

# ── Disk image ────────────────────────────────────────────────
# 128 MB FAT32 image, 8 sectors/cluster, 32 reserved sectors.
# Built by mkfat32.py (pure Python, no dosfstools package needed).
# Created once; preserved across builds so filesystem state survives reboots.
$(DISK_IMG):
	@echo ">>> Creating 128 MB FAT32 disk image (no external tools needed)..."
	python3 mkfat32.py $(DISK_IMG) 128
	@echo ">>> $(DISK_IMG) ready."

iso: $(MULTIBOOT)
	mkdir -p iso/boot/grub
	printf '%s\n'                                                 \
	    'set timeout=3'                                           \
	    'set default=0'                                           \
	    'insmod all_video'                                        \
	    'insmod vbe'                                              \
	    'insmod vga'                                              \
	    'insmod gfxterm'                                          \
	    'terminal_input  console'                                 \
	    'terminal_output console'                                 \
	    'menuentry "RTOS++" {'                                    \
	    '    multiboot /boot/main.elf'                            \
	    '    boot'                                                \
	    '}'                                                       \
	    'menuentry "RTOS++ (text console only)" {'                \
	    '    set gfxpayload=text'                                 \
	    '    multiboot /boot/main.elf'                            \
	    '    boot'                                                \
	    '}'                                                       \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue --product-name="RTOS++" -o main.iso iso -- -volid RTOSPP
	@echo ">>> ISO ready: main.iso"


clean:
	rm -rf *.o main.iso iso hello hello_blob.o tcc_tool libtcc_glue.so i386-libtcc-kern.a

# distclean removes build artifacts and the disk image, but KEEPS the
# downloaded bochs-2.0/ tree and the local TCC build.
distclean: clean
	# NOTE: bochs-2.0/ is intentionally NOT removed (avoids re-downloading).
	# NOTE: tcc-local/ and tcc-src/ are also kept so `make cc` works
	#       without re-downloading. Remove them by hand if needed:
	#         rm -rf tcc-local tcc-src tcc-mob.tar.gz
	rm -rf $(BOCHS_ARCHIVE) ramdisk.o $(DISK_IMG)

# Remove the local TCC build completely (forces re-download on next setup-tcc).
tcc-clean:
	rm -rf $(TCC_LOCAL) $(TCC_SRC_DIR) $(TCC_ARCHIVE)

.PHONY: all world clean distclean tcc-clean iso test_main run-test cc tcc setup-tcc download-tcc

# ============================================================
#  TCC glue — host-side C compiler for guest ELFs
# ------------------------------------------------------------
#  Mirrors the bochs_glue pattern: tcc_glue.cpp wraps libtcc
#  into a CLI tool (tcc_tool) and a shared library
#  (libtcc_glue.so).  The kernel links tcc_stub.cpp (no-ops)
#  so the kernel binary does not depend on TCC at run time.
#
#  TCC is built from source automatically — no apt required.
#  Run once before first use:
#    make setup-tcc          # download + build TCC into tcc-local/
#
#  Then compile guest programs normally:
#    make cc SRC=prog.c      # OUT defaults to stem of SRC
#    make cc SRC=prog.c OUT=prog
#
#  The compiled 32-bit ELF is written to disk.img.  Boot the OS
#  and type the ELF name in a terminal to run it.
#
#  Under the hood:
#    1. i386-tcc -c prog.c → prog.o  (relocatable 32-bit i386 object)
#    2. ld -m elf_i386 -T tcc_guest.ld → ELF32 (code at 0x08002000,
#       safely past the Bochs slot GDT/IDT/stub injection zone)
#    3. mtools mcopy prog → disk.img::/prog
# ============================================================

# ── Local TCC build paths ────────────────────────────────────────────────────
# TCC is built from source into tcc-local/ so we get:
#   tcc-local/bin/i386-tcc   — cross-compiler targeting i386
#   tcc-local/lib/libtcc.a   — embedded-compiler library
#   tcc-local/include/libtcc.h
#
# TCC source: GitHub mirror of the official mob (development) branch.
TCC_LOCAL     := tcc-local
TCC_SRC_DIR   := tcc-src
TCC_REPO      := https://github.com/TinyCC/tinycc/archive/refs/heads/mob.tar.gz
TCC_ARCHIVE   := tcc-mob.tar.gz
TCC_I386      := $(TCC_LOCAL)/bin/i386-tcc
TCC_LIB       := $(TCC_LOCAL)/lib/libtcc.a
TCC_INC       := $(TCC_LOCAL)/include/libtcc.h

# ── Auto-detect: use system TCC/libtcc if present, else fall back to local ──
# If the local build exists it takes priority (consistent cross-compiler).
# The shell function runs at parse time so it only queries what is installed.
TCC_TOOL   := tcc_tool
TCC_SO     := libtcc_glue.so

# Include / link flags — prefer local build, then system.
TCC_IFLAGS := $(shell \
    if [ -f $(TCC_INC) ]; then echo "-I$(TCC_LOCAL)/include"; \
    elif pkg-config --exists libtcc 2>/dev/null; then pkg-config --cflags libtcc; \
    fi)
TCC_LIBS   := $(shell \
    if [ -f $(TCC_LIB) ]; then echo "$(TCC_LOCAL)/lib/libtcc.a"; \
    elif pkg-config --exists libtcc 2>/dev/null; then pkg-config --libs libtcc; \
    else echo "-ltcc"; \
    fi)
TCC_CFLAGS := -O2 -Wall -std=c++17 $(TCC_IFLAGS)

# ── setup-tcc / download-tcc ─────────────────────────────────────────────────
# Downloads TCC source from GitHub and builds:
#   • i386-tcc  (cross-compiler: host=x86-64, target=i386)
#   • libtcc.a  (embedded compiler library, position-independent)
#   • libtcc.h  (API header)
#
# Requires on the build host: gcc make (already needed for the kernel build).
# binutils-multiarch is needed for ld -m elf_i386; install it once:
#   sudo apt install binutils-multiarch
#
# Everything else is self-contained in tcc-local/.

$(TCC_ARCHIVE):
	@echo ">>> Downloading TCC source (mob branch) from GitHub ..."
	wget -O $@ "$(TCC_REPO)" || curl -L -o $@ "$(TCC_REPO)"
	@echo ">>> Download complete: $@"


$(TCC_SRC_DIR)/.extracted: $(TCC_ARCHIVE)
	@echo ">>> Extracting TCC source ..."
	mkdir -p $(TCC_SRC_DIR)
	tar -xzf $(TCC_ARCHIVE) --strip-components=1 -C $(TCC_SRC_DIR)
	touch $@
	sed -i 's/tcc_error_noabort("'"'"'%s'"'"' defined twice", name);/\/\* ignore \*\//' $(TCC_SRC_DIR)/tccelf.c
	touch $@

# Build i386-tcc cross-compiler + libtcc into tcc-local/.
# Flags used:
#   --prefix        install into tcc-local/ (no root needed)
#   --enable-cross  build cross-compilers for all TCC targets (includes i386-tcc)
#   --extra-cflags  -fPIC so libtcc.a is position-independent and linkable into .so
$(TCC_I386) $(TCC_LIB) $(TCC_INC) &: $(TCC_SRC_DIR)/.extracted
	@echo ">>> Configuring TCC for cross-compilation (target: i386) ..."
	cd $(TCC_SRC_DIR) && ./configure \
	    --prefix="$(CURDIR)/$(TCC_LOCAL)" \
	    --enable-cross \
	    --extra-cflags="-fPIC -O2"
	@echo ">>> Building TCC ..."
	$(MAKE) -C $(TCC_SRC_DIR)
	@echo ">>> Installing TCC into $(TCC_LOCAL)/ ..."
	$(MAKE) -C $(TCC_SRC_DIR) install
	@echo ">>> TCC ready."
	@echo "    cross-compiler : $(TCC_I386)"
	@echo "    libtcc         : $(TCC_LIB)"
	@echo "    header         : $(TCC_INC)"

# Friendly aliases.
setup-tcc download-tcc: $(TCC_I386) $(TCC_KERN_LIB)
	@echo ">>> setup-tcc complete."
	@echo "    host cross-compiler : $(TCC_I386)"
	@echo "    kernel TCC library  : $(TCC_KERN_LIB)"
	@echo "    Now run: make BOCHS=1  to rebuild the kernel with in-kernel TCC."
	@echo "    Inside the OS:  cc hello_tcc.c"

# ── Host shared library ──────────────────────────────────────────────────────
# Note: libtcc.a built above is -fPIC, so we can link it into the .so.
$(TCC_SO): tcc_glue.cpp $(TCC_LIB)
	@echo ">>> Building $(TCC_SO) ..."
	g++ $(TCC_CFLAGS) -fPIC -shared \
	    -o $@ $< \
	    $(TCC_LIBS) -ldl
	@echo ">>> $(TCC_SO) ready."

# ── Standalone CLI tool ───────────────────────────────────────────────────────
$(TCC_TOOL): tcc_glue.cpp $(TCC_LIB)
	@echo ">>> Building $(TCC_TOOL) ..."
	g++ $(TCC_CFLAGS) \
	    -DHAVE_LIBTCC \
	    -o $@ $< \
	    $(TCC_LIBS) -ldl
	@echo ">>> $(TCC_TOOL) ready."

# ── cc / tcc targets ────────────────────────────────────────────────────────
# Compile a C source file → 32-bit ELF → inject into disk.img.
#
#   make cc SRC=foo.c
#   make cc SRC=foo.c OUT=foo
#   make tcc SRC=foo.c            (alias)
#
# SRC may be:
#   - A host-filesystem path  (e.g. hello_tcc.c)
#   - A filename that already exists on disk.img (mtools reads it out)
#
# The ELF is linked with tcc_guest.ld: code lands at 0x08002000,
# safely past the Bochs slab GDT/IDT/stub injection zone.

ifndef SRC
SRC :=
endif
ifndef OUT
OUT :=
endif

# Ensure i386-tcc is on PATH from the local build.
export PATH := $(CURDIR)/$(TCC_LOCAL)/bin:$(PATH)

cc tcc: $(TCC_TOOL) $(DISK_IMG) tcc_guest.ld
	@if [ ! -x "$(TCC_I386)" ] && ! command -v i386-tcc >/dev/null 2>&1; then \
	    echo ""; \
	    echo "ERROR: i386-tcc not found."; \
	    echo "Run  make setup-tcc  to download and build TCC automatically,"; \
	    echo "then retry:  make cc SRC=$(SRC)"; \
	    echo ""; \
	    exit 1; \
	fi
ifndef SRC
	@echo "Usage: make cc SRC=<file.c> [OUT=<name>]"
	@echo "  Compiles SRC to a 32-bit ELF and writes it to $(DISK_IMG)."
	@exit 1
endif
	@echo ">>> Compiling $(SRC) → $(or $(OUT),$(basename $(notdir $(SRC)))) in $(DISK_IMG) ..."
	@# Guest programs commonly #include "bochs_drivers.h" (see compile.md).
	@# The in-kernel `cc` command resolves #include by reading straight
	@# from disk.img, so make sure a real copy is always there -- via
	@# mtools mcopy (same tool/overwrite-flag combo tcc_glue.cpp uses for
	@# the compiled ELF itself), which writes proper VFAT long-filename
	@# entries for a 13-character base name like this one. Overwrite (-o)
	@# so re-running `make cc` after editing bochs_drivers.h picks up the
	@# change; ignore failure (`|| true`) so a disk.img built before this
	@# existed, or one where the file is already current, never blocks a
	@# compile over this best-effort sync step.
	@MTOOLS_SKIP_CHECK=1 mcopy -o -i "$(DISK_IMG)" "bochs_drivers.h" "::bochs_drivers.h" 2>/dev/null || true
	@# compositor.h (the GUI widget library) #includes both of these,
	@# so any guest program using it from the in-kernel `cc` command
	@# needs all three present on disk.img -- same best-effort sync.
	@MTOOLS_SKIP_CHECK=1 mcopy -o -i "$(DISK_IMG)" "font.h" "::font.h" 2>/dev/null || true
	@MTOOLS_SKIP_CHECK=1 mcopy -o -i "$(DISK_IMG)" "compositor.h" "::compositor.h" 2>/dev/null || true
	./$(TCC_TOOL) "$(DISK_IMG)" "$(SRC)" "$(OUT)" "tcc_guest.ld"
	@echo ">>> Done. Boot the OS and type '$(or $(OUT),$(basename $(notdir $(SRC))))' to run it."

# ============================================================
#  Bochs CPU/FPU/memory static libraries
# ------------------------------------------------------------
#  Downloads Bochs 2.0 from the official bochs-emu/Bochs GitHub
#  mirror (tag REL_2_0_FINAL), extracts it, applies
#  patch-bochs-2.0.sh (source-level fixes needed to build this
#  2003-era code with a modern GCC/glibc toolchain - see that
#  script for details on each one), configures --with-nogui, and
#  builds the static libs needed by the glue code: cpu/libcpu.a,
#  fpu/libfpu.a, memory/libmemory.a. If $(BOCHS_CPU_LIB) already
#  exists (e.g. from a previous run) the whole step is skipped.
#
#  NOTE: unlike later Bochs releases, 2.0 has no cpu/cpudb/ (CPU
#  model database, added in 2.5) and fpu/ lives at the bochs root
#  rather than under cpu/ (that move happened in 2.6.1) - so
#  neither is referenced here.
# ============================================================
$(BOCHS_ARCHIVE):
	wget -O $@ "$(BOCHS_URL)" || curl -L -o $@ "$(BOCHS_URL)"
	@gzip -t $@ 2>/dev/null || { \
	    echo ""; \
	    echo "ERROR: $@ is not a valid gzip file."; \
	    echo "       The download likely failed (404 / HTML error page /"; \
	    echo "       redirect page saved instead of the real tarball)."; \
	    echo "       URL used: $(BOCHS_URL)"; \
	    echo "       Try opening that URL in a browser, then either fix"; \
	    echo "       BOCHS_URL/BOCHS_TAG in the Makefile or download it"; \
	    echo "       manually to $@ in this directory."; \
	    echo ""; \
	    rm -f $@; \
	    exit 1; \
	}

$(BOCHS_DIR)/.extracted: $(BOCHS_ARCHIVE)
	rm -rf $(BOCHS_DIR)
	mkdir -p $(BOCHS_DIR)
	tar -xzf $(BOCHS_ARCHIVE) --strip-components=2 -C $(BOCHS_DIR)
	@if [ ! -f "$(BOCHS_DIR)/configure" ]; then \
	    echo ""; \
	    echo "ERROR: extracting $(BOCHS_ARCHIVE) did not produce"; \
	    echo "       $(BOCHS_DIR)/configure as expected."; \
	    echo "       Run 'tar tzf $(BOCHS_ARCHIVE) | head' to see the"; \
	    echo "       archive's actual top-level layout and adjust the"; \
	    echo "       --strip-components value above if it changed."; \
	    echo ""; \
	    exit 1; \
	fi
	@echo "$(BOCHS_PATCH_SCRIPT_B64)" | base64 -d > patch-bochs-2.0.sh
	chmod +x patch-bochs-2.0.sh
	rm -f $(BOCHS_DIR)/.claude-patched
	./patch-bochs-2.0.sh $(BOCHS_DIR)
	touch $@

$(BOCHS_CPU_LIB):
	@set -e; \
	if [ -f "$(BOCHS_CPU_LIB)" ]; then \
	    echo ">>> Using existing Bochs libs in $(BOCHS_DIR)."; \
	else \
	    echo ">>> Bochs libs not found - downloading and building $(BOCHS_DIR)..."; \
	    $(MAKE) $(BOCHS_DIR)/.extracted; \
	    cd $(BOCHS_DIR) && ./configure \
	        --enable-cpu-level=6 --enable-fpu --with-nogui \
	        --host=i686-linux-gnu \
	        CXXFLAGS="-O2 -m32 -fno-stack-protector -fno-pie -fno-rtti -fno-exceptions" \
	        CFLAGS="-O2 -m32 -fno-stack-protector -fno-pie"; \
	    cd ..; \
	    $(MAKE) -C $(BOCHS_DIR)/cpu; \
	    $(MAKE) -C $(BOCHS_DIR)/fpu; \
	    $(MAKE) -C $(BOCHS_DIR)/memory; \
	fi



# Bochs instrument stub header (required by bochs_glue.cpp).
# Prebuilt bundle already contains it; re-copying is harmless.
$(BOCHS_DIR)/instrument.h:
	cp instrument_stub.h $@

# ============================================================
#  BusyBox ramdisk
# ============================================================
$(BUSYBOX_BIN):
	@echo ">>> Downloading BusyBox i686 static binary..."
	wget -O $@ "$(BUSYBOX_URL)" || curl -L -o $@ "$(BUSYBOX_URL)"
	chmod +x $@
	@echo ">>> BusyBox downloaded."

# Embed BusyBox as read-only data in the kernel ELF.
# IMPORTANT: -B i386 (not i386:x86-64) for a 32-bit kernel binary.
ramdisk.o: $(BUSYBOX_BIN)
	@echo ">>> Embedding BusyBox into ramdisk.o..."
	objcopy \
	    -I binary \
	    -O elf32-i386 \
	    -B i386 \
	    --rename-section .data=.rodata,alloc,load,readonly,data,contents \
	    --redefine-sym _binary_busybox_start=ramdisk_start \
	    --redefine-sym _binary_busybox_end=ramdisk_end   \
	    --redefine-sym _binary_busybox_size=ramdisk_size  \
	    $(BUSYBOX_BIN) $@
	@echo ">>> ramdisk.o created."

# Tiny test ELF that prints "HELLO\n" via port 0xE9 and halts.
# Used to verify the GDT/IDT/port-IO chain end-to-end without dragging
# in busybox's full Linux ABI requirements.
hello: hello.c
	@echo ">>> Building hello test ELF..."
	gcc -m32 -nostdlib -nostartfiles -static -fno-pie -no-pie \
	    -Wl,-Ttext=0x08048000 \
	    -o $@ hello.c
	@echo ">>> hello built."

# Embed the hello ELF as a second blob with its own symbols.
hello_blob.o: hello
	@echo ">>> Embedding hello into hello_blob.o..."
	objcopy \
	    -I binary \
	    -O elf32-i386 \
	    -B i386 \
	    --rename-section .data=.rodata,alloc,load,readonly,data,contents \
	    --redefine-sym _binary_hello_start=hello_start \
	    --redefine-sym _binary_hello_end=hello_end   \
	    --redefine-sym _binary_hello_size=hello_size  \
	    hello $@
	@echo ">>> hello_blob.o created."

# ============================================================
#  Bochs CPU emulation: ON by default (set BOCHS=0 to disable)
#  bochs_infra.o provides all Bochs infrastructure globals
#  (logfunctions, SIM, bx_cpu, bx_mem, bx_devices, etc.)
# ============================================================



BOCHS_OBJ    := bochs_glue.o bochs_infra.o bochs_pc_system.o bochs_cstubs.o setjmp.o test_module.o tcc_kernel.o
# libcpudb.a (per-model CPU database) is intentionally NOT linked here:
# Bochs 2.0 predates cpu/cpudb/, so it never gets built (see the
# $(BOCHS_CPU_LIB) rule above). If you later bump BOCHS_VERSION to a
# release that does have cpu/cpudb/, add
# "$(BOCHS_DIR)/cpu/cpudb/libcpudb.a" back to this list.
BOCHS_LIBS   := $(BOCHS_DIR)/cpu/libcpu.a \
                $(BOCHS_DIR)/fpu/libfpu.a \
                $(BOCHS_DIR)/memory/libmemory.a
BOCHS_IFLAGS := -I$(BOCHS_DIR) -I$(BOCHS_DIR)/cpu \
                -I$(BOCHS_DIR)/iodev -I$(BOCHS_DIR)/gui
BOCHS_DEP    := $(BOCHS_CPU_LIB)
BOCHS_CDEF   := -DBOCHS_ENABLED=1
LIBGCC_EH    := /usr/lib/gcc/x86_64-linux-gnu/13/32/libgcc_eh.a


# ============================================================
#  Kernel object files
# ============================================================
boot.o: boot.S
	as --32 boot.S -o boot.o

kernel.o: kernel.cpp $(BOCHS_DEP)
	g++ -m32 -O2 $(BOCHS_IFLAGS) $(CXXFLAGS) $(BOCHS_CDEF) -c kernel.cpp -o kernel.o

bochs_stub.o: bochs_stub.cpp
	g++ -m32 -O2 $(CXXFLAGS) -c bochs_stub.cpp -o bochs_stub.o

bochs_glue.o: bochs_glue.cpp $(BOCHS_DIR)/instrument.h $(BOCHS_CPU_LIB)
	g++ -m32 -O2 $(BOCHS_IFLAGS) $(CXXFLAGS) -DBOCHS_GLUE -c bochs_glue.cpp -o bochs_glue.o

# bochs_infra.cpp needs system headers (not freestanding) because bochs.h
# pulls in <stdio.h> etc. for its own types. Compiled as a normal 32-bit object.
bochs_infra.o: bochs_infra.cpp $(BOCHS_DIR)/instrument.h $(BOCHS_CPU_LIB)
	g++ -m32 -O2 $(BOCHS_IFLAGS) \
	    -fno-exceptions -fno-rtti -fno-pie -fno-pic \
	    -std=c++17 \
	    -include instrument_stub.h \
	    -c bochs_infra.cpp -o bochs_infra.o

# NOTE (Bochs 2.0 port): gui/siminterface.cc is intentionally NOT
# compiled/linked (there used to be a bochs_paramtree.o rule here).
# Linking that whole file pulled in bx_real_sim_c - a separate, unused
# class in the same translation unit - and its bochsrc-parsing
# dependencies (bx_options, bx_find_bochsrc, bx_read_configuration,
# etc), none of which we need. The only symbol we actually needed from
# it (bx_simulator_interface_c's empty base constructor) is now
# provided directly in bochs_infra.cpp instead.

# bochs_pc_system.o — provides bx_pc_system_c constructor and timer methods
bochs_pc_system.o: $(BOCHS_DIR)/pc_system.cc $(BOCHS_CPU_LIB)
	g++ -m32 -O2 $(BOCHS_IFLAGS) \
	    -fno-exceptions -fno-rtti -fno-pie -fno-pic \
	    -std=c++17 \
	    -include instrument_stub.h \
	    -c $(BOCHS_DIR)/pc_system.cc -o bochs_pc_system.o

# bochs_cstubs.o — freestanding C stdlib stubs (no system headers)
bochs_cstubs.o: bochs_cstubs.c
	gcc -m32 -O2 -ffreestanding -fno-pie -fno-pic \
	    -c bochs_cstubs.c -o bochs_cstubs.o

# ── i386-libtcc-kern.a — TCC compiled to target i386, linked into the kernel ──
# Built by setup-tcc from TCC's libtcc.c with:
#   -DTCC_TARGET_I386 -DONE_SOURCE=1 -DCONFIG_TCC_SEMLOCK=0
# so tcc_kernel.cpp can call tcc_new/tcc_compile_string/tcc_output_file in-kernel.
TCC_KERN_LIB := i386-libtcc-kern.a

$(TCC_KERN_LIB): $(TCC_I386)
	@echo ">>> Building i386-targeting libtcc for kernel ..."
	cd $(TCC_SRC_DIR) && gcc -m32 -c libtcc.c \
	    -DTCC_TARGET_I386 -DONE_SOURCE=1 -DCONFIG_TCC_SEMLOCK=0 \
	    "-DCONFIG_TCC_CROSSPREFIX=\"i386-\"" \
	    "-DCONFIG_TCCDIR=\"/tcc\"" \
	    "-DCONFIG_TCC_SYSROOTDIR=\"\"" \
	    "-DCONFIG_TCC_LIBPATHS=\"{B}\"" \
	    "-DTCC_LIBTCC1=\"\"" \
	    "-DCONFIG_TCC_CRTPREFIX=\"{B}\"" \
	    '-DCONFIG_TCC_ELFINTERP="/lib/ld-linux.so.2"' \
	    -DTCC_IS_NATIVE=0 \
	    -I. -O2 -w -fno-stack-protector -U_FORTIFY_SOURCE -fno-builtin \
	    -o i386-libtcc-kern.o
	ar rcs $(CURDIR)/$(TCC_KERN_LIB) $(TCC_SRC_DIR)/i386-libtcc-kern.o
	@echo ">>> $(TCC_KERN_LIB) ready."

# tcc_kernel.o — real in-kernel TCC glue (replaces tcc_stub.o).
# Compiled freestanding i386; provides all POSIX shims libtcc.a needs.
# Depends on $(TCC_KERN_LIB) existing so libtcc.h is available.
tcc_kernel.o: tcc_kernel.cpp $(TCC_KERN_LIB)
	g++ -m32 -O2 -ffreestanding -fno-pie -fno-pic -fno-exceptions -fno-rtti \
	    -fno-stack-protector -std=c++17 \
	    -I$(TCC_SRC_DIR) \
	    -c tcc_kernel.cpp -o tcc_kernel.o

# setjmp.o — pure-asm i386 setjmp/longjmp/__longjmp_chk matching glibc layout.
# Required by libcpu.a (Bochs' internal exception unwinding) and by
# bochs_glue.cpp's rescue path.
setjmp.o: setjmp.S
	as --32 setjmp.S -o setjmp.o
	
test_module.o: test_module.cpp
	g++ -m32 -O2 $(BOCHS_IFLAGS) $(CXXFLAGS) -c test_module.cpp -o test_module.o

# ============================================================
#  Link
# ============================================================
$(MULTIBOOT): boot.o kernel.o ramdisk.o hello_blob.o test_module.o $(BOCHS_OBJ) $(TCC_KERN_LIB) $(BOCHS_DEP)
	mkdir -p iso/boot
	g++ -m32 -T linker.ld -nostdlib -no-pie -static \
	    -o $(MULTIBOOT)              \
	    -Wl,--start-group             \
	    boot.o kernel.o ramdisk.o hello_blob.o \
	    $(BOCHS_OBJ)                  \
	    $(TCC_KERN_LIB)               \
	    $(BOCHS_LIBS)                 \
	    -lgcc $(LIBGCC_EH)            \
	    -Wl,--end-group               \
	    -Wl,--allow-multiple-definition

# ============================================================
#  ISO image via GRUB (hybrid BIOS + UEFI)
# ------------------------------------------------------------
#  grub-mkrescue auto-detects the GRUB platforms installed on the
#  build host. With grub-pc-bin installed you get a BIOS-bootable
#  El Torito image; with grub-efi-amd64-bin / grub-efi-ia32-bin also
#  installed you get an additional EFI System Partition embedded
#  in the same ISO, so the output boots on:
#    * QEMU / Bochs                      (BIOS)
#    * VMware Workstation / Fusion       (BIOS or UEFI firmware)
#    * Real bare metal w/ legacy CSM     (BIOS)
#    * Real bare metal UEFI-only         (UEFI)
#
#  See: install with
#    apt-get install grub-pc-bin grub-efi-amd64-bin grub-efi-ia32-bin \
#                    xorriso mtools
# ============================================================
$(MAIN): $(MULTIBOOT)
	mkdir -p iso/boot/grub
	printf '%s\n'                                                 \
	    'set timeout=3'                                           \
	    'set default=0'                                           \
	    'insmod all_video'                                        \
	    'insmod vbe'                                              \
	    'insmod vga'                                              \
	    'insmod gfxterm'                                          \
	    'terminal_input  console'                                 \
	    'terminal_output console'                                 \
	    'menuentry "RTOS++" {'                                    \
	    '    multiboot /boot/main.elf'                            \
	    '    boot'                                                \
	    '}'                                                       \
	    'menuentry "RTOS++ (text console only)" {'                \
	    '    set gfxpayload=text'                                 \
	    '    multiboot /boot/main.elf'                            \
	    '    boot'                                                \
	    '}'                                                       \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue                                                 \
	    --product-name="RTOS++"                                   \
	    --product-version="1.0"                                   \
	    -o $(MAIN) iso                                            \
	    -- -volid RTOSPP
	@echo ">>> ISO ready: $(MAIN)"
	@if command -v xorriso >/dev/null 2>&1; then \
	    echo "--- Boot record summary ---"; \
	    xorriso -indev $(MAIN) -report_el_torito plain 2>/dev/null \
	        | sed -n '/Boot record/p;/El Torito/p'; \
	    xorriso -indev $(MAIN) -report_system_area plain 2>/dev/null \
	        | sed -n '/System area/p'; \
	fi

# ============================================================
#  test_main — standalone Bochs init + cpu_tick verification
# ------------------------------------------------------------
#  Builds test_main.cpp (which provides its own kernel_main and a
#  two-phase self-test) instead of the full kernel.cpp. Produces a
#  bootable test_main.iso. This is the smallest end-to-end check
#  that the Bochs glue works: Phase 1 runs BX_CPU(0)->initialize()
#  + reset(); Phase 2 loads a tiny guest and ticks it, expecting
#  "HI\n" on the guest port-0xE9 console.
#
#  Run it headless and watch the port-0xE9 trace:
#    make test_main
#    qemu-system-i386 -M q35 -cdrom test_main.iso -boot d \
#        -m 512M -display none -debugcon stdio -no-reboot
#  A passing run prints:  === TEST PASSED (init + tick) ===
#
#  `make run-test` does both steps in one go.
# ============================================================
TEST_ISO   := test_main.iso
TEST_ELF   := iso/boot/main.elf

test_main.o: test_main.cpp $(BOCHS_DEP)
	g++ -m32 -O2 $(BOCHS_IFLAGS) $(CXXFLAGS) $(BOCHS_CDEF) -c test_main.cpp -o test_main.o

# test_main links WITHOUT ramdisk.o / hello_blob.o — the harness
# references none of the busybox/hello blob symbols.
test_main: boot.o test_main.o $(BOCHS_OBJ) $(TCC_KERN_LIB) $(BOCHS_DEP)
	mkdir -p iso/boot/grub
	g++ -m32 -T linker.ld -nostdlib -no-pie -static \
	    -o $(TEST_ELF) \
	    -Wl,--start-group             \
	    boot.o test_main.o            \
	    $(BOCHS_OBJ)                  \
	    $(TCC_KERN_LIB)               \
	    $(BOCHS_LIBS)                 \
	    -lgcc $(LIBGCC_EH)            \
	    -Wl,--end-group               \
	    -Wl,--allow-multiple-definition
	printf '%s\n' \
	    'set timeout=0' \
	    'set default=0' \
	    'menuentry "RTOS++ test_main" {' \
	    '    multiboot /boot/main.elf' \
	    '    boot' \
	    '}' \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue -o $(TEST_ISO) iso
	@echo ">>> $(TEST_ISO) ready. Boot it with -debugcon stdio to see the trace."

run-test: test_main
	qemu-system-i386 -M q35 -cdrom $(TEST_ISO) -boot d \
	    -m 512M -display none -debugcon stdio -no-reboot