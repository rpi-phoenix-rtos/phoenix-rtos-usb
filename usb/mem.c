/*
 * Phoenix-RTOS
 *
 * USB host memory pool management
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <sys/mman.h>
#include <sys/threads.h>

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define USB_CHUNK_SIZE 32
#define USB_BUF_SIZE   4096

/* Issue #121 — the free-list head was intermittently found smashed with
 * non-pointer (recycled DRAM) bytes during early USB enumeration. ROOT-CAUSED
 * AND FIXED: stale dirty cache lines left by a prior cached owner of the page
 * were evicted over the pool (usb `12c4fe8`, the dc-civac in usb_mmapUncached
 * below). The archaeology this file carried to find that writer — rings of
 * recent allocs and frees, and the caller-PC walk that named the adjacent
 * overflow suspect — has done its job and is gone; it cost work on every
 * usb_alloc()/usb_free().
 *
 * What stays is detection, not investigation: usb_chunkSane() still refuses to
 * follow a wild free-list pointer, and a hit still dumps the corrupt node's
 * bytes. Silence is not evidence — if this ever comes back, the next boot must
 * say so rather than recover quietly. */

struct usb_chunk_hdr {
	struct usb_chunk_hdr *next;
	size_t size;
};


typedef struct usb_buf {
	union {
		struct {
			struct usb_buf *next;
			unsigned freesz;
			struct usb_chunk_hdr *head;
		};
		char padding[USB_CHUNK_SIZE];
	};

	char start[];
} usb_buf_t;


/* Dump the bytes of a smashed free-list node, so a recurrence says what wrote
 * there instead of only that something did: identifiable USB descriptor/report
 * bytes name a source class, plain text names another. Caller must hold the pool
 * lock. 'hdr' is the wild pointer caught by usb_chunkSane and may point anywhere
 * inside the buffer, so the dump is clamped to the buffer bounds. */
static void usb_memReportCorrupt(const usb_buf_t *buf, const struct usb_chunk_hdr *hdr)
{
	const uint8_t *base = (const uint8_t *)buf;
	const uint8_t *p = (const uint8_t *)hdr;
	unsigned i;

	if ((p >= base) && (p + USB_CHUNK_SIZE <= base + USB_BUF_SIZE)) {
		fprintf(stderr, "usb_mem: corrupt node bytes @%p:", (void *)p);
		for (i = 0; i < USB_CHUNK_SIZE; i++) {
			fprintf(stderr, " %02x", p[i]);
		}
		fprintf(stderr, " | ascii: ");
		for (i = 0; i < USB_CHUNK_SIZE; i++) {
			fprintf(stderr, "%c", ((p[i] >= 0x20) && (p[i] < 0x7f)) ? p[i] : '.');
		}
		fprintf(stderr, "\n");
	}
}


/* A usb_buf_t* must be USB_BUF_SIZE-aligned (every chunk buffer is a page from
 * _usb_allocBuffer()). An overflow that smashes a buffer header's buf->next
 * field (offset 0) leaves a non-aligned wild pointer there; reject it before
 * usb_allocFrom recurses into it and faults dereferencing string bytes as a
 * usb_buf_t (#121). NULL is valid (end of the buffer chain). */
static int usb_bufSane(const usb_buf_t *buf)
{
	if (buf == NULL) {
		return 1;
	}
	return (((uintptr_t)buf & (USB_BUF_SIZE - 1)) == 0) ? 1 : 0;
}


#if defined(__TARGET_AARCH64A72)
/* Raspberry Pi 4: the VL805 host controller behind the BCM2711 PCIe bridge
 * returns wrong data for DMA above 3 GiB, even though the inbound window covers
 * 4 GiB (the device tree's dma-ranges stops at 3 GiB). It shows only under
 * memory pressure: silently corrupted reads, then an xHCI Host System Error. */
#define USB_DMA_LIMIT 0xc0000000ULL

/* Under memory pressure there may be no free memory below USB_DMA_LIMIT left to
 * map, so everything the stack needs in normal operation is reserved when it
 * starts (see the DMA page pool below). In pages:
 *  - VL805 xHCI controller: DCBAA, command ring, event ring, ERST, scratchpad
 *    array and the shared input context take a page each (6), plus 31
 *    scratchpad buffers (HCSPARAMS2 Max Scratchpad Buffers)               37
 *  - devices: an output context and an EP0 ring each (2), plus a transfer
 *    ring per other endpoint: the VL805's USB 2.0 hub, a keyboard and a
 *    mouse (3 each) and two mass-storage devices (4 each)                 17
 *  - pages carved into small blocks by usb_alloc() (setup packets, CBW/CSW,
 *    hub status, interrupt reports: 127 blocks per page)                  2
 *  - transfer buffers: umass moves at most UMASS_MAX_IO (64 KiB) per SCSI
 *    command and issues one command per device at a time; two devices     32
 * 88 pages, i.e. two 256 KiB pool segments. */
#define USB_DMA_RESERVE_PAGES (37U + 17U + 2U + 32U)
#endif

/* Rejected allocations are held while retrying, so the allocator hands out other pages */
#define USB_DMA_RETRIES 32

/* DMA memory reserved when the stack starts, in pages. Zero: no pool, every
 * block of a page or more is mapped when it is needed and unmapped when freed. */
#ifndef USB_DMA_RESERVE_PAGES
#define USB_DMA_RESERVE_PAGES 0U
#endif


static void *usb_mmapUncached(size_t size)
{
	void *res;

	/* MAP_CONTIGUOUS + MAP_PRIVATE matches the flags used by the kernel
	 * drivers/physmmap.c dmammap helper. Keep the allocator consistent
	 * with that path; the flags don't affect correctness here — other
	 * ports either ignore MAP_CONTIGUOUS or honor it without cost — so
	 * this is just code hygiene. */
	if ((res = mmap(NULL, size, PROT_WRITE | PROT_READ,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_UNCACHED | MAP_CONTIGUOUS, -1, 0)) == MAP_FAILED)
		return NULL;

	/* #121: evict stale dirty cache lines a prior (cached) owner left on these
	 * recycled physical pages. Otherwise those lines write back over our uncached
	 * DMA data and corrupt the pool/contexts — observed as foreign banner strings
	 * ("Raspberry", "PWM1 jack @", "Phoenix Systems") smashing buf->next/head,
	 * intermittently failing USB init ("Fail to init hcds"). dc civac is EL0-legal
	 * (SCTLR_EL1.UCI) and, on the A72's PIPT D-cache, cleans+invalidates the line
	 * for the physical address regardless of this mapping's uncached attribute, so
	 * the eviction lands even though we read/write the page uncached. Done once,
	 * right after mmap, before the buffer is initialised or DMA'd. */
	{
		uintptr_t a = (uintptr_t)res & ~63UL;
		uintptr_t e = (uintptr_t)res + size;
		for (; a < e; a += 64UL) {
			__asm__ volatile("dc civac, %0" : : "r"(a) : "memory");
		}
		__asm__ volatile("dsb sy" : : : "memory");
	}

	return res;
}


static void *usb_allocUncached(size_t size)
{
#ifdef USB_DMA_LIMIT
	void *held[USB_DMA_RETRIES];
	void *res = NULL, *p;
	int n = 0;

	/* The kernel allocator takes no placement hint: retry until the (contiguous) block ends below the limit */
	while (n < USB_DMA_RETRIES) {
		p = usb_mmapUncached(size);
		if (p == NULL) {
			break;
		}
		if ((unsigned long long)va2pa(p) + size <= USB_DMA_LIMIT) {
			res = p;
			break;
		}
		held[n++] = p;
	}

	while (n > 0) {
		munmap(held[--n], size);
	}

	if (res == NULL) {
		fprintf(stderr, "usb: no DMA memory below 0x%llx for %zu bytes\n", USB_DMA_LIMIT, size);
	}

	return res;
#else
	return usb_mmapUncached(size);
#endif
}


/* A block of its own, unmapped again when freed: used without a pool, and when
 * the pool cannot serve a request. 'size' and 'alignment' are whole pages. */
static void *usb_allocDirect(size_t size, size_t alignment)
{
	char *addr, *res;

	if ((addr = usb_allocUncached(size)) == NULL)
		return NULL;

	if (va2pa(addr) % alignment == 0) {
		return addr;
	}

	munmap(addr, size);

	if ((addr = usb_allocUncached(alignment * 2)) == NULL)
		return NULL;

	res = (char *)(((uintptr_t)addr + (alignment - 1)) & ~(alignment - 1));

	/* unmap memory prefix */
	if (res != addr)
		munmap(addr, res - addr);

	/* unmap memory sufix */
	if (res + size != addr + alignment * 2)
		munmap(res + size, (addr + alignment * 2) - (res + size));

	return res;
}


/*
 * DMA page pool
 *
 * Blocks of a page or more (rings, contexts, the pages usb_alloc() carves into
 * small blocks, transfer buffers) are carved out of physically contiguous
 * segments and go back to them when freed, instead of being mapped for every
 * transfer. With USB_DMA_LIMIT, memory below the limit may not be available
 * when the system is under memory pressure, which is exactly when the stack
 * would otherwise need a new transfer buffer; so USB_DMA_RESERVE_PAGES are
 * reserved when the stack starts. The pool grows by a segment when it runs out
 * (a newly plugged device, say); that can fail under pressure like any other
 * allocation, and the request then falls back to a block of its own.
 *
 * A run of pages starts at a physical address aligned to its size rounded up
 * to a power of two, up to 64 KiB: a block of up to 64 KiB never spans a 64 KiB
 * boundary, which xHCI TRB data buffers must not do, as with the kernel's buddy
 * allocator before. Single pages, mostly long-lived, are taken from the bottom
 * of the pool and longer runs from the top, so that the rings and contexts of
 * hot-plugged devices do not break up the runs transfer buffers need.
 */

#define USB_POOL_SEG_PAGES 64U /* one bitmap word per segment */
#define USB_POOL_SEG_SIZE  ((size_t)USB_POOL_SEG_PAGES * _PAGE_SIZE)
#define USB_POOL_SEGS_MAX  16U /* 4 MiB; beyond it every block is one of its own */
#define USB_POOL_BOUNDARY  (0x10000U / _PAGE_SIZE) /* 64 KiB, in pages */


typedef struct {
	char *base;
	addr_t pa;
	uint64_t used; /* bit n set: page n is allocated */
} usb_poolSeg_t;


static struct {
	usb_buf_t *buffer;
	usb_poolSeg_t segs[USB_POOL_SEGS_MAX];
	unsigned int nsegs;
	handle_t lock;
} usb_mem_common;


static uint64_t usb_poolRunMask(unsigned int npages)
{
	return (npages >= 64U) ? ~(uint64_t)0 : (((uint64_t)1 << npages) - 1U);
}


/* Caller must hold the lock */
static int _usb_poolGrow(void)
{
	usb_poolSeg_t *seg;
	char *base;

	if (usb_mem_common.nsegs >= USB_POOL_SEGS_MAX) {
		return -1;
	}

	base = usb_allocUncached(USB_POOL_SEG_SIZE);
	if (base == NULL) {
		return -1;
	}

	seg = &usb_mem_common.segs[usb_mem_common.nsegs++];
	seg->base = base;
	seg->pa = va2pa(base);
	seg->used = 0;

	return 0;
}


/* Start page of a free run of 'npages' in 'seg' whose physical page number is a
 * multiple of 'align': the lowest one, or with 'fromTop' the highest. -1 if none. */
static int usb_poolSegFit(const usb_poolSeg_t *seg, unsigned int npages, unsigned int align, int fromTop)
{
	uint64_t mask = usb_poolRunMask(npages);
	unsigned int i = (align - (unsigned int)((seg->pa / _PAGE_SIZE) % align)) % align;
	int found = -1;

	for (; i + npages <= USB_POOL_SEG_PAGES; i += align) {
		if ((seg->used & (mask << i)) == 0U) {
			found = (int)i;
			if (fromTop == 0) {
				break;
			}
		}
	}

	return found;
}


/* Caller must hold the lock */
static int _usb_poolFind(unsigned int npages, unsigned int align, usb_poolSeg_t **seg)
{
	int fromTop = (npages > 1U) ? 1 : 0;
	unsigned int i, n = usb_mem_common.nsegs;
	int start;

	for (i = 0; i < n; i++) {
		*seg = &usb_mem_common.segs[(fromTop != 0) ? (n - 1U - i) : i];
		start = usb_poolSegFit(*seg, npages, align, fromTop);
		if (start >= 0) {
			return start;
		}
	}

	return -1;
}


/* Caller must hold the lock. 'size' and 'alignment' are whole pages. */
static void *_usb_poolAlloc(size_t size, size_t alignment)
{
	unsigned int npages, align = 1;
	usb_poolSeg_t *seg;
	int start;

	if ((size > USB_POOL_SEG_SIZE) || (alignment > USB_POOL_SEG_SIZE)) {
		return NULL;
	}

	npages = (unsigned int)(size / _PAGE_SIZE);
	while ((align < npages) && (align < USB_POOL_BOUNDARY)) {
		align <<= 1;
	}
	if (align < alignment / _PAGE_SIZE) {
		align = (unsigned int)(alignment / _PAGE_SIZE);
	}

	start = _usb_poolFind(npages, align, &seg);
	if ((start < 0) && (USB_DMA_RESERVE_PAGES != 0U) && (_usb_poolGrow() == 0)) {
		fprintf(stderr, "usb: DMA pool grown to %u KiB\n", usb_mem_common.nsegs * (unsigned int)(USB_POOL_SEG_SIZE / 1024U));
		start = _usb_poolFind(npages, align, &seg);
	}
	if (start < 0) {
		return NULL;
	}

	seg->used |= usb_poolRunMask(npages) << start;

	return seg->base + (size_t)start * _PAGE_SIZE;
}


/* Caller must hold the lock. Returns 0 if 'ptr' is not pool memory. */
static int _usb_poolFree(void *ptr, size_t size)
{
	uintptr_t p = (uintptr_t)ptr, base;
	unsigned int i, start, npages = (unsigned int)(size / _PAGE_SIZE);

	for (i = 0; i < usb_mem_common.nsegs; i++) {
		base = (uintptr_t)usb_mem_common.segs[i].base;
		if ((p >= base) && (p < base + USB_POOL_SEG_SIZE)) {
			start = (unsigned int)((p - base) / _PAGE_SIZE);
			if ((start + npages > USB_POOL_SEG_PAGES) || (((p - base) % _PAGE_SIZE) != 0U)) {
				fprintf(stderr, "usb_mem: bad free of %zu bytes at %p, leaking it\n", size, ptr);
			}
			else {
				usb_mem_common.segs[i].used &= ~(usb_poolRunMask(npages) << start);
			}
			return 1;
		}
	}

	return 0;
}


/* Caller must hold the lock. 'size' and 'alignment' are whole pages. Not cleared. */
static void *_usb_allocPages(size_t size, size_t alignment)
{
	void *res = _usb_poolAlloc(size, alignment);

	if (res == NULL) {
		res = usb_allocDirect(size, alignment);
	}

	return res;
}


/* Caller must hold the lock. 'size' is whole pages. */
static void _usb_freePages(void *ptr, size_t size)
{
	if (_usb_poolFree(ptr, size) == 0) {
		munmap(ptr, size);
	}
}


void *usb_allocAligned(size_t size, size_t alignment)
{
	void *res;

	size = (size + (_PAGE_SIZE - 1)) & ~(_PAGE_SIZE - 1);
	alignment = (alignment + (_PAGE_SIZE - 1)) & ~(_PAGE_SIZE - 1);

	mutexLock(usb_mem_common.lock);
	res = _usb_allocPages(size, alignment);
	mutexUnlock(usb_mem_common.lock);

	/* Pool pages are recycled: clear them, as a fresh mapping would be */
	if (res != NULL) {
		memset(res, 0, size);
	}

	return res;
}


void usb_freeAligned(void *ptr, size_t size)
{
	if (ptr == NULL) {
		return;
	}

	size = (size + (_PAGE_SIZE - 1)) & ~(_PAGE_SIZE - 1);

	mutexLock(usb_mem_common.lock);
	_usb_freePages(ptr, size);
	mutexUnlock(usb_mem_common.lock);
}


/* Caller must hold the lock */
static usb_buf_t *_usb_allocBuffer(void)
{
	struct usb_chunk_hdr *hdr;
	usb_buf_t *buf;

	buf = _usb_allocPages(USB_BUF_SIZE, USB_BUF_SIZE);
	if (buf == NULL)
		return NULL;

	buf->next = NULL;
	buf->freesz = USB_BUF_SIZE - USB_CHUNK_SIZE;

	hdr = (struct usb_chunk_hdr *)buf->start;
	hdr->next = NULL;
	hdr->size = buf->freesz;
	buf->head = hdr;

	return buf;
}


/* Sanity-check a free-list node before dereferencing it. A free chunk header
 * must live inside this buffer's allocatable area, be USB_CHUNK_SIZE-aligned,
 * and carry a size that fits. This guards against a heap overflow (an
 * allocated buffer written past its end) that smashes an adjacent free-chunk
 * header or buf->head — which otherwise faults here as a wild-pointer deref.
 * NULL (end of list) is valid. */
static int usb_chunkSane(const usb_buf_t *buf, const struct usb_chunk_hdr *hdr)
{
	uintptr_t base = (uintptr_t)buf;
	uintptr_t h = (uintptr_t)hdr;

	if (hdr == NULL) {
		return 1;
	}
	if ((h < base + USB_CHUNK_SIZE) || (h >= base + USB_BUF_SIZE)) {
		return 0;
	}
	if ((h & (USB_CHUNK_SIZE - 1)) != 0) {
		return 0;
	}
	if ((hdr->size == 0) || (hdr->size > USB_BUF_SIZE - USB_CHUNK_SIZE)) {
		return 0;
	}
	if (h + hdr->size > base + USB_BUF_SIZE) {
		return 0;
	}
	return 1;
}


static void *usb_allocFrom(usb_buf_t *buf, size_t size)
{
	struct usb_chunk_hdr *prev, *next, *hdr = NULL;

	/* Search for a chunk in this buffer */
	if (buf->freesz >= size) {
		prev = buf->head;
		hdr = buf->head;
		if (!usb_chunkSane(buf, hdr)) {
			/* TODO(USB-MEM): free-list head corrupted by a heap overflow — see
			 * usb_chunkSane. Log and treat this buffer as full so we don't fault
			 * walking a wild pointer; the leak is bounded and recoverable. */
			fprintf(stderr, "usb_mem: free-list head corrupt: buf=%p head=%p (overflow upstream)\n",
				(void *)buf, (void *)hdr);
			usb_memReportCorrupt(buf, hdr);
			hdr = NULL;
		}
		else if (hdr->size < size) {
			hdr = hdr->next;
			while (hdr != NULL && usb_chunkSane(buf, hdr) && hdr->size < size) {
				prev = hdr;
				hdr = hdr->next;
			}
			if (!usb_chunkSane(buf, hdr)) {
				fprintf(stderr, "usb_mem: free-list node corrupt: buf=%p prev=%p next=%p (overflow upstream)\n",
					(void *)buf, (void *)prev, (void *)hdr);
				usb_memReportCorrupt(buf, hdr);
				hdr = NULL;
			}
		}
	}

	/* No big enough chunks in this buffer */
	if (hdr == NULL) {
		/* buf->next lives at offset 0 of the buffer header — the first field an
		 * adjacent-buffer forward overflow smashes (#121). usb_chunkSane only
		 * validates chunk headers, not the buffer pointer, so guard buf->next
		 * here or the recursion below faults dereferencing string bytes as a
		 * usb_buf_t (the observed EL0 Data Abort at usb_allocFrom "buf->freesz").
		 * Treat a smashed link as end-of-chain: log, report, leak the rest of the
		 * chain (bounded) rather than crash the daemon mid-enumeration. */
		if (!usb_bufSane(buf->next)) {
			fprintf(stderr, "usb_mem: buf->next corrupt, leaking chain: buf=%p next=%p (overflow upstream)\n",
				(void *)buf, (void *)buf->next);
			usb_memReportCorrupt(buf, (const struct usb_chunk_hdr *)buf->next);
			return NULL;
		}

		/* Alloc next buffer */
		if (buf->next == NULL) {
			if ((buf->next = _usb_allocBuffer()) == NULL)
				return NULL;
		}

		return usb_allocFrom(buf->next, size);
	}

	if (hdr->size > size) {
		/* Shrink this chunk */
		next = (struct usb_chunk_hdr *)((char *)hdr + size);
		next->next = hdr->next;
		next->size = hdr->size - size;
	}
	else {
		next = hdr->next;
	}

	if (hdr == buf->head)
		buf->head = next;
	else
		prev->next = next;

	buf->freesz -= size;
	memset(hdr, 0, size);

	return (void *)hdr;
}


void usb_free(void *ptr, size_t size)
{
	usb_buf_t *buf;
	struct usb_chunk_hdr *next, *prev, *hdr;

	if (ptr == NULL || size == 0)
		return;

	size = (size + (USB_CHUNK_SIZE - 1)) & ~(USB_CHUNK_SIZE - 1);
	if (size > USB_BUF_SIZE - USB_CHUNK_SIZE) {
		usb_freeAligned(ptr, size);
		return;
	}

	buf = (usb_buf_t *)((uintptr_t)ptr & ~(USB_BUF_SIZE - 1));
	hdr = (struct usb_chunk_hdr *)ptr;
	mutexLock(usb_mem_common.lock);

	/* If a heap overflow has corrupted this buffer's free-list (see
	 * usb_chunkSane), the coalescing walk below would fault dereferencing a
	 * wild next pointer. Detect it, log, and leak this chunk rather than crash
	 * or corrupt further — bounded and recoverable. */
	if ((buf->head != NULL) && !usb_chunkSane(buf, buf->head)) {
		fprintf(stderr, "usb_mem: free-list corrupt on free, leaking chunk: buf=%p head=%p (overflow upstream)\n",
			(void *)buf, (void *)buf->head);
		usb_memReportCorrupt(buf, buf->head);
		mutexUnlock(usb_mem_common.lock);
		return;
	}

	hdr->size = size;

	if (buf->head == NULL) {
		/* Buffer full */
		buf->head = (struct usb_chunk_hdr *)ptr;
		hdr->next = NULL;
	}
	else {
		prev = buf->head;
		/* Find, where to put the freed chunk */
		while (prev->next < hdr && prev->next != NULL)
			prev = prev->next;

		next = prev->next;
		if ((struct usb_chunk_hdr *)((uintptr_t)prev + prev->size) == ptr) {
			/* Left merge */
			prev->size += size;
			hdr = prev;
		}
		else if (prev > hdr) {
			buf->head = hdr;
			next = prev;
		}
		else {
			prev->next = hdr;
		}

		if ((struct usb_chunk_hdr *)((char *)hdr + hdr->size) == next) {
			/* Right merge */
			hdr->size += next->size;
			hdr->next = next->next;
		}
		else {
			hdr->next = next;
		}
	}

	buf->freesz += size;
	mutexUnlock(usb_mem_common.lock);
}


void *usb_alloc(size_t size)
{
	void *ret;

	if (size == 0)
		return NULL;

	size = (size + (USB_CHUNK_SIZE - 1)) & ~(USB_CHUNK_SIZE - 1);

	mutexLock(usb_mem_common.lock);
	if (size > USB_BUF_SIZE - USB_CHUNK_SIZE) {
		/* Whole pages: transfer buffers, which are not cleared here, as the
		 * caller fills them (OUT) or usb_transferSubmit() clears them (IN) */
		size = (size + (_PAGE_SIZE - 1)) & ~(_PAGE_SIZE - 1);
		ret = _usb_allocPages(size, _PAGE_SIZE);
	}
	else {
		ret = usb_allocFrom(usb_mem_common.buffer, size);
	}
	mutexUnlock(usb_mem_common.lock);

	return ret;
}


int usb_memInit(void)
{
	unsigned int i, nsegs = (USB_DMA_RESERVE_PAGES + USB_POOL_SEG_PAGES - 1U) / USB_POOL_SEG_PAGES;

	if (mutexCreate(&usb_mem_common.lock) != 0)
		return -1;

	mutexLock(usb_mem_common.lock);

	/* Not fatal: the pool grows on demand, and a request it cannot serve gets a block of its own */
	for (i = 0; i < nsegs; i++) {
		if (_usb_poolGrow() != 0) {
			fprintf(stderr, "usb: reserved %u of %u KiB of DMA memory\n", i * (unsigned int)(USB_POOL_SEG_SIZE / 1024U),
				nsegs * (unsigned int)(USB_POOL_SEG_SIZE / 1024U));
			break;
		}
	}

	usb_mem_common.buffer = _usb_allocBuffer();

	mutexUnlock(usb_mem_common.lock);

	if (usb_mem_common.buffer == NULL) {
		resourceDestroy(usb_mem_common.lock);
		return -1;
	}

	return 0;
}
