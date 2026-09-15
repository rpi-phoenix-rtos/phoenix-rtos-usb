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
 * were evicted over the pool (usb `12c4fe8`, the dc-civac in usb_allocBuffer
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


static struct {
	usb_buf_t *buffer;
	handle_t lock;
} usb_mem_common;


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


/* A usb_buf_t* must be USB_BUF_SIZE-aligned (every pool buffer comes from
 * usb_allocAligned(USB_BUF_SIZE, USB_BUF_SIZE)). An overflow that smashes a
 * buffer header's buf->next field (offset 0) leaves a non-aligned wild pointer
 * there; reject it before usb_allocFrom recurses into it and faults dereferencing
 * string bytes as a usb_buf_t (#121). NULL is valid (end of the buffer chain). */
static int usb_bufSane(const usb_buf_t *buf)
{
	if (buf == NULL) {
		return 1;
	}
	return (((uintptr_t)buf & (USB_BUF_SIZE - 1)) == 0) ? 1 : 0;
}


static void *usb_allocUncached(size_t size)
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


void *usb_allocAligned(size_t size, size_t alignment)
{
	char *addr, *res;

	size = (size + (_PAGE_SIZE - 1)) & ~(_PAGE_SIZE - 1);
	alignment = (alignment + (_PAGE_SIZE - 1)) & ~(_PAGE_SIZE - 1);

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


void usb_freeAligned(void *ptr, size_t size)
{
	munmap(ptr, size);
}


static usb_buf_t *usb_allocBuffer(void)
{
	struct usb_chunk_hdr *hdr;
	usb_buf_t *buf;

	buf = usb_allocAligned(USB_BUF_SIZE, USB_BUF_SIZE);
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
			if ((buf->next = usb_allocBuffer()) == NULL)
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
		munmap(ptr, size);
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
	/* Don't manage larger buffers */
	if (size > USB_BUF_SIZE - USB_CHUNK_SIZE)
		return usb_allocAligned(size, USB_BUF_SIZE);

	mutexLock(usb_mem_common.lock);
	ret = usb_allocFrom(usb_mem_common.buffer, size);
	mutexUnlock(usb_mem_common.lock);

	return ret;
}


int usb_memInit(void)
{
	if ((usb_mem_common.buffer = usb_allocBuffer()) == NULL)
		return -1;

	return mutexCreate(&usb_mem_common.lock);
}
