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

/* TODO(USB-MEM): diagnostic instrumentation for issue #121 — the free-list head
 * is intermittently found smashed with non-pointer (recycled DRAM) bytes during
 * early USB enumeration. Static analysis has cleared every in-stack copy site
 * (ctrlBuf/string/config descriptors, hub status, xHCI TRB programming are all
 * length-bounded), so the writer is external to this pool's logical owners — the
 * prime remaining hypothesis is a controller DMA write landing in a chunk that
 * was already freed and recoalesced (a transfer buffer freed via usb_free while
 * the xHCI still has a live TRB pointing at it). This block captures, on the next
 * boot, enough context to discriminate that from a stray content overflow:
 *   - the corrupt header's raw bytes (hex + ASCII), so identifiable USB
 *     descriptor/report bytes vs. plain text name the source class, and
 *   - a ring of the most recent usb_free() {addr,size}; if the corrupt chunk's
 *     address matches a recently-freed buffer, it is a use-after-free.
 * Remove once the writer is pinned and fixed. */
#define USB_FREELOG_DEPTH 16


struct usb_chunk_hdr {
	struct usb_chunk_hdr *next;
	size_t size;
};


struct usb_freelog_ent {
	void *addr;
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

	/* TODO(USB-MEM): #121 diagnostic free-log ring; see comment above. The lock
	 * is held by every usb_free() and by the corruption-report path, so the ring
	 * needs no separate synchronization. */
	struct usb_freelog_ent freelog[USB_FREELOG_DEPTH];
	unsigned freelogPos;
} usb_mem_common;


/* TODO(USB-MEM): #121 — record a freed chunk in the ring. Caller must hold the
 * pool lock. */
static void usb_freelogRecord(void *addr, size_t size)
{
	usb_mem_common.freelog[usb_mem_common.freelogPos].addr = addr;
	usb_mem_common.freelog[usb_mem_common.freelogPos].size = size;
	usb_mem_common.freelogPos = (usb_mem_common.freelogPos + 1) % USB_FREELOG_DEPTH;
}


/* TODO(USB-MEM): #121 — dump the bytes of a smashed free-list node plus the
 * recent-free ring, so the next boot pins the corruption mechanism. Caller must
 * hold the pool lock. 'hdr' is the wild pointer caught by usb_chunkSane; it may
 * point anywhere inside the buffer, so clamp the dump to the buffer bounds. */
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

	fprintf(stderr, "usb_mem: recent frees (newest last):");
	for (i = 0; i < USB_FREELOG_DEPTH; i++) {
		unsigned idx = (usb_mem_common.freelogPos + i) % USB_FREELOG_DEPTH;
		struct usb_freelog_ent *e = &usb_mem_common.freelog[idx];
		if (e->addr != NULL) {
			fprintf(stderr, " %p/%zu%s", e->addr, e->size,
				(e->addr == (void *)hdr) ? "<==MATCH(use-after-free)" : "");
		}
	}
	fprintf(stderr, "\n");
}


static void *usb_allocUncached(size_t size)
{
	void *res;

	/* MAP_CONTIGUOUS + MAP_PRIVATE matches the flags used by the Pi 4
	 * 'X' diag rig (port/diag-udp.c) and by the kernel
	 * drivers/physmmap.c dmammap helper. Keep them so we're consistent
	 * with the rig's allocator — verified to not affect rig flakiness
	 * (the rig was flaky with both flag sets), so this is just code
	 * hygiene. Other ports either ignore MAP_CONTIGUOUS or honor it
	 * without cost. */
	if ((res = mmap(NULL, size, PROT_WRITE | PROT_READ,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_UNCACHED | MAP_CONTIGUOUS, -1, 0)) == MAP_FAILED)
		return NULL;

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

	/* TODO(USB-MEM): #121 diagnostic — record this free so the corruption-report
	 * path can tell whether a smashed node matches a recently-freed chunk. */
	usb_freelogRecord(ptr, size);

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
