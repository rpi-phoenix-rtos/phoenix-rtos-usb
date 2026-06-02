/*
 * Phoenix-RTOS
 *
 * USB Hub
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */


#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/list.h>
#include <sys/minmax.h>
#include <sys/threads.h>
#include <sys/types.h>
#include <string.h>
#include <usb.h>
#include <unistd.h>

#include <usb.h>

#include "usbhost.h"
#include "hub.h"
#include "drv.h"
#include "hcd.h"
#include "dev.h"
#include "log.h"

#define HUB_ENUM_RETRIES     3
#define HUB_ENUM_GIVEUP      3   /* TODO(#129) stop re-enumerating a port after this many failed attempts (bounds the re-enum reboot-loop) */
#define HUB_DEBOUNCE_STABLE  100000
#define HUB_DEBOUNCE_PERIOD  25000
#define HUB_DEBOUNCE_TIMEOUT 1500000


#undef USB_LOG_TAG
#define USB_LOG_TAG "usbhub"

typedef struct _hub_event {
	struct _hub_event *next, *prev;
	usb_dev_t *hub;
	int scanAll; /* TODO(#129) 1 = scan ALL ports for present devices (initial scan), ignore status bitmap */
} hub_event_t;


struct {
	char stack[4096] __attribute__((aligned(8)));
	handle_t lock;
	handle_t cond;
	hub_event_t *events;
	usb_dev_t *tts;
} hub_common;


static int hub_getDesc(usb_dev_t *hub, char *buf, size_t len)
{
	usb_setup_packet_t setup = (usb_setup_packet_t) {
		.bmRequestType = REQUEST_DIR_DEV2HOST | REQUEST_TYPE_CLASS | REQUEST_RECIPIENT_DEVICE,
		.bRequest = REQ_GET_DESCRIPTOR,
		.wValue = USB_DESC_TYPE_HUB << 8,
		.wIndex = 0,
		.wLength = len,
	};

	return usb_devCtrl(hub, usb_dir_in, &setup, buf, len);
}


static int hub_setConf(usb_dev_t *hub, int conf)
{
	usb_setup_packet_t setup = (usb_setup_packet_t) {
		.bmRequestType = REQUEST_DIR_HOST2DEV | REQUEST_TYPE_STANDARD | REQUEST_RECIPIENT_DEVICE,
		.bRequest = REQ_SET_CONFIGURATION,
		.wValue = conf,
		.wIndex = 0,
		.wLength = 0,
	};

	return usb_devCtrl(hub, usb_dir_out, &setup, NULL, 0);
}


static int hub_setPortPower(usb_dev_t *hub, int port)
{
	usb_setup_packet_t setup = (usb_setup_packet_t) {
		.bmRequestType = REQUEST_DIR_HOST2DEV | REQUEST_TYPE_CLASS | REQUEST_RECIPIENT_OTHER,
		.bRequest = REQ_SET_FEATURE,
		.wValue = USB_PORT_FEAT_POWER,
		.wIndex = port,
		.wLength = 0
	};

	return usb_devCtrl(hub, usb_dir_out, &setup, NULL, 0);
}


static int hub_getPortStatus(usb_dev_t *hub, int port, usb_port_status_t *status)
{
	usb_setup_packet_t setup = (usb_setup_packet_t) {
		.bmRequestType = REQUEST_DIR_DEV2HOST | REQUEST_TYPE_CLASS | REQUEST_RECIPIENT_OTHER,
		.bRequest = REQ_GET_STATUS,
		.wValue = 0,
		.wIndex = port,
		.wLength = sizeof(usb_port_status_t)
	};

	return usb_devCtrl(hub, usb_dir_in, &setup, (char *)status, sizeof(usb_port_status_t));
}


static int hub_clearPortFeature(usb_dev_t *hub, int port, uint16_t wValue)
{
	usb_setup_packet_t setup = (usb_setup_packet_t) {
		.bmRequestType = REQUEST_DIR_HOST2DEV | REQUEST_TYPE_CLASS | REQUEST_RECIPIENT_OTHER,
		.bRequest = REQ_CLEAR_FEATURE,
		.wValue = wValue,
		.wIndex = port,
		.wLength = 0
	};

	return usb_devCtrl(hub, usb_dir_out, &setup, NULL, 0);
}


static int hub_setPortFeature(usb_dev_t *hub, int port, uint16_t wValue)
{
	usb_setup_packet_t setup = (usb_setup_packet_t) {
		.bmRequestType = REQUEST_DIR_HOST2DEV | REQUEST_TYPE_CLASS | REQUEST_RECIPIENT_OTHER,
		.bRequest = REQ_SET_FEATURE,
		.wValue = wValue,
		.wIndex = port,
		.wLength = 0
	};

	return usb_devCtrl(hub, usb_dir_out, &setup, NULL, 0);
}


static int hub_interruptInit(usb_dev_t *hub)
{
	usb_transfer_t *t;

	if ((t = calloc(1, sizeof(usb_transfer_t))) == NULL) {
		log_error("Out of memory!\n");
		return -ENOMEM;
	}

	if ((t->buffer = usb_alloc(sizeof(uint32_t))) == NULL) {
		free(t);
		log_error("Out of memory!\n");
		return -ENOMEM;
	}

	if ((hub->irqPipe = usb_pipeOpen(hub, 0, usb_dir_in, usb_transfer_interrupt)) == NULL) {
		usb_free(t->buffer, sizeof(uint32_t));
		free(t);
		log_error("Fail to open interrupt pipe!\n");
		return -ENOMEM;
	}

	t->type = usb_transfer_interrupt;
	t->direction = usb_dir_in;
	t->size = (hub->nports / 8) + 1;
	t->hub = hub;
	t->recipient = usb_drvType_hcd;

	hub->statusTransfer = t;

	return 0;
}


static int hub_requestStatus(usb_dev_t *hub)
{
	return usb_transferSubmit(hub->statusTransfer, hub->irqPipe, NULL);
}


static int hub_clearPortFeatures(usb_dev_t *hub, int port, uint32_t change)
{
	int i;

	for (i = 0; i < 5; i++) {
		if (change & (1 << i)) {
			if (hub_clearPortFeature(hub, port, USB_PORT_FEAT_C_CONNECTION + i) < 0)
				return -1;
		}
	}

	return 0;
}


int hub_portReset(usb_dev_t *hub, int port, usb_port_status_t *status)
{
	int retries;

	memset(status, 0, sizeof(*status));
	if (hub_setPortFeature(hub, port, USB_PORT_FEAT_RESET) < 0)
		return -1;

	for (retries = 5; (status->wPortChange & USB_PORT_STAT_C_RESET) == 0 && retries > 0; --retries) {
		usleep(100000);
		if (hub_getPortStatus(hub, port, status) < 0)
			return -1;
	}

	if (hub_clearPortFeatures(hub, port, status->wPortChange) < 0)
		return -1;

	return (retries > 0) ? 0 : -1;
}


static int hub_portDebounce(usb_dev_t *hub, int port)
{
	usb_port_status_t status;
	uint16_t pstatus = 0xffff;
	int totalTime = 0, stableTime = 0;
	int ret;

	while (totalTime < HUB_DEBOUNCE_TIMEOUT) {
		if ((ret = hub_getPortStatus(hub, port, &status)) < 0)
			return ret;

		if (!(status.wPortChange & USB_PORT_STAT_C_CONNECTION) &&
				(status.wPortStatus & USB_PORT_STAT_CONNECTION) == pstatus) {
			stableTime += HUB_DEBOUNCE_PERIOD;
			if (stableTime >= HUB_DEBOUNCE_STABLE)
				break;
		}
		else {
			stableTime = 0;
			pstatus = status.wPortStatus & USB_PORT_STAT_CONNECTION;
		}

		if (status.wPortChange & USB_PORT_STAT_C_CONNECTION)
			hub_clearPortFeature(hub, port, USB_PORT_FEAT_C_CONNECTION);

		totalTime += HUB_DEBOUNCE_PERIOD;
		usleep(HUB_DEBOUNCE_PERIOD);
	}

	if (stableTime < HUB_DEBOUNCE_STABLE)
		return -ETIMEDOUT;

	return pstatus;
}


static void hub_devDisconnect(usb_dev_t *dev, bool silent)
{
	usb_devDisconnected(dev, silent);
}


static void hub_devConnected(usb_dev_t *hub, int port)
{
	usb_dev_t *dev;
	usb_port_status_t status;
	int ret;
	int retries = HUB_ENUM_RETRIES;

	if ((dev = usb_devAlloc()) == NULL) {
		log_error("Not enough memory to allocate a new device!\n");
		return;
	}

	dev->hub = hub;
	dev->hcd = hub->hcd;
	dev->port = port;

	do {
		if ((ret = hub_portReset(hub, port, &status)) < 0) {
			log_error("fail to reset port %d\n", port);
			break;
		}

		if (status.wPortStatus & USB_PORT_STAT_HIGH_SPEED)
			dev->speed = usb_high_speed;
		else if (status.wPortStatus & USB_PORT_STAT_LOW_SPEED)
			dev->speed = usb_low_speed;
		else
			dev->speed = usb_full_speed;

		ret = usb_devEnumerate(dev);
		retries--;
		if (ret != 0 && !hub_portDebounce(hub, port)) {
			printf("usb: Enumeration failed. No retrying\n");
			break;
		}
		else if (ret != 0) {
			dev->hcd->ops->pipeDestroy(dev->hcd, dev->ctrlPipe);
			if (dev->address != 0)
				hcd_addrFree(hub->hcd, dev->address);
			dev->address = 0;
			dev->locationID = 0;
		}
	} while (ret != 0 && retries > 0);

	if (ret != 0) {
		/* TODO(#129) bound the log volume. When the VL805/hub link flaps (the
		 * intermittent Pi4 enumeration wall), the hub re-creates and its per-port
		 * GIVEUP counters reset, so a downstream device can be retried thousands
		 * of times. Logging every failure floods the UART; the back-pressure
		 * reset-loops the box (a stability bug distinct from the enum hang). Cap
		 * the message so the system stays up + networked even when a device never
		 * enumerates. */
		static unsigned enumFailLogged = 0;
		if (enumFailLogged < 8u) {
			printf("usb: Enumeration failed despite %d attempts\n", HUB_ENUM_RETRIES);
			if (++enumFailLogged == 8u) {
				printf("usb: enumeration-failure logging suppressed (link flapping)\n");
			}
		}
		hub_devDisconnect(dev, true);
	}
	else {
		/* TODO(#129) record the enumerated device so the port is tracked: the
		 * disconnect check in hub_connectstatus and the initial-scan dedup guard
		 * both test hub->devs[port-1]. Without this it stayed NULL forever, so a
		 * port could be (re-)enumerated twice. */
		hub->devs[port - 1] = dev;
	}
}


static void hub_connectstatus(usb_dev_t *hub, int port, usb_port_status_t *status)
{
	int pstatus;

	if (hub->devs[port - 1] != NULL) {
		hub_devDisconnect(hub->devs[port - 1], false);
		hub->devs[port - 1] = NULL; /* TODO(#129) keep tracking in sync (see hub_devConnected) */
		hub->portEnumFails[port - 1] = 0; /* a real disconnect: a fresh device may attach */
	}

	/* TODO(#129) bound the re-enum loop. A device that repeatedly fails to
	 * enumerate (e.g. the Pi4 LS keyboard behind the VL805 hub's TT) otherwise
	 * loops forever: each failed attempt resets the port, which re-fires a
	 * port-status change, which re-triggers enumeration. That flood
	 * (xhci "transfer completion timeout" x thousands) hangs/reboots the box.
	 * After HUB_ENUM_GIVEUP consecutive failures, stop retrying this port until
	 * the device is physically re-plugged (a disconnect clears the counter). */
	if (hub->portEnumFails[port - 1] >= HUB_ENUM_GIVEUP) {
		return;
	}

	pstatus = hub_portDebounce(hub, port);
	if (pstatus < 0) {
		return;
	}

	if (pstatus) {
		hub_devConnected(hub, port);
		/* hub_devConnected records hub->devs[port-1] on success; NULL = failed. */
		if (hub->devs[port - 1] == NULL) {
			if (hub->portEnumFails[port - 1] < 255u) {
				hub->portEnumFails[port - 1]++;
			}
			if (hub->portEnumFails[port - 1] == HUB_ENUM_GIVEUP) {
				fprintf(stderr, "usb: hub port %d gave up after %d failed enum attempts\n",
					port, HUB_ENUM_GIVEUP);
			}
		}
		else {
			hub->portEnumFails[port - 1] = 0;
		}
	}
}


static void hub_portstatus(usb_dev_t *hub, int port)
{
	usb_port_status_t status;
	int connection = 0;

	if (hub_getPortStatus(hub, port, &status) < 0)
		return;

	if (status.wPortChange & USB_PORT_STAT_C_CONNECTION) {
		hub_clearPortFeature(hub, port, USB_PORT_FEAT_C_CONNECTION);
		connection = 1;
	}

	if (status.wPortChange & USB_PORT_STAT_C_ENABLE) {
		hub_clearPortFeature(hub, port, USB_PORT_FEAT_C_ENABLE);
		if (!(status.wPortStatus & USB_PORT_STAT_ENABLE))
			connection = 1;
	}

	if (status.wPortChange & USB_PORT_STAT_C_RESET)
		hub_clearPortFeature(hub, port, USB_PORT_FEAT_C_RESET);

	if (connection)
		hub_connectstatus(hub, port, &status);
}


static uint32_t hub_getStatus(usb_dev_t *hub)
{
	uint32_t status = 0;

	if (usb_transferCheck(hub->statusTransfer)) {
		if (hub->statusTransfer->error == 0 && hub->statusTransfer->transferred > 0)
			memcpy(&status, hub->statusTransfer->buffer, sizeof(status));

		hub_requestStatus(hub);
	}

	return status;
}


static void hub_thread(void *args)
{
	hub_event_t *ev;
	uint32_t status;
	int i;

	for (;;) {
		mutexLock(hub_common.lock);
		while (hub_common.events == NULL) {
			condWait(hub_common.cond, hub_common.lock, 0);
		}
		ev = hub_common.events;
		LIST_REMOVE(&hub_common.events, ev);
		mutexUnlock(hub_common.lock);

		if (ev->scanAll) {
			/* TODO(#129) DELAYED FALLBACK initial scan: connect ports reporting a
			 * present device that the interrupt path has NOT already enumerated,
			 * independent of the interrupt status bitmap (see hub_conf). Runs in
			 * the hub thread so downstream enumeration doesn't re-enter the owning
			 * hub's ep0 path.
			 *
			 * The settle delay is essential: the interrupt status-change path is
			 * the PRIMARY mechanism and it works when it fires; this scan only
			 * covers the ~50% of boots where the single boot-time status-change
			 * URB is missed. Enumerating immediately after hub_conf failed (the
			 * hub's TT / port power-good for an LS device behind the HS hub is not
			 * settled yet -> the kbd enum fails and can hang). Waiting lets (a) the
			 * interrupt path enumerate first (then the devs[] guard below skips the
			 * port, avoiding a double-enum/churn) and (b) the TT settle. */
			usleep(2000000u);
			for (i = 0; i < ev->hub->nports; i++) {
				usb_port_status_t st;
				/* Skip ports the interrupt path already enumerated: a race
				 * between this scan and the boot-time status-change interrupt
				 * could otherwise have hub_connectstatus disconnect+reconnect an
				 * already-attached device (churn + frees its mbox while in use =
				 * the #121 UAF). Only the still-empty ports need the scan. */
				if (ev->hub->devs[i] != NULL) {
					continue;
				}
				if ((hub_getPortStatus(ev->hub, i + 1, &st) == 0) &&
						((st.wPortStatus & USB_PORT_STAT_CONNECTION) != 0)) {
					hub_connectstatus(ev->hub, i + 1, &st);
				}
			}
		}
		else {
			status = hub_getStatus(ev->hub);
			for (i = 0; i < ev->hub->nports; i++) {
				if (status & (1 << (i + 1)))
					hub_portstatus(ev->hub, i + 1);
			}
		}

		free(ev);
	}
}


static void hub_postEvent(usb_dev_t *hub, int scanAll)
{
	hub_event_t *e;

	if ((e = malloc(sizeof(hub_event_t))) == NULL)
		return;

	e->hub = hub;
	e->scanAll = scanAll;

	mutexLock(hub_common.lock);
	LIST_ADD(&hub_common.events, e);
	condSignal(hub_common.cond);
	mutexUnlock(hub_common.lock);
}


void hub_notify(usb_dev_t *hub)
{
	hub_postEvent(hub, 0);
}


/* TODO(#129) deferred initial full-port scan — see hub_conf. */
static void hub_notifyScan(usb_dev_t *hub)
{
	hub_postEvent(hub, 1);
}


int hub_conf(usb_dev_t *hub)
{
	char buf[15];
	usb_hub_desc_t *desc;
	int i;
	int ret;

	if (hub_setConf(hub, 1) < 0) {
		log_error("Fail to set configuration!\n");
		return -EINVAL;
	}

	if (hub_getDesc(hub, buf, sizeof(buf)) < 0) {
		log_error("Fail to get descriptor\n");
		return -EINVAL;
	}

	/* Hub descriptors might vary in size */
	desc = (usb_hub_desc_t *)buf;
	hub->nports = min(USB_HUB_MAX_PORTS, desc->bNbrPorts);
	if ((hub->devs = calloc(hub->nports, sizeof(usb_dev_t *))) == NULL) {
		log_error("Out of memory!\n");
		return -ENOMEM;
	}
	if ((hub->portEnumFails = calloc(hub->nports, sizeof(unsigned char))) == NULL) {
		log_error("Out of memory!\n");
		free(hub->devs);
		return -ENOMEM;
	}

	for (i = 0; i < hub->nports; i++) {
		if (hub_setPortPower(hub, i + 1) < 0) {
			log_error("Fail to set port %d power!\n", i + 1);
			free(hub->devs);
			return -EINVAL;
		}
	}

	if (hub_interruptInit(hub) != 0)
		return -EINVAL;

	ret = hub_requestStatus(hub);
	if (ret < 0)
		return ret;

	/* Initial port scan (#129): enumerate devices already connected when the hub
	 * is powered on, instead of relying solely on the interrupt status-change
	 * pipe. The status-change endpoint reports the boot-time connect only once,
	 * and the single in-flight status URB can miss/lose that one completion
	 * (observed on the Pi 4 VL805: downstream kbd/mouse enumerated only ~50% of
	 * boots while the hub itself always came up). Mainline hub drivers scan ports
	 * after powering them; this makes boot-time enumeration deterministic, and the
	 * interrupt pipe still drives later hotplug. The scan MUST run in the hub
	 * thread, NOT synchronously here: hub_conf executes inside this hub's own
	 * enumeration, and enumerating a downstream device re-entrantly would clobber
	 * the single-slot ep0 state (xhci->cur). Posting an event defers it to the
	 * hub thread, the same context the interrupt path uses.
	 *
	 * TODO(#129) DISABLED again: even with devs[] tracking + enterHaltedState
	 * no-op-under-keepRunning, the scan-triggered downstream enum FAILS to bind
	 * the kbd (insertions=0) and ~50% of boots still hang/lose the network — yet
	 * the interrupt-TRIGGERED enum of the same kbd SUCCEEDS (idemp boot bound
	 * /dev/kbd0). Same enum code, so the difference is timing/state: the scan runs
	 * right after hub_conf (hub just configured), likely before the hub's TT/ports
	 * settle, so the LS-kbd-behind-TT enum fails too early. Next: try a settle
	 * delay before the scan, or fix the hub INTERRUPT delivery instead of scanning.
	 * NB: the enterHaltedState fix did NOT stop the hang -> there is another hang
	 * source (mbox UAF killing TCP/IP, or another loop). */
	/* TODO(#129) DISABLED: 4 scan variants (sync, async, guarded, delayed-fallback)
	 * all consistently FAIL to bind the kbd (insertions=0) and cause intermittent
	 * hangs, whereas the interrupt-path enum of the same kbd succeeds. The scan-
	 * triggered enum differs from interrupt-triggered in some context/state we
	 * have not isolated (UART captures keep truncating). Approach parked; next
	 * session: deep UART analysis of the scan-enum bind failure, OR fix the hub
	 * interrupt-completion delivery directly (the root of the ~50% rate). */
	(void)hub_notifyScan; /* hub_notifyScan(hub); */

	return 0;
}


int hub_init(void)
{
	if (mutexCreate(&hub_common.lock) != 0)
		return -ENOMEM;

	if (condCreate(&hub_common.cond) != 0) {
		resourceDestroy(hub_common.lock);
		return -ENOMEM;
	}

	if (beginthread(hub_thread, 4, hub_common.stack, sizeof(hub_common.stack), NULL) != 0) {
		resourceDestroy(hub_common.lock);
		resourceDestroy(hub_common.cond);
		return -ENOMEM;
	}

	return 0;
}
