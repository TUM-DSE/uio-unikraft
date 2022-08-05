#ifndef __PLAT_DRV_VIRTIO_CONSLE_H
#define __PLAT_DRV_VIRTIO_CONSLE_H

#include <uk/config.h>
#include <uk/arch/types.h>

#include <virtio/virtio_ids.h>
#include <virtio/virtio_config.h>
#include <virtio/virtio_types.h>

#define VIRTIO_CONSOLE_F_SIZE 0
#define VIRTIO_CONSOLE_F_MULTIPORT 1
#define VIRTIO_CONSOLE_F_EMERG_WRITE 2

#define VIRTIO_CONSOLE_DEVICE_READY 0
#define VIRTIO_CONSOLE_PORT_ADD 1
#define VIRTIO_CONSOLE_PORT_REMOVE 2
#define VIRTIO_CONSOLE_PORT_READY 3
#define VIRTIO_CONSOLE_CONSOLE_PORT 4
#define VIRTIO_CONSOLE_RESIZE 5
#define VIRTIO_CONSOLE_PORT_OPEN 6
#define VIRTIO_CONSOLE_PORT_NAME 7

struct virtio_console_resize {
	__virtio_le16 cols;
	__virtio_le16 rows;
};

#endif /* __PLAT_DRV_VIRTIO_CONSOLE_H */
