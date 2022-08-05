#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <uk/alloc.h>
#include <uk/essentials.h>
#include <uk/sglist.h>
#include <virtio/virtio_bus.h>
#include <virtio/virtio_ids.h>
#include <virtio/virtio_console.h>
#include <uk/console.h>

#define DRIVER_NAME "virtio-console"
static struct uk_alloc *a;

struct virtio_console_queue {
	struct virtqueue *vq;
	uint16_t hwvq_id;
	struct uk_sglist sg;
	struct uk_sglist_seg sgsegs[1];
	char buf[1];
};

struct virtio_console_device {
	struct virtio_dev *vdev;
	struct virtio_console_queue *rxq;
	struct virtio_console_queue *txq;
};

static int virtio_console_start(struct virtio_console_device *d)
{
	int rc = 0;
	UK_ASSERT(d != NULL);

	virtqueue_intr_disable(d->rxq->vq);
	virtqueue_intr_disable(d->txq->vq);
	// rc = virtqueue_intr_enable(d->rxq->vq);
	UK_ASSERT(rc == 0);
	virtio_dev_drv_up(d->vdev);
	uk_pr_info(DRIVER_NAME ": started\n");

	return 0;
}

static inline void virtio_console_feature_set(struct virtio_console_device *d)
{
	d->vdev->features = 0;
}

static int virtio_console_feature_negotiate(struct virtio_console_device *d)
{
	__u64 host_features;
	host_features = virtio_feature_get(d->vdev);

	uk_pr_info(DRIVER_NAME ": host feature = %#lx\n", host_features);

	return 0;
}

static int virtio_console_recv(struct virtqueue *vq, void *priv)
{
	int handled = 1;
	uk_pr_info(DRIVER_NAME ": recv\n");
	return handled;
}

static int virtio_console_vq_alloc(struct virtio_console_device *d)
{
	int vq_avail = 0;
	int rc = 0;
	int total_vqs = 2;
	int i = 0;
	__u16 qdesc_size[total_vqs];

	vq_avail = virtio_find_vqs(d->vdev, total_vqs, &qdesc_size[0]);
	if (unlikely(vq_avail != total_vqs)) {
		uk_pr_err(DRIVER_NAME ": Expected: %d queues, found %d\n",
			  total_vqs, vq_avail);
		rc = -ENOMEM;
		goto exit;
	}
	for (i = 0; i < total_vqs; i++) {
		uk_pr_debug(DRIVER_NAME ": qdesc_size[%d] = %d\n", i,
			    qdesc_size[i]);
	}

	// Setup rx queue
	d->rxq->hwvq_id = 0;
	d->rxq->vq = virtio_vqueue_setup(d->vdev, d->rxq->hwvq_id,
					 qdesc_size[0], virtio_console_recv, a);
	if (unlikely(PTRISERR(d->rxq->vq))) {
		uk_pr_err(DRIVER_NAME ": Failed to set up receiveq %" PRIu16
				      "\n",
			  d->rxq->hwvq_id);
		rc = PTR2ERR(d->rxq->hwvq_id);
		goto exit;
	}
	uk_sglist_init(&d->rxq->sg, 1, &d->rxq->sgsegs[0]);
	d->rxq->vq->priv = d;

	// Setup tx queue
	d->txq->hwvq_id = 1;
	d->txq->vq = virtio_vqueue_setup(d->vdev, d->txq->hwvq_id,
					 qdesc_size[1], NULL, a);
	if (unlikely(PTRISERR(d->txq->vq))) {
		uk_pr_err(DRIVER_NAME ": Failed to set up transmitq %" PRIu16
				      "\n",
			  d->txq->hwvq_id);
		rc = PTR2ERR(d->txq->vq);
		goto exit;
	}
	uk_sglist_init(&d->rxq->sg, 1, &d->rxq->sgsegs[0]);
	d->txq->vq->priv = d;

exit:
	return rc;
}

static int virtio_console_rxq_enqueue(struct virtio_console_device *d)
{
	struct uk_sglist *sg = &d->rxq->sg;
	void *buf = &d->rxq->buf[0];
	int rc;

	uk_sglist_reset(sg);

	rc = uk_sglist_append(sg, buf, 1);
	if (unlikely(rc != 0)) {
		uk_pr_err(DRIVER_NAME ": Failed to uk_sglist_append()\n");
		return rc;
	}

	rc = virtqueue_buffer_enqueue(d->rxq->vq, buf, sg, 0, sg->sg_nseg);
	if (likely(rc >= 0)) {
		// virtqueue_host_notify(d->rxq->vq);
		rc = 0;
	}

	return rc;
}

static int virtio_console_configure(struct virtio_console_device *d)
{
	int rc = 0;

	rc = virtio_console_feature_negotiate(d);
	if (rc != 0) {
		uk_pr_err(DRIVER_NAME
			  ": Failed to negotiate the device feature %d\n",
			  rc);
		rc = -EINVAL;
		goto out_status_fail;
	}

	rc = virtio_console_vq_alloc(d);
	if (rc) {
		uk_pr_err(DRIVER_NAME ": Could not allocate virtqueue\n");
		goto out_status_fail;
	}

	rc = virtio_console_rxq_enqueue(d);
	if (rc) {
		uk_pr_err(DRIVER_NAME
			  ": Failed to add a buffer to receive queue\n");
		goto out_status_fail;
	}

	uk_pr_info(DRIVER_NAME ": Configured: features=0x%lx\n",
		   d->vdev->features);
out:
	return rc;

out_status_fail:
	virtio_dev_status_update(d->vdev, VIRTIO_CONFIG_STATUS_FAIL);
	goto out;
}

static int virtio_console_add_dev(struct virtio_dev *vdev)
{
	struct virtio_console_device *vcdev = NULL;
	struct uk_console_device *uk_cdev = NULL;
	int rc = 0;

	UK_ASSERT(vdev != NULL);

	vcdev = uk_calloc(a, 1, sizeof(*vcdev));
	if (!vcdev) {
		rc = -ENOMEM;
		goto out;
	}
	vcdev->vdev = vdev;

	vcdev->rxq = uk_calloc(a, 1, sizeof(*vcdev->rxq));
	if (!vcdev) {
		rc = -ENOMEM;
		goto out_free;
	}

	vcdev->txq = uk_calloc(a, 1, sizeof(*vcdev->txq));
	if (!vcdev) {
		rc = -ENOMEM;
		goto out_free;
	}

	virtio_console_feature_set(vcdev);
	rc = virtio_console_configure(vcdev);
	if (rc)
		goto out_free;

	rc = virtio_console_start(vcdev);
	if (rc)
		goto out_free;

	uk_cdev = uk_calloc(a, 1, sizeof(*uk_cdev));
	if (!uk_cdev) {
		rc = -ENOMEM;
		goto out_free;
	}

	strncpy(&uk_cdev->name[0], "virtio-console", sizeof(uk_cdev->name));
	uk_cdev->ops.getc = NULL;
	uk_cdev->ops.putc = NULL;
	uk_console_register_device(uk_cdev);

out:
	return rc;
out_free:
	if (vcdev) {
		uk_free(a, vcdev->rxq);
		uk_free(a, vcdev->txq);
	}
	uk_free(a, vcdev);
	uk_free(a, uk_cdev);
	goto out;
}

static int virtio_console_drv_init(struct uk_alloc *drv_allocator)
{
	if (!drv_allocator) {
		return -EINVAL;
	}

	a = drv_allocator;

	return 0;
}

// clang-format off
static const struct virtio_dev_id vconsole_dev_id[] = {
	{VIRTIO_ID_CONSOLE},
	{VIRTIO_ID_INVALID} /* List Terminator */
};

static struct virtio_driver vconsole_drv = {
	.dev_ids = vconsole_dev_id,
	.init = virtio_console_drv_init,
	.add_dev = virtio_console_add_dev
};
// clang-format on

VIRTIO_BUS_REGISTER_DRIVER(&vconsole_drv);
