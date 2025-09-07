#include <linux/init.h>      
#include <linux/module.h>    
#include <linux/kernel.h>
#include <linux/device.h> 
#include <linux/stat.h> 
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/firmware.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/i2c.h>
#include <linux/mod_devicetable.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/printk.h>

MODULE_LICENSE("GPL");        
MODULE_AUTHOR("Hari Prasath Kumar @ hari-kumar@ti.com");   
MODULE_DESCRIPTION("TI PMIC FW Download kernel module");
MODULE_VERSION("0.1");        

#define NONCE_SIZE  32U

struct class *dwnld_class = NULL;
struct device *dwnld_device = NULL;
struct workqueue_struct *dwnld_req = NULL;
struct delayed_work dwnld_work = {0};
struct i2c_client *dwnld_client = NULL;
static atomic_t dwnld_in_progress = ATOMIC_INIT(0);
static atomic_t current_byte = ATOMIC_INIT(0);
static atomic_t total_bytes = ATOMIC_INIT(0);

static s32 pmic_download_compute_hmac(bool mac, const char *algo_name, const u8 *data, u32 dlen, const u8 *key, u32 klen, u8 *digest);
static s32 pmic_download_compute_sha384(const u8 *msg, u32 msg_len, u8 *hash384);
static s32 pmic_download_write_chunk_fw(const u8 *f, u32 flen, const u8 *ephemeral_key);
static void pmic_download_get_random_number(u8 *nonce);
static s32 pmic_download_derive_mac_key(const u8 *nonce, const u8 *key, u8 *derived_key);
static s32 pmic_download_update_buffer(const u8 *data, u32  dlen, u32 buffer_num);
static s32 pmic_download_update_fw(const u8 *fw, u32 fwlen, const u8 *key, u32 klen);
static void pmic_download_i2c_remove(struct i2c_client *client);

static ssize_t status_show(struct device *dev,
                            struct device_attribute *attr,
                            char *buf)
{
    return sprintf(buf, "%d / %d\n", atomic_read(&current_byte), atomic_read(&total_bytes));
}

static ssize_t progress_show(struct device *dev,
                            struct device_attribute *attr,
                            char *buf)
{
    return sprintf(buf, "%d\n", atomic_read(&dwnld_in_progress));
}

static ssize_t trigger_store(struct device *dev,
                            struct device_attribute *attr,
                            const char *buf, size_t count)
{
    pr_info("[pmic-download] trigger_store\n");

    if (!atomic_cmpxchg(&dwnld_in_progress, 0, 1)) {
        /* bool queue_delayed_work(struct workqueue_struct *wq,
                    struct delayed_work *dwork,
                    unsigned long delay) */
        pr_info("[pmic-download] work queued\n");
        queue_delayed_work(dwnld_req, &dwnld_work, msecs_to_jiffies(10));
    } else {
        pr_info("[pmic-download] work not queued busy\n");
        return -EBUSY; 
    }

    return count;
}

#define BUFFER_0   0
#define BUFFER_1   1
#define BUFFER_2   2


static s32 pmic_download_compute_hmac(bool mac, const char *algo_name, const u8 *data, u32 dlen, const u8 *key, u32 klen, u8 *digest) {
    struct crypto_shash *hmac_handle = NULL;
    struct shash_desc *hmac_ctxt = NULL;
    s32 ret;

    if (!algo_name || !data || !digest) {
        pr_err("[pmic-download] invalid args\n");
        return -EINVAL;
    }

    /* struct crypto_shash *crypto_alloc_shash(const char *alg_name, u32 type,
					u32 mask); */
    hmac_handle = crypto_alloc_shash(algo_name, 0, 0);
    if (IS_ERR(hmac_handle)) {
        pr_err("[pmic-download] hmac allocation failed %ld \n", PTR_ERR(hmac_handle));
        return PTR_ERR(hmac_handle);
    }

    hmac_ctxt = kmalloc(sizeof(*hmac_ctxt) + crypto_shash_descsize(hmac_handle), GFP_KERNEL);
    if (!hmac_ctxt) {
        pr_err("[pmic-download] hmac context allocation failed %ld \n", PTR_ERR(hmac_ctxt));
        /* void crypto_free_shash(struct crypto_shash *tfm) */
        crypto_free_shash(hmac_handle);
        return -ENOMEM;
    }

    hmac_ctxt->tfm = hmac_handle;

    if (mac) {
        if (!key) {
            pr_err("[pmic-download] key null\n");
            return -EINVAL;
        }
        ret = crypto_shash_setkey(hmac_handle, key, klen);
        if (ret) goto err;
    }

    ret = crypto_shash_init(hmac_ctxt);
    if (ret) goto err;

    ret = crypto_shash_update(hmac_ctxt, data, dlen);
    if (ret) goto err;

    ret = crypto_shash_final(hmac_ctxt, digest);

err:
    kfree(hmac_ctxt);
    crypto_free_shash(hmac_handle);
    return ret;
}


static s32 pmic_download_compute_sha384(const u8 *msg, u32 msg_len, u8 *hash384) {
    return pmic_download_compute_hmac(false, "sha384", msg, msg_len, NULL, 0, hash384);
}


static s32 pmic_download_write_chunk_fw(const u8 *f, u32 flen, const u8 *ephemeral_key) {
    s32 ret;
    u8 hash384[48] = {0};
    u8 digest[32] = {0};

    ret = pmic_download_compute_sha384(f, flen, hash384);
    if (ret < 0) return ret;

    ret = pmic_download_compute_hmac(true, "hmac(sha256)", (const u8 *)f, flen, ephemeral_key, 32, digest);
    if (ret < 0) return ret;

    /* Select Buffer 2 -> reset window, 1kB at a time FW */
    ret = pmic_download_update_buffer(f, flen, BUFFER_2);
    pr_info("[pmic-download] pmic_download_update_buffer %d \n", BUFFER_2);
    if (ret < 0) return ret;

    /* Select Buffer 0 -> Write MAC Digest */
    ret = pmic_download_update_buffer(digest, 32, BUFFER_0);
    pr_info("[pmic-download] pmic_download_update_buffer %d\n" , BUFFER_0);
    if (ret < 0) return ret;

    /* Trigger Program */
    ret = 0; // i2c_smbus_write_byte_data(dwnld_client, 0x68, 0x80);
    if (ret < 0) return ret;

    return 0;
}

static s32 pmic_download_fw_chunk_update(const u8 *f, u32 flen, u32 buffer_num) 
{
    u32 blocks = flen / 32;
    u32 rem    = flen % 32;
    s32 ret;
    u32 i = 0;
    u8 buf[32];

    pr_info("[pmic-download] pmic_download_fw_chunk_update len = %d blocks = %d, rem = %d \n", flen, blocks, rem);

    for (u32 blk_idx = 0; blk_idx < blocks; blk_idx++) {
        for (u32 b = 0; b < 32; b++, i++) {
            buf[b] = f[i];
            if (buffer_num == BUFFER_2)
                atomic_inc(&current_byte);
        }

        ret = 0; // i2c_smbus_write_block_data(dwnld_client, 0x81, 32, buf);
        if (ret < 0) {
            pr_err("[pmic-download] err at block %u\n", blk_idx);
            return ret;
        }
        pr_info("[pmic-download] sent block %u\n", blk_idx);
    }

    if (rem) {
        memset(buf, 0, sizeof(buf));
        for (u32 b = 0; b < rem; b++, i++) {
            buf[b] = f[i];
            if (buffer_num == BUFFER_2)
                atomic_inc(&current_byte);
        }

        ret = 0; // i2c_smbus_write_block_data(dwnld_client, 0x81, 32, buf);
        if (ret < 0) {
            pr_err("[pmic-download] err at last block\n");
            return ret;
        }
        pr_info("[pmic-download] sent last partial block\n");
    }
    
    return 0;
}

static void pmic_download_get_random_number(u8 *nonce) {
    get_random_bytes(nonce, NONCE_SIZE);
}

static s32 pmic_download_derive_mac_key(const u8 *nonce, const u8 *key, u8 *derived_key) {

    u8 msg[25+NONCE_SIZE] = {0};
    char str[] = "VR security protocol";
    const u8 *p = nonce;
    s32 ret;

    for (u32 i = 0; i < NONCE_SIZE; i++) msg[2+i] = *p++;
    for (u32 i = 0; i < 20; i++) msg[35+i] = str[i]; // without null
    msg[1] = msg[55] = 0x01;

    /* derived_key = HMAC(msg, key) */
    ret = pmic_download_compute_hmac(true, "hmac(sha256)", (const u8 *)msg, 25 + NONCE_SIZE, key, 32, derived_key);
    if (ret) return ret;

    return 0;
}

static s32 pmic_download_update_buffer(const u8 *data, u32  dlen, u32 buffer_num) {
    s32 ret;

    /* Set Buffer target */
    ret = 0; // i2c_smbus_write_byte_data(dwnld_client, 0x66, buffer_num);
    if (ret < 0) {
        pr_info("[pmic-download] err i2c write byte %d", ret);
        return ret;
    }

    /* Reset window */
    ret = 0; // i2c_smbus_write_byte_data(dwnld_client, 0x67, 0);
    if (ret < 0) return ret;

    pr_info("[pmic-download] pmic_download_fw_chunk_update \n");
    ret = pmic_download_fw_chunk_update(data, dlen, buffer_num);
    if (ret < 0) return ret;

    return 0;
}

static s32 pmic_download_update_fw(const u8 *fw, u32 fwlen, const u8 *key, u32 klen) {
    u8 nonce[NONCE_SIZE];
    u8 ephemeral_key[32];
    s32 ret;
    const u8 *f = NULL;

    pmic_download_get_random_number(nonce);
    pr_info("[pmic-download] Random number generated \n");

    ret = pmic_download_derive_mac_key((const u8 *)nonce, (const u8 *)key, ephemeral_key);
    if (ret) return ret;
    pr_info("[pmic-download] EPHEMERAL_KEY generated \n");
    
    /* Select Buffer 1 -> write Nonce */
    ret = pmic_download_update_buffer(nonce, NONCE_SIZE, BUFFER_1);
    if (ret < 0) return ret;

    f = fw;
    atomic_set(&total_bytes, fwlen);
    atomic_set(&current_byte, 0);

    while (fwlen) {
        size_t chunk_len = min(1024U, fwlen);
        ret = pmic_download_write_chunk_fw(f, chunk_len, ephemeral_key);
        pr_info("[pmic-download] FW_DATA chunk %d \n", chunk_len);

        if (ret < 0) return ret;

        f += 1024;
        fwlen -= chunk_len;
    }

    return 0;
}


static void dwnld_work_handler(struct work_struct *work)
{
    const struct firmware *fw;
    const struct firmware *key;
    u32 ret;
    pr_info("[pmic-download] fw_work_handler triggered\n");
    
    /* int request_firmware(const struct firmware **fw, const char *name,
		     struct device *device);*/
    ret = request_firmware(&fw, "ti_buck_fw.bin", dwnld_device);
    if (ret < 0 || !fw) {
        pr_err("[pmic-download] fw loading failed error code : %d\n", ret);
        atomic_set(&dwnld_in_progress, 0);
        atomic_set(&current_byte, 0);
        atomic_set(&total_bytes, 0);
        return;
    }

    ret = request_firmware(&key, "ti_buck_fw_key.bin", dwnld_device);
    if (ret < 0 || !key) {
        pr_err("[pmic-download] key loading failed error code : %d\n", ret);
        release_firmware(fw);
        atomic_set(&dwnld_in_progress, 0);
        atomic_set(&current_byte, 0);
        atomic_set(&total_bytes, 0);
        return;
    }

    ret = pmic_download_update_fw(fw->data, fw->size, key->data, key->size);
    if (ret < 0) {
        pr_info("[pmic-download] error during download %d\n", ret);
    } else {
        pr_info("[pmic-download] fw_work_handler completed\n"); 
    }

    /* void release_firmware(const struct firmware *fw); */
    release_firmware(fw);
    release_firmware(key);
    atomic_set(&dwnld_in_progress, 0);
    atomic_set(&current_byte, 0);
}


static int pmic_download_i2c_probe(struct i2c_client *client,
                                   const struct i2c_device_id *id) {
    dwnld_client = client;
    
    return 0;
}

static void pmic_download_i2c_remove(struct i2c_client *client) {
    dwnld_client = NULL;
    pr_info("[pmic-download] pmic_download_i2c_remove \n");
}

static DEVICE_ATTR_WO(trigger);
static DEVICE_ATTR_RO(status);
static DEVICE_ATTR_RO(progress);

/* int i2c_register_driver(struct module *owner, struct i2c_driver *driver); */
static const struct i2c_device_id pmic_id[] = {
    { "ti-pmic-fw-dwnld", 0 },
    { }
};
MODULE_DEVICE_TABLE(i2c, pmic_id);

static struct i2c_driver driver_if = {
    .driver = {
        .name = "ti-pmic-fw-dwnld",
    },
    .probe = pmic_download_i2c_probe,
    .remove = pmic_download_i2c_remove,
    .id_table = pmic_id,
};


static int __init pmic_download_init(void)
{
    int ret;

    pr_info("[pmic-download] module loaded\n");

    ret = i2c_register_driver(THIS_MODULE, &driver_if);
    if (ret < 0) {
        pr_err("[pmic-download] Cannot register to I2C Core\n");
        return ret;
    }

    dwnld_class = class_create(THIS_MODULE, "pmic_fw_downloader");
    if (IS_ERR(dwnld_class)) {
        pr_err("[pmic-download] Class creation failed\n");
        return PTR_ERR(dwnld_class);
    }

    /* struct device *
            device_create(const struct class *cls, struct device *parent, dev_t devt,
	        void *drvdata, const char *fmt, ...); */
    dwnld_device = device_create(dwnld_class, NULL, 0, NULL, "ti-buck-regulator-pmbus-iv");
    if (IS_ERR(dwnld_device)) {
        pr_err("[pmic-download] Device creation failed\n");
        /* void class_destroy(const struct class *cls); */
        class_destroy(dwnld_class);
        return PTR_ERR(dwnld_device);
    }

    /* int device_create_file(struct device *device,
		       const struct device_attribute *entry);
       void device_destroy(const struct class *cls, dev_t devt); */
    if (device_create_file(dwnld_device, &dev_attr_trigger)) {
        pr_err("[pmic-download] Trigger File creation Failed \n");
        device_destroy(dwnld_class, 0);
        class_destroy(dwnld_class);
        return -ENOMEM;
    }

    if (device_create_file(dwnld_device, &dev_attr_status)) {
        pr_err("[pmic-download] Status File creation Failed \n");
        device_remove_file(dwnld_device, &dev_attr_trigger);
        device_destroy(dwnld_class, 0);
        class_destroy(dwnld_class);
        return -ENOMEM;
    }
    
    if (device_create_file(dwnld_device, &dev_attr_progress)) {
        pr_err("[pmic-download] Progress File creation Failed \n");
        device_remove_file(dwnld_device, &dev_attr_trigger);
        device_remove_file(dwnld_device, &dev_attr_status);
        device_destroy(dwnld_class, 0);
        class_destroy(dwnld_class);
        return -ENOMEM;
    }

    pr_info("[pmic-download] sysfs files created \n");

    /*#define create_singlethread_workqueue(name)				\
	    alloc_ordered_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, name)*/
    dwnld_req = create_singlethread_workqueue("ti_buck_fw_dwnldr");
    if (!dwnld_req) {
        pr_err("[pmic-download] Workqueue creation failed\n");
        device_remove_file(dwnld_device, &dev_attr_trigger);
        device_remove_file(dwnld_device, &dev_attr_status);
        device_remove_file(dwnld_device, &dev_attr_progress);
        device_destroy(dwnld_class, 0);
        class_destroy(dwnld_class);
        return -ENOMEM;
    }

    INIT_DELAYED_WORK(&dwnld_work, dwnld_work_handler);
    pr_info("[pmic-download] work queued\n");

    return 0;  
}


static void __exit pmic_download_exit(void)
{
    i2c_del_driver(&driver_if);
    /* void device_remove_file(struct device *dev,
			const struct device_attribute *attr); */
    device_remove_file(dwnld_device, &dev_attr_trigger);
    device_remove_file(dwnld_device, &dev_attr_status);
    device_remove_file(dwnld_device, &dev_attr_progress);
    device_destroy(dwnld_class, 0);
    class_destroy(dwnld_class);
    /* bool cancel_delayed_work_sync(struct delayed_work *dwork); */
    cancel_delayed_work_sync(&dwnld_work);
    destroy_workqueue(dwnld_req);
    pr_info("[pmic-download] module unloaded\n");
}

module_init(pmic_download_init);
module_exit(pmic_download_exit);
