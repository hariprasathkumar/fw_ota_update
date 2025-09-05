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

MODULE_LICENSE("GPL");        
MODULE_AUTHOR("Hari Prasath Kumar @ hari-kumar@ti.com");   
MODULE_DESCRIPTION("TI PMIC FW Download kernel module");
MODULE_VERSION("0.1");        


struct class *dwnld_class = NULL;
struct device *dwnld_device = NULL;
struct workqueue_struct *dwnld_req = NULL;
struct delayed_work dwnld_work = {0};
static atomic_t dwnld_in_progress = ATOMIC_INIT(0);
static atomic_t current_byte = ATOMIC_INIT(0);
static atomic_t total_bytes = ATOMIC_INIT(0);

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

static void dwnld_work_process(const struct firmware *f) 
{
    size_t blocks = f->size / 32;
    size_t rem = f->size - (blocks*32);
    char *d = (char *)f->data;
    atomic_set(&current_byte, 0);
    atomic_set(&total_bytes, f->size);
    while (blocks--) {
        char buf[33];
        for (u32 b = 0; b < 32; b++) {
            buf[b] = d[atomic_read(&current_byte)];
            atomic_inc(&current_byte);
        }
        buf[32] = '\0';
        pr_info("[pmic-download] block %d = %s\n", blocks, buf);
    }

    size_t rest = atomic_read(&current_byte) + rem;
    for ( ; atomic_read(&current_byte) < rest; atomic_inc(&current_byte)) {
        u32 idx = atomic_read(&current_byte);
        pr_info("[pmic-download] byte %d = %c \n", idx, *(d + idx));
    }
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
    if (ret < 0) {
        pr_err("[pmic-download] fw loading failed error code : %d\n", ret);
        atomic_set(&dwnld_in_progress, 0);
        atomic_set(&current_byte, 0);
        atomic_set(&total_bytes, 0);
        return;
    }

    ret = request_firmware(&key, "ti_buck_fw_key.bin", dwnld_device);
    if (ret < 0) {
        pr_err("[pmic-download] key loading failed error code : %d\n", ret);
        release_firmware(fw);
        atomic_set(&dwnld_in_progress, 0);
        atomic_set(&current_byte, 0);
        atomic_set(&total_bytes, 0);
        return;
    }

    pr_info("[pmic-download] processing key \n");
    dwnld_work_process(key);

    pr_info("[pmic-download] processing fw \n");
    dwnld_work_process(fw);

    pr_info("[pmic-download] fw_work_handler completed\n"); 
    
    /* void release_firmware(const struct firmware *fw); */
    release_firmware(fw);
    release_firmware(key);
    atomic_set(&dwnld_in_progress, 0);
    atomic_set(&current_byte, 0);
    atomic_set(&total_bytes, 0);
}
static DEVICE_ATTR_WO(trigger);
static DEVICE_ATTR_RO(status);
static DEVICE_ATTR_RO(progress);

static int __init pmic_download_init(void)
{
    pr_info("[pmic-download] module loaded\n");
    
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
        device_destroy(dwnld_device, 0);
        class_destroy(dwnld_class);
        return -ENOMEM;
    }

    if (device_create_file(dwnld_device, &dev_attr_status)) {
        pr_err("[pmic-download] Status File creation Failed \n");
        device_remove_file(dwnld_device, &dev_attr_trigger);
        device_destroy(dwnld_device, 0);
        class_destroy(dwnld_class);
        return -ENOMEM;
    }
    
    if (device_create_file(dwnld_device, &dev_attr_progress)) {
        pr_err("[pmic-download] Progress File creation Failed \n");
        device_remove_file(dwnld_device, &dev_attr_trigger);
        device_remove_file(dwnld_device, &dev_attr_status);
        device_destroy(dwnld_device, 0);
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
        device_destroy(dwnld_device, 0);
        class_destroy(dwnld_class);
        return -ENOMEM;
    }

    INIT_DELAYED_WORK(&dwnld_work, dwnld_work_handler);
    pr_info("[pmic-download] work queued\n");

    return 0;  
}


static void __exit pmic_download_exit(void)
{
    /* void device_remove_file(struct device *dev,
			const struct device_attribute *attr); */
    device_remove_file(dwnld_device, &dev_attr_trigger);
    device_remove_file(dwnld_device, &dev_attr_status);
    device_remove_file(dwnld_device, &dev_attr_progress);
    device_destroy(dwnld_device, 0);
    class_destroy(dwnld_class);
    /* bool cancel_delayed_work_sync(struct delayed_work *dwork); */
    cancel_delayed_work_sync(&dwnld_work);
    destroy_workqueue(dwnld_req);
    pr_info("[pmic-download] module unloaded\n");
}

module_init(pmic_download_init);
module_exit(pmic_download_exit);
