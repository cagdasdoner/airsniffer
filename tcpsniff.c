#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/cdev.h>
#include<linux/skbuff.h>
#include<linux/netdevice.h>
#include <linux/tcp.h>
#include <linux/ip.h>

MODULE_LICENSE("GPL");

#define DEVICE_NAME "sniffa"
#define CLASS_NAME  "char"

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define BUFSIZ 1024

static int major_no;
static int sniffa_open(struct inode *, struct file *);
static int sniffa_release(struct inode *, struct file *);
static ssize_t sniffa_read(struct file *, char *, size_t, loff_t *);
static ssize_t sniffa_write(struct file *filp, const char *buffer, size_t len, loff_t * off);
static unsigned int sniffa_poll(struct file *filp, poll_table *wait);
static int sniffa(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

static char sniff_data[BUFSIZ] = {0};
static char sniff_filter[BUFSIZ] = {0};
static struct class* c_net  = NULL;
static struct device* d_net = NULL;
wait_queue_head_t waitqueue;
int data_ready = 0;
int pack_cnt;

static struct file_operations fops = {
	.read = sniffa_read,
	.write = sniffa_write,
	.open = sniffa_open,
	.release = sniffa_release,
	.poll = sniffa_poll
};

static struct packet_type pt = { 
	.type = __constant_htons(ETH_P_IP),
	.func = sniffa,
};

static int sniffa(struct sk_buff *skb,
		struct net_device *dev, 
		struct packet_type *pt,
		struct net_device *orig_dev){

	struct iphdr *network_header;
	struct tcphdr *tcp_header;
	int sport, dport;

	network_header = (struct iphdr *)skb_network_header(skb);
	if (network_header->protocol == IPPROTO_TCP){
		printk("TCP Packet number %d\n", pack_cnt);
		tcp_header = (struct tcphdr *)skb_transport_header(skb); 
		sport = ntohs((unsigned short int) tcp_header->source);
		dport = ntohs((unsigned short int) tcp_header->dest);
		memset(sniff_data, 0, BUFSIZ);
		/* TODO: Grab data for user space. */
		snprintf(sniff_data, BUFSIZ, "%s, %d, %d, %d, %d.%d.%d.%d, %d.%d.%d.%d", skb->dev->name, skb->len, sport, dport, 
								NIPQUAD(network_header->saddr), NIPQUAD(network_header->daddr));
		data_ready = 1;
		wake_up_interruptible(&waitqueue);
		pack_cnt++;
	}
	kfree_skb(skb);

	return 0;
}

static int sniffa_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "sniffer open.\n");

	dev_add_pack(&pt);

	return 0;
}

static int sniffa_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "sniffa release.\n");

	dev_remove_pack(&pt);

	return 0;
}

static ssize_t sniffa_read(struct file *filp, char *buffer, size_t length, loff_t * offset)
{
	int ret = 0;
	if (copy_to_user(buffer, sniff_data, length) != 0) {
		printk(KERN_ALERT "sniffa failed to copy.\n");
		return -EFAULT;
	}
	ret = strlen(sniff_data);
	data_ready = 0;

	return ret;
}

/* TODO: Might be used to filter packages based on proto, source, port etc. */
static ssize_t sniffa_write(struct file *filp, const char *buffer, size_t len, loff_t * off)
{
	printk(KERN_INFO "sniffa write.\n");
	if (copy_from_user(sniff_filter, buffer, len) != 0) {
		printk(KERN_ALERT "sniffa failed to copy.\n");
		return -EFAULT;
	}

	return len;
}

static unsigned int sniffa_poll(struct file *filp, poll_table *wait)
{
	unsigned int ret = 0;
	printk(KERN_INFO "sniffer poll\n");
	poll_wait(filp, &waitqueue, wait);

	if (data_ready) {
		ret |= POLLIN | POLLRDNORM;
	}

	return ret;		
}

static int __init sniffa_init(void){
	printk(KERN_INFO "sniffa_init.\n");
	
	if(!(major_no = register_chrdev(0, DEVICE_NAME, &fops))) {
		return major_no;
	}

	printk(KERN_INFO "sniffa attach as %d.\n", major_no);

	/* Attach descriptor under /dev instead of mknod. */
	c_net = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(c_net)){
		unregister_chrdev(major_no, DEVICE_NAME);
		printk(KERN_ALERT "Failed to register device class.\n");
		return PTR_ERR(c_net);
	}
	d_net = device_create(c_net, NULL, MKDEV(major_no, 0), NULL, DEVICE_NAME);
	if (IS_ERR(d_net)){
		class_destroy(c_net);
		unregister_chrdev(major_no, DEVICE_NAME);
		printk(KERN_ALERT "Failed to create the device.\n");
		return PTR_ERR(d_net);
	}
	init_waitqueue_head(&waitqueue);

	return 0;
}

static void __exit sniffa_exit(void){
	printk(KERN_INFO "sniffa_exit.\n");
	dev_remove_pack(&pt);
	device_destroy(c_net, MKDEV(major_no, 0));
	class_unregister(c_net);
	class_destroy(c_net);
	unregister_chrdev(major_no, DEVICE_NAME);
}

module_init(sniffa_init);
module_exit(sniffa_exit);