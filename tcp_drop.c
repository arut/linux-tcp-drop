/*
 * Linux implementation of TCPDROP 
 *
 * (C) 2012 Roman Arutyunyan <arut@qip.ru>
 *
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <linux/ctype.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/module.h>

#ifdef CONFIG_NET_NS
#include <net/net_namespace.h>
#endif

#include <net/ip.h>
#include <net/tcp.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>

#define TCP_DROP_PROC "tcp_drop"

static int 
tcp_drop(const __be32 saddr, __be16 sport,
         const __be32 daddr, __be16 dport)
{
	struct sock        *sk;
	struct inet_timewait_sock *tw;

#ifdef TCP_DROP_DEBUG
	printk(KERN_DEBUG "tcp_drop: drop %08X:%04X %08X:%04X\n", 
			saddr, sport, daddr, dport);
#endif

	sk = inet_lookup(
#ifdef CONFIG_NET_NS
			&init_net, 
#endif
			&tcp_hashinfo,
			daddr, htons(dport), 
			saddr, htons(sport), 
			0);

	if (!sk) {
#ifdef TCP_DROP_DEBUG
		printk(KERN_DEBUG "tcp_drop: not found");
#endif
		return -1;
	}

	if (sk->sk_state == TCP_TIME_WAIT) {

		/* this is timewait socket; deschedule it right now */

#ifdef TCP_DROP_DEBUG
		printk(KERN_DEBUG "tcp_drop: dropping timewait socket\n");
#endif

		tw = inet_twsk(sk);
		inet_twsk_deschedule(tw, &tcp_death_row);
		inet_twsk_put(tw);

	} else {

#ifdef TCP_DROP_DEBUG
		printk(KERN_DEBUG "tcp_drop: dropping socket\n");
#endif

		tcp_done(sk);
		sock_put(sk);
	}

	return 0;
}

static int 
parse_addr(char *s, __be32 *addr, __be16 *port)
{
	char         *p;
	unsigned long res;

	p = strchr(s, ':');

	if (!p) {
		printk(KERN_ERR "tcp_drop: format error\n");
		return -1;
	}

	*p++ = 0;

	if (strict_strtoul(p, 10, &res) < 0) {
		printk(KERN_ERR "tcp_drop: bad format\n");
		return -1;
	}

	*port = (__be16)res;

	*addr = in_aton(s);

#ifdef TCP_DROP_DEBUG
	printk(KERN_DEBUG "tcp_drop: addr %08X:%04X\n", 
			*addr, *port);
#endif

	return 0;
}

static int 
tcp_drop_a(char *s)
{
	char      *p;
	__be32     saddr, daddr;
	__be16     sport, dport;

	if (!s) {
		printk(KERN_ERR "tcp_drop: null drop string\n");
		return -1;
	}

	for(p = s; *p && !isspace(*p); ++p);

	if (!*p) {
		printk(KERN_ERR "tcp_drop: need both ends to drop\n");
		return -1;
	}

	*p = 0;

	for(++p; *p && isspace(*p); ++p);

	if (parse_addr(s, &saddr, &sport)
	    || parse_addr(p, &daddr, &dport))
	{
		printk(KERN_ERR "tcp_drop: error parsing addresses\n");
		return -1;
	}

	return tcp_drop(saddr, sport, daddr, dport);
}

static int 
tcp_drop_write_proc(struct file *file, const char __user *buffer,
	unsigned long count, void *data)
{
	ssize_t ret = -ENOMEM;
	char   *page;

	if (count > PAGE_SIZE)
		return -EOVERFLOW;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (page) {
		ret = -EFAULT;
		if (copy_from_user(page, buffer, count))
			goto out;

		page[count] = 0;

		if (tcp_drop_a(page))
			ret = -EFAULT;

		ret = count;
	}
out:
	free_page((unsigned long)page);
	return ret;
}

static int __init 
tcp_drop_init(void)
{
	struct proc_dir_entry *res;

	printk(KERN_DEBUG "tcp_drop: loading\n");

	res = create_proc_entry(TCP_DROP_PROC, S_IWUSR | S_IWGRP, 
#ifdef CONFIG_NET_NS
		init_net.
#endif
		proc_net);

	if (!res) {
		printk(KERN_ERR "tcp_drop: unable to register proc file\n");
		return -ENOMEM;
	}
	
	res->write_proc = tcp_drop_write_proc;

	return 0;
}

module_init(tcp_drop_init);

static void __exit 
tcp_drop_exit(void)
{
	printk(KERN_DEBUG "tcp_drop: unloading\n");

	remove_proc_entry(TCP_DROP_PROC, 
#ifdef CONFIG_NET_NS
		init_net.
#endif
		proc_net);
}

module_exit(tcp_drop_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roman Arutyunyan <arut@qip.ru>");
MODULE_DESCRIPTION("Tcpdrop: runtime socket dropping");
MODULE_VERSION("0.0.1");
