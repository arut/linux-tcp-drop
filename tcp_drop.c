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
#include <net/inet6_hashtables.h>
#include <net/inet_timewait_sock.h>

#define TCP_DROP_PROC    "tcp_drop"
#define TCP_DROP_MAX_ARG  256

static void
tcp_drop_split(const char *s, int *len, __be16 *port)
{
	for(__be16 scale = 1; *len > 0; scale *= 10) {
		char c = *(s + --*len);
		if (c == ':' || c < '0' || c > '9')
			return;
		*port += (c - '0') * scale;
	}
}

static int 
tcp_drop(const char *s, int len)
{
	char                      *d;
	__be16                     sport = 0, dport = 0;
	int                        slen = 0, dlen = 0;
	struct sock               *sk = NULL;
	union {
		__be32                 v4;
		struct in6_addr        v6;
	} saddr, daddr;

	for(d = s; 
		slen < len && !isspace(*d); 
		++d, ++slen);

	for(dlen = slen;
		dlen < len && isspace(*d); 
		++d, ++dlen);

	dlen = len - dlen;

	tcp_drop_split(s, &slen, &sport);
	tcp_drop_split(d, &dlen, &dport);

	if (in4_pton(s, slen, &saddr.v4, '\0', NULL)
		&& in4_pton(d, dlen, &daddr.v4, '\0', NULL))
	{
		sk = inet_lookup(
#ifdef CONFIG_NET_NS
				&init_net, 
#endif
				&tcp_hashinfo,
				daddr.v4, htons(dport), 
				saddr.v4, htons(sport), 
				0);

	} else if (in6_pton(s, slen, &saddr.v6, '\0', NULL)
		&& in6_pton(d, dlen, &daddr.v6, '\0', NULL))
	{
		sk = inet6_lookup(
#ifdef CONFIG_NET_NS
				&init_net, 
#endif
				&tcp_hashinfo,
				&daddr.v6, htons(dport), 
				&saddr.v6, htons(sport), 
				0);
	}

	if (!sk) {
		printk(KERN_INFO "tcp_drop: not found");
		return -1;
	}

	printk(KERN_INFO "tcp_drop: dropping %.*s:%d %.*s:%d\n", 
			slen, s, sport, dlen, d, dport);

	if (sk->sk_state == TCP_TIME_WAIT) {
		inet_twsk_deschedule(inet_twsk(tw), &tcp_death_row);
		inet_twsk_put(inet_twsk(tw));
	} else {
		tcp_done(sk);
		sock_put(sk);
	}

	return 0;
}

static int 
tcp_drop_write_proc(struct file *file, const char __user *buffer,
	unsigned long count, void *data)
{
	ssize_t ret = -EFAULT;
	char   *kbuffer;

	if (!count || count > TCP_DROP_MAX_ARG)
		return -EOVERFLOW;

	kbuffer = (char *)kmalloc(count, GFP_KERNEL);
	if (!kbuffer)
		return ret;

	if (!copy_from_user(kbuffer, buffer, count)
		 && !tcp_drop(kbuffer, count))
	{
		ret = count;
	}

	kfree(kbuffer);
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
