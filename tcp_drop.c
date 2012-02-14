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

#define TCP_DROP_PROC "tcp_drop"

static int
tcp_drop_sock(struct sock *sk)
{
	struct inet_timewait_sock *tw;

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
tcp_drop_v4(const __be32 saddr, __be16 sport,
            const __be32 daddr, __be16 dport)
{
	struct sock *sk;

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

	return tcp_drop_sock(sk);
}

static int 
tcp_drop_v6(const struct in6_addr *saddr, __be16 sport,
            const struct in6_addr *daddr, __be16 dport)
{
	struct sock *sk;

	sk = inet6_lookup(
#ifdef CONFIG_NET_NS
			&init_net, 
#endif
			&tcp_hashinfo,
			daddr, htons(dport), 
			saddr, htons(sport), 
			0);

	return tcp_drop_sock(sk);
}

static int 
parse_port(char *s, __be16 *port)
{
	char           *p;
	unsigned long   res;

	p = strrchr(s, ':');

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

	return 0;
}

static int 
tcp_drop_a(char *s)
{
	char           *d;
	__be16          sport,  dport;
	__be32          saddr4, daddr4;
	struct in6_addr saddr6, daddr6;

	/* split args */
	if (!s) {
		printk(KERN_ERR "tcp_drop: null drop string\n");
		return -1;
	}

	for(d = s; *d && !isspace(*d); ++d);

	if (!*d) {
		printk(KERN_ERR "tcp_drop: need both ends to drop\n");
		return -1;
	}

	*d = 0;

	for(++d; *d && isspace(*d); ++d);

	/* parse ports */
	if (parse_port(s, &sport))
		return -1;

	if (parse_port(d, &dport))
		return -1;

	/* try ipv4 on both */
	if (in4_pton(s, -1, &saddr4, '\0', NULL)) {

		if (!in4_pton(d, -1, &daddr4, '\0', NULL))
			return -1;

#ifdef TCP_DROP_DEBUG
		printk(KERN_DEBUG "tcp_drop: ipv4 addr %08X:%04X - %08X:%04X\n", 
			saddr4, sport, daddr4, dport);
#endif

		return tcp_drop_v4(saddr4, sport, daddr4, dport);
	}

	/* try ipv6 on both */
	if (in6_pton(s, -1, &saddr6, '\0', NULL)) {

		if (!in6_pton(d, -1, &daddr6, '\0', NULL))
			return -1;

#ifdef TCP_DROP_DEBUG
	/*	printk(KERN_DEBUG "tcp_drop: ipv6 addr %08X:%04X\n", 
			*addr, *port);*/
#endif

		return tcp_drop_v6(&saddr6, sport, &daddr6, dport);
	}

	return -1;
}

static int 
tcp_drop_write_proc(struct file *file, const char __user *buffer,
	unsigned long count, void *data)
{
	ssize_t ret = -ENOMEM;
	char   *page;

	if (count > PAGE_SIZE)
		return -EOVERFLOW;

	/* TODO: improve allocation */
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
