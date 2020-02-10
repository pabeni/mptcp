// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2020, Red Hat, Inc.
 */

#include <linux/inet.h>
#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/netns/generic.h>
#include <net/mptcp.h>
#include <net/genetlink.h>
#include <uapi/linux/mptcp.h>

#include "protocol.h"

static int pm_nl_pernet_id;

struct mptcp_pm_addr_entry {
	struct list_head	list;
	struct mptcp_addr_info	addr;
	struct rcu_head		rcu;
};

struct pm_nl_pernet {
	struct list_head	signal;
	struct list_head	local;
	spinlock_t		lock;
	unsigned		add_addr_signal_max;
	unsigned		add_addr_accept_max;
	unsigned		local_addr_max;;
};

#define MPTCP_PM_ADDR_MAX	8

static void local_address(const struct sock_common *skc,
			  struct mptcp_addr_info *addr)
{
	memset(addr, 0, sizeof(*addr));

	addr->family = skc->skc_family;
	if (addr->family == AF_INET)
		addr->addr.s_addr = skc->skc_rcv_saddr;
#if IS_ENABLED(CONFIG_IPV6)
	else if (addr->family == AF_INET6)
		addr->addr6 = skc->skc_v6_rcv_saddr;
#endif
}

static void remote_address(const struct sock_common *skc,
			   struct mptcp_addr_info *addr)
{
	memset(addr, 0, sizeof(*addr));

	addr->family = skc->skc_family;
	addr->port = skc->skc_dport;
	if (addr->family == AF_INET)
		addr->addr.s_addr = skc->skc_daddr;
#if IS_ENABLED(CONFIG_IPV6)
	else if (addr->family == AF_INET6)
		addr->addr6 = skc->skc_v6_daddr;
#endif
}

static bool lookup_subflow_by_saddr(const struct mptcp_sock *msk,
				   struct mptcp_addr_info *saddr)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_addr_info cur;
	struct sock_common *skc;

	list_for_each_entry(subflow, &msk->conn_list, node) {
		skc = (struct sock_common *)mptcp_subflow_tcp_sock(subflow);

		local_address(skc, &cur);
		if (!memcpy(&cur, saddr, sizeof(struct mptcp_addr_info)))
			return true;
	}

	return false;
}

static struct mptcp_pm_addr_entry *
pick_local_address(const struct pm_nl_pernet *pernet,
		   const struct mptcp_sock *msk)
{
	struct mptcp_pm_addr_entry *entry, *ret;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &pernet->local, list) {
		if (entry->addr.family == ((struct sock *)msk)->sk_family &&
		    !lookup_subflow_by_saddr(msk, &entry->addr)) {
			ret = entry;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

static struct mptcp_pm_addr_entry *
pick_signal_address(struct pm_nl_pernet *pernet, unsigned pos)
{
	struct mptcp_pm_addr_entry *entry, *ret = NULL;
	int i = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &pernet->local, list) {
		if (++i == pos) {
			ret = entry;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

static void mptcp_pm_create_subflow_or_signal(struct mptcp_sock *msk)
{
	unsigned addr_signaled, laddr_used, max;
	struct sock *sk = (struct sock *)msk;
	struct mptcp_pm_addr_entry *local;
	struct mptcp_addr_info remote;
	struct pm_nl_pernet *pernet;

	pernet = net_generic(sock_net((struct sock *)msk), pm_nl_pernet_id);

	lock_sock(sk);

	spin_lock_bh(&msk->pm.lock);
	laddr_used = READ_ONCE(msk->pm.local_addr_used);
	max = READ_ONCE(msk->pm.local_addr_max);

	/* check first if should create a new subflow */
	if (max && laddr_used < max) {
		remote_address((struct sock_common *)sk, &remote);

		local = pick_local_address(pernet, msk);
		if (local) {
			WRITE_ONCE(msk->pm.local_addr_used, laddr_used + 1);
			spin_unlock(&msk->pm.lock);
			__mptcp_subflow_connect(sk, &local->addr, &remote);
			release_sock(sk);
			return;
		}

		/* lookup failed, avoid fourther attemps later */
		WRITE_ONCE(msk->pm.local_addr_used, max);
	}

	/* check for announce */
	addr_signaled = READ_ONCE(msk->pm.add_addr_signaled);
	max = READ_ONCE(msk->pm.add_addr_signal_max);
	if (max && addr_signaled < max) {
		local = pick_signal_address(pernet, addr_signaled);

		if (local) {
			WRITE_ONCE(msk->pm.local_addr_used, laddr_used + 1);
			mptcp_pm_announce_addr(msk, &local->addr);
		} else {
			/* pick failed, avoid fourther attemps later */
			WRITE_ONCE(msk->pm.local_addr_used, max);
		}
	}
	spin_unlock_bh(&msk->pm.lock);
	release_sock(sk);
}

void mptcp_pm_nl_fully_established(struct mptcp_sock *msk)
{
	mptcp_pm_create_subflow_or_signal(msk);
}

void mptcp_pm_nl_subflow_established(struct mptcp_sock *msk)
{
	mptcp_pm_create_subflow_or_signal(msk);
}

void mptcp_pm_nl_add_addr(struct mptcp_sock *msk)
{
	struct sock *sk = (struct sock *)msk;
	struct mptcp_addr_info remote;
	struct mptcp_addr_info local;
	struct pm_nl_pernet *pernet;
	unsigned accepted;

	pernet = net_generic(sock_net((struct sock *)msk), pm_nl_pernet_id);

	spin_lock(&msk->pm.lock);
	accepted = READ_ONCE(msk->pm.add_addr_accepted);
	if (accepted >= READ_ONCE(msk->pm.add_addr_accept_max)) {
		spin_unlock(&msk->pm.lock);
		return;
	}

	/* connect to the specified remote address, using whatever
	 * local address the routing configuration will pick.
	 */
	remote = msk->pm.remote;
	memset(&local, 0, sizeof(local));
	local.family = remote.family;
	WRITE_ONCE(msk->pm.add_addr_accepted, accepted + 1);
	spin_unlock(&msk->pm.lock);

	lock_sock(sk);
	__mptcp_subflow_connect((struct sock *)msk, &local, &remote);
	release_sock(sk);
}

int mptcp_pm_nl_get_local_id(struct mptcp_sock *msk, struct sock_common *skc)
{
	struct mptcp_pm_addr_entry *entry;
	struct mptcp_addr_info skc_local;
	struct mptcp_addr_info msk_local;
	struct pm_nl_pernet *pernet;
	int ret = -1;

	if (WARN_ON_ONCE(!msk))
		return 0;

	local_address((struct sock_common *)msk, &msk_local);
	local_address((struct sock_common *)msk, &skc_local);
	if (!memcmp(&msk_local, &skc_local, sizeof(struct mptcp_addr_info)))
		return 0;

	pernet = net_generic(sock_net((struct sock *)msk), pm_nl_pernet_id);

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &pernet->local, list) {
		if (!memcmp(&entry->addr, &skc_local,
			     sizeof(struct mptcp_addr_info))) {
			ret = entry->addr.id;
			break;
		}
	}
	rcu_read_unlock();

	/* TODO: if not found add to local list, marking it as "DO NOT USE
	 for new subflow", up to MPTCP_PM_ADDR_MAX */
	return ret;
}

void mptcp_pm_nl_data_init(struct mptcp_sock *msk)
{
	struct pm_nl_pernet *pernet;

	pernet = net_generic(sock_net((struct sock *)msk), pm_nl_pernet_id);

	WRITE_ONCE(msk->pm.add_addr_signal_max, pernet->add_addr_signal_max);
	WRITE_ONCE(msk->pm.add_addr_accept_max, pernet->add_addr_accept_max);
	WRITE_ONCE(msk->pm.local_addr_max, pernet->local_addr_max);
}

#define MPTCP_PM_CMD_GRP_OFFSET	0

static const struct genl_multicast_group mptcp_pm_mcgrps[] = {
	[MPTCP_PM_CMD_GRP_OFFSET]	= { .name = MPTCP_PM_CMD_GRP_NAME, },
};

static const struct nla_policy mptcp_pm_addr_policy[MPTCP_PM_ADDR_ATTR_MAX + 1] = {
	[MPTCP_PM_ADDR_ATTR_FAMILY]	= { .type	= NLA_U16,	},
	[MPTCP_PM_ADDR_ATTR_ADDR4]	= { .type	= NLA_U32,	},
	[MPTCP_PM_ADDR_ATTR_ADDR6]	= { .type	= NLA_BINARY,
					    .len   = sizeof(struct in6_addr), },
};

static const struct nla_policy mptcp_pm_policy[MPTCP_PM_ATTR_MAX + 1] = {
	[MPTCP_PM_ATTR_ADDR_LIST]	=
			   NLA_POLICY_NESTED_ARRAY(mptcp_pm_addr_policy),
	[MPTCP_PM_ATTR_ADD_ADDR_MAX]	= { .type	= NLA_U32,	},
};

static int mptcp_pm_family_to_addr(int family)
{
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	if (family == AF_INET6)
		return MPTCP_PM_ADDR_ATTR_ADDR6;
#endif
	return MPTCP_PM_ADDR_ATTR_ADDR4;
}

static int mptcp_pm_parse_addr(struct nlattr *addr,
			       struct mptcp_addr_info *loc_addr,
			       struct genl_info *info)
{
	struct nlattr *tb[MPTCP_PM_ADDR_ATTR_MAX + 1];
	int err, addr_addr;

	/* no validation needed - was already done via nested policy */
	err = nla_parse_nested_deprecated(tb, MPTCP_PM_ADDR_ATTR_MAX, addr,
					  mptcp_pm_addr_policy, info->extack);
	if (err)
		return err;

	if (!tb[MPTCP_PM_ADDR_ATTR_FAMILY]) {
		NL_SET_ERR_MSG_ATTR(info->extack, addr,
				    "missing family");
		return -EINVAL;
	}

	loc_addr->family = nla_get_u16(tb[MPTCP_PM_ADDR_ATTR_FAMILY]);
	if (loc_addr->family != AF_INET
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	    && loc_addr->family != AF_INET6
#endif
	    ) {
		NL_SET_ERR_MSG_ATTR(info->extack, addr,
				    "unknown address family");
		return -EINVAL;
	}
	addr_addr = mptcp_pm_family_to_addr(loc_addr->family);
	if (!tb[addr_addr])
		NL_SET_ERR_MSG_ATTR(info->extack, addr,
				    "missing address data");

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	if (loc_addr->family == AF_INET6)
		loc_addr->addr6 = nla_get_in6_addr(tb[addr_addr]);
	else
#endif
		loc_addr->addr.s_addr = nla_get_in_addr(tb[addr_addr]);
	return 0;
}

static void __flush_list(struct list_head *head)
{
	while (!list_empty(head)) {
		struct mptcp_pm_addr_entry *cur = list_entry(head,
						     struct mptcp_pm_addr_entry,
						     list);

		head = head->next;
		list_del_rcu(&cur->list);
		kfree_rcu(cur, rcu);
	}
}

static int mptcp_pm_parse_addr_list(struct nlattr *addrs,
				    struct list_head *head,
				    struct genl_info *info,
				    bool ignore_port)
{
	struct mptcp_pm_addr_entry *loc_addr;
	int err, remaining, len;
	struct nlattr *addr;

	len = 0;
	nla_for_each_nested(addr, addrs, remaining) {
		loc_addr = kzalloc(sizeof(*loc_addr), GFP_KERNEL);
		if (!loc_addr) {
			NL_SET_ERR_MSG(info->extack, "can't allocate addr");
			err = -ENOMEM;
			goto fail;
		}

		err = mptcp_pm_parse_addr(addr, &loc_addr->addr, info);
		if (err)
			goto fail;

		if (ignore_port)
			loc_addr->addr.port = 0;

		list_add_tail(&loc_addr->list, head);
		if (++len >= MPTCP_PM_ADDR_MAX) {
			NL_SET_ERR_MSG(info->extack, "address list limit exceeded");
			err = -EINVAL;
			goto fail;
		}
	}
	return len;

fail:
	__flush_list(head);
	return err;
}

static struct pm_nl_pernet *genl_info_pm_nl(struct genl_info *info)
{
	return net_generic(genl_info_net(info), pm_nl_pernet_id);
}

static int mptcp_pm_nl_signal(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *addrs = info->attrs[MPTCP_PM_ATTR_ADDR_LIST];
	struct pm_nl_pernet *pernet = genl_info_pm_nl(info);
	struct list_head old_head;
	LIST_HEAD(head);
	int len;

	if (addrs) {
		len = mptcp_pm_parse_addr_list(addrs, &head, info, false);
		if (len < 0)
			return len;
	}

	spin_lock(&pernet->lock);
	pernet->add_addr_signal_max = len;
	old_head = pernet->signal;
	list_replace_rcu(&pernet->signal, &head);
	spin_unlock(&pernet->lock);

	__flush_list(&old_head);
	return 0;
}

static int mptcp_pm_nl_local(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *addrs = info->attrs[MPTCP_PM_ATTR_ADDR_LIST];
	struct pm_nl_pernet *pernet = genl_info_pm_nl(info);
	struct list_head old_head;
	LIST_HEAD(head);
	int len;

	if (addrs) {
		len = mptcp_pm_parse_addr_list(addrs, &head, info, true);
		if (len)
			return len;
	}

	spin_lock(&pernet->lock);
	pernet->local_addr_max = len;
	old_head = pernet->local;
	list_replace_rcu(&pernet->local, &head);
	spin_unlock(&pernet->lock);

	__flush_list(&old_head);
	return 0;
}

static int mptcp_pm_nl_add_addr_max(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attr = info->attrs[MPTCP_PM_ATTR_ADD_ADDR_MAX];
	struct pm_nl_pernet *pernet = genl_info_pm_nl(info);
	int limit;

	if (!attr) {
		NL_SET_ERR_MSG(info->extack, "missing announce accept limit");
		return -EINVAL;
	}

	limit = nla_get_u16(attr);
	if (limit > MPTCP_PM_ADDR_MAX) {
		NL_SET_ERR_MSG(info->extack, "announce accept limit greater than maximum");
		return -EINVAL;
	}

	WRITE_ONCE(pernet->add_addr_accept_max, limit);
	return 0;
}

static struct genl_ops mptcp_pm_ops[] = {
	{
		.cmd    = MPTCP_CMD_NS_SIGNAL,
		.doit   = mptcp_pm_nl_signal,
		.flags  = GENL_ADMIN_PERM,
	},
	{
		.cmd    = MPTCP_CMD_NS_LOCAL,
		.doit   = mptcp_pm_nl_local,
		.flags  = GENL_ADMIN_PERM,
	},
	{
		.cmd    = MPTCP_CMD_NS_ADD_ADDR_MAX,
		.doit   = mptcp_pm_nl_add_addr_max,
		.flags  = GENL_ADMIN_PERM,
	},
};

static struct genl_family mptcp_genl_family __ro_after_init = {
	.name		= MPTCP_PM_NAME,
	.version	= MPTCP_PM_VER,
	.maxattr	= MPTCP_PM_ATTR_MAX,
	.policy		= mptcp_pm_policy,
	.netnsok	= true,
	.module		= THIS_MODULE,
	.ops		= mptcp_pm_ops,
	.n_ops		= ARRAY_SIZE(mptcp_pm_ops),
	.mcgrps		= mptcp_pm_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(mptcp_pm_mcgrps),
};

static int __net_init pm_nl_init_net(struct net *net)
{
	struct pm_nl_pernet *pernet = net_generic(net, pm_nl_pernet_id);

	INIT_LIST_HEAD_RCU(&pernet->signal);
	INIT_LIST_HEAD_RCU(&pernet->local);
	pernet->add_addr_signal_max = 0;
	pernet->add_addr_accept_max = 0;
	pernet->local_addr_max = 0;
	spin_lock_init(&pernet->lock);
	return 0;
}

static void __net_exit pm_nl_exit_net(struct list_head *net_list)
{
	struct net *net;

	list_for_each_entry(net, net_list, exit_list) {
		struct pm_nl_pernet *pernet = net_generic(net, pm_nl_pernet_id);

		/* net is removed from namespace list, can't race with
		 * other modifiers
		 */
		__flush_list(&pernet->signal);
		__flush_list(&pernet->local);
	}
}

static struct pernet_operations mptcp_pm_pernet_ops = {
	.init = pm_nl_init_net,
	.exit_batch = pm_nl_exit_net,
	.id = &pm_nl_pernet_id,
	.size = sizeof(struct pm_nl_pernet),
};

void mptcp_pm_nl_init(void)
{
	if (register_pernet_subsys(&mptcp_pm_pernet_ops) < 0)
		panic("Failed to register MPTCP PM pernet subsystem.\n");

	if (genl_register_family(&mptcp_genl_family))
		panic("Failed to register MPTCP PM netlink family");
}
