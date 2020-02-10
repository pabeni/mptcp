// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Intel Corporation.
 */
#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

static struct workqueue_struct *pm_wq;

/* path manager command handlers */

int mptcp_pm_announce_addr(struct mptcp_sock *msk,
			   const struct mptcp_addr_info *addr)
{
	pr_debug("msk=%p, local_id=%d", msk, addr->id);

	msk->pm.local = *addr;
	WRITE_ONCE(msk->pm.addr_signal, true);
	return 0;
}

int mptcp_pm_remove_addr(struct mptcp_sock *msk, u8 local_id)
{
	return -ENOTSUPP;
}

int mptcp_pm_remove_subflow(struct mptcp_sock *msk, u8 remote_id)
{
	return -ENOTSUPP;
}

/* path manager event handlers */

void mptcp_pm_new_connection(struct mptcp_sock *msk, int server_side)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p, token=%u side=%d", msk, msk->token, server_side);

	WRITE_ONCE(pm->server_side, server_side);
}

static bool mptcp_pm_work_pending(const struct mptcp_pm_data *pm)
{
	return (READ_ONCE(pm->local_addr_used) <
		READ_ONCE(pm->local_addr_max)) ||
	       (READ_ONCE(pm->add_addr_signaled) <
		READ_ONCE(pm->add_addr_signal_max));
}

static bool mptcp_pm_schedule_work(struct mptcp_sock *msk,
				   enum mptcp_pm_status new_status)
{
	if (msk->pm.status != MPTCP_PM_IDLE)
		return false;

	if (queue_work(pm_wq, &msk->pm.subflow_work)) {
		msk->pm.status = new_status;
		sock_hold((struct sock *)msk);
		return true;
	}
	return false;
}

void mptcp_pm_fully_established(struct mptcp_sock *msk)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p", msk);

	/* try to avoid acquiring the lock below */
	if (READ_ONCE(pm->fully_established) || !mptcp_pm_work_pending(pm))
		return;

	spin_lock_bh(&pm->lock);
	if (READ_ONCE(pm->fully_established))
		goto out_unlock;

	if (mptcp_pm_schedule_work(msk, MPTCP_PM_ESTABLISHED))
		WRITE_ONCE(pm->fully_established, true);

out_unlock:
	spin_unlock_bh(&pm->lock);
}

void mptcp_pm_connection_closed(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_subflow_established(struct mptcp_sock *msk,
				  struct mptcp_subflow_context *subflow)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p", msk);

	if (!mptcp_pm_work_pending(pm))
		return;

	spin_lock_bh(&pm->lock);

	if (mptcp_pm_work_pending(pm))
		mptcp_pm_schedule_work(msk, MPTCP_PM_SUBFLOW_ESTABLISHED);

	spin_unlock_bh(&pm->lock);
}

void mptcp_pm_subflow_closed(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_add_addr(struct mptcp_sock *msk,
		       const struct mptcp_addr_info *addr)
{
	struct mptcp_pm_data *pm = &msk->pm;
	unsigned max, cur;

	pr_debug("msk=%p, remote_id=%d", msk, addr->id);

	/* avoid acquiring the lock if there is no room for fouther addresses */
	if (READ_ONCE(pm->add_addr_accepted) >=
	    READ_ONCE(pm->add_addr_accept_max))
		return;

	spin_lock_bh(&pm->lock);

	/* be sure there is something to signal re-checking under PM lock */
	max = READ_ONCE(pm->add_addr_accept_max);
	cur = READ_ONCE(pm->add_addr_accepted);
	if (cur >= max)
		goto unlock;

	if (mptcp_pm_schedule_work(msk, MPTCP_PM_ADD_ADDR)) {
		WRITE_ONCE(pm->add_addr_accepted, cur + 1);
		pm->remote = *addr;
	}

unlock:
	spin_unlock_bh(&pm->lock);
}

/* path manager helpers */

int mptcp_pm_addr_signal(struct mptcp_sock *msk, unsigned int remaining,
			 struct mptcp_addr_info *saddr)
{
	struct mptcp_addr_info addr;
	int ret = -EINVAL;

	spin_lock_bh(&msk->pm.lock);

	/* double check after the lock is acquired */
	if (!mptcp_pm_should_signal(msk))
		goto out_unlock;

	/* load real data */
	memset(&addr, 0, sizeof(addr));

	if (remaining < mptcp_add_addr_len(saddr->family))
		goto out_unlock;

	WRITE_ONCE(msk->pm.addr_signal, false);
	ret = 0;

out_unlock:
	spin_unlock_bh(&msk->pm.lock);
	return ret;
}

int mptcp_pm_get_local_id(struct mptcp_sock *msk, struct sock_common *skc)
{
	return mptcp_pm_nl_get_local_id(msk, skc);
}

static void pm_worker(struct work_struct *work)
{
	struct mptcp_pm_data *pm = container_of(work, struct mptcp_pm_data,
						subflow_work);
	struct mptcp_sock *msk = container_of(pm, struct mptcp_sock, pm);
	struct sock *sk = (struct sock *)msk;

	switch (pm->status) {
	case MPTCP_PM_ADD_ADDR:
		mptcp_pm_nl_add_addr(msk);
		break;

	case MPTCP_PM_ESTABLISHED:
		mptcp_pm_nl_fully_established(msk);
		break;

	case MPTCP_PM_SUBFLOW_ESTABLISHED:
		mptcp_pm_nl_subflow_established(msk);
		break;

	default:
		break;
	}

	sock_put(sk);
}

void mptcp_pm_data_init(struct mptcp_sock *msk)
{
	WRITE_ONCE(msk->pm.add_addr_signaled, 0);
	WRITE_ONCE(msk->pm.add_addr_accepted, 0);
	WRITE_ONCE(msk->pm.local_addr_used, 0);
	msk->pm.fully_established = false;
	msk->pm.status = MPTCP_PM_IDLE;

	spin_lock_init(&msk->pm.lock);
	INIT_WORK(&msk->pm.subflow_work, pm_worker);

	mptcp_pm_nl_data_init(msk);
}

void mptcp_pm_init(void)
{
	pm_wq = alloc_workqueue("pm_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 8);
	if (!pm_wq)
		panic("Failed to allocate workqueue");

	mptcp_pm_nl_init();
}
