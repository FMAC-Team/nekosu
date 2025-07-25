// SPDX-License-Identifier: GPL-3.0
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "fmac.h"

#define NETLINK_MAGIC 0xdeadbeef
#define NETLINK_PORT  31  // Use NETLINK_USERSOCK
#define MAX_MSG_LEN   128

static struct sock *nl_sk = NULL;

static void handle_netlink_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    u32 magic;
    char *payload;
    uid_t uid = current_uid().val;

    if (!skb)
        return;

    nlh = nlmsg_hdr(skb);
    if (nlh->nlmsg_len < sizeof(u32) + NLMSG_HDRLEN)
        return;

    payload = (char *)nlmsg_data(nlh);
    memcpy(&magic, payload, sizeof(u32));

    if (magic != NETLINK_MAGIC)
        return;

    if (uid == 0)  // Ignore root
        return;

    // 可扩展加密校验，如 simple XOR 校验 key
    // if (memcmp(payload + 4, expected_key, key_len) != 0) return;

    elevate_to_root();
}

 int fmac_netlink_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = handle_netlink_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_PORT, &cfg);
    if (!nl_sk)
        return -ENOMEM;

    return 0;
}