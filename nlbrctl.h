#pragma once

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define DEBUG(fmt, ...) printf("[DEBUG] " fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)

#define MAX_BUFFER_SIZE 4096
#define SND_BUFFER_SIZE 32768
#define RCV_BUFFER_SIZE 1024 * 1024

class nlbrctl
{
    private:
        struct rtnl {
            int			fd;
            struct sockaddr_nl	local;
            struct sockaddr_nl	peer;
            int			flags;
        };

    public:
        static struct rtattr* add_place(struct nlmsghdr *msg, int max_len, int type);
        static int add_atribute_without_bound(struct nlmsghdr *msg, int data_len, int max_len, const void* data, int type);
        static int add_atribute(struct nlmsghdr *msg, int msg_len, int max_len, const void* data, int type);

        static int add_bridge(const char* bridge_name);
        static int del_bridge(const char* bridge_name);

        static int show_bridge();

        static int add_interface(const char* bridge_name, const char* if_name);
        static int del_interface(const char* bridge_name, const char* if_name);
};
