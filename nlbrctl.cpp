#include "nlbrctl.h"

int nlbrctl::add_atribute_without_bound(struct nlmsghdr *msg, int data_len, int max_len, const void* data, int type) {
    int len = RTA_LENGTH(data_len);
	struct rtattr *rta;

	if (NLMSG_ALIGN(msg->nlmsg_len) + RTA_ALIGN(len) > max_len) {
		return -1;
	}
	rta = NLMSG_TAIL(msg);
	rta->rta_type = type;
	rta->rta_len = len;
	if (data_len)
		memcpy(RTA_DATA(rta), data, data_len);
	msg->nlmsg_len = NLMSG_ALIGN(msg->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

struct rtattr* nlbrctl::add_place(struct nlmsghdr *msg, int max_len, int type) {
    // bounding a nest for attribute
    struct rtattr *place = NLMSG_TAIL(msg);

    nlbrctl::add_atribute_without_bound(msg, 0, max_len, NULL, type);

    return place;
}

int add_place_end(struct nlmsghdr* msg, struct rtattr* n) {
    n->rta_len = (char *)NLMSG_TAIL(msg) - (char *)n;
	return msg->nlmsg_len;
}

int nlbrctl::add_atribute(struct nlmsghdr *msg, int msg_len, int max_len, const void* data, int type) {
    // bounding a nest for attribute
    struct rtattr *place = NLMSG_TAIL(msg);

    int len = RTA_LENGTH(msg_len);
	struct rtattr *rta;

	if (NLMSG_ALIGN(msg->nlmsg_len) + RTA_ALIGN(msg_len) > max_len) {
		return msg->nlmsg_len;
	}

	rta = NLMSG_TAIL(msg);
	rta->rta_type = type;
	rta->rta_len = len;
	if (msg_len)
		memcpy(RTA_DATA(rta), data, msg_len);
	msg->nlmsg_len = NLMSG_ALIGN(msg->nlmsg_len) + RTA_ALIGN(len);

    place->rta_len = (char *)NLMSG_TAIL(msg) - (char *)place;
	return msg->nlmsg_len;
}

int nlbrctl::add_bridge(const char* bridge_name) {
    struct rtnl     rthandle;
    socklen_t       addr_len;
    struct iovec    iov;
    
    struct {
        struct sockaddr_nl     nladdr                   = { 0 };
        struct nlmsghdr        header                   = { 0 };
        struct ifinfomsg       if_info                  = { 0 };
        struct msghdr          body                     = { 0 };
        struct nlattr          nla                      = { 0 };
        char                   buf[MAX_BUFFER_SIZE];
    } msg;

    // reset struct
	memset(&rthandle,       0, sizeof(rthandle));
    memset(&rthandle.local, 0, sizeof(rthandle.local));
    memset(&rthandle.peer,  0, sizeof(rthandle.peer));

    rthandle.fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (rthandle.fd < 0) {
        ERROR("failed to create socket: %d\n", errno);
        close(rthandle.fd);
        return -1; 
    }

    int sndbuf = SND_BUFFER_SIZE;
    if (setsockopt(rthandle.fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        ERROR("failed to set send buffer size: %d", errno);
		close(rthandle.fd);
        return -1; 
	}

    int rcvbuf = RCV_BUFFER_SIZE;
    if (setsockopt(rthandle.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        ERROR("failed to set receive buffer size: %d\n", errno);
        close(rthandle.fd);
        return -1; 
	}

    int ext_dummy = true;
    if (setsockopt(rthandle.fd, SOL_NETLINK, NETLINK_EXT_ACK, &ext_dummy, sizeof(ext_dummy)) < 0) {
        ERROR("failed to set extended ack report: %d\n", errno);
        close(rthandle.fd);
        return -1; 
	}

    // setting for bind netlink socket
    rthandle.local.nl_family = AF_NETLINK;
    rthandle.local.nl_groups = 0;

    if (bind(rthandle.fd, (struct sockaddr *)&rthandle.local, sizeof(rthandle.local)) < 0) {
		ERROR("failed to bind socket: %d\n", errno);
        close(rthandle.fd);
        return -1;      
	}

    addr_len = sizeof(rthandle.local);
    if (getsockname(rthandle.fd, (struct sockaddr *)&rthandle.local, &addr_len) < 0) {
		ERROR("failed to getsockname: %d\n", errno);
		close(rthandle.fd);
        return -1; 
	}
	if (addr_len != sizeof(rthandle.local)) {
		ERROR("addr_len is wrong: %d\n", errno);
		close(rthandle.fd);
        return -1; 
	}
	if (rthandle.local.nl_family != AF_NETLINK) {
		ERROR("wrong socket family: %d\n", rthandle.local.nl_family);
		close(rthandle.fd);
        return -1; 
	}

    int chk_dummy = true;
    if (setsockopt(rthandle.fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &chk_dummy, sizeof(chk_dummy)) < 0) {
        ERROR("failed to set netlink input checking: %d\n", errno);
        close(rthandle.fd);
        return -1; 
	}

    // forming request message
    msg.header.nlmsg_len    = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    msg.header.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    msg.header.nlmsg_type   = RTM_NEWLINK;
    msg.header.nlmsg_pid    = 0;

    msg.if_info.ifi_family  = AF_UNSPEC;
    msg.if_info.ifi_type    = ARPHRD_NETROM;
    msg.if_info.ifi_index   = 0; // zero index for new link
    msg.if_info.ifi_flags   = 0;
    msg.if_info.ifi_change  = 0;
    
    // strace wrong decompile that code, and print wrong packet body :/
    struct rtattr* ifname_place = nlbrctl::add_place(&msg.header, sizeof(msg), IFLA_IFNAME);
    nlbrctl::add_atribute_without_bound(&msg.header, strlen(bridge_name)+1, sizeof(msg), bridge_name, IFLA_IFNAME);
    add_place_end(&msg.header, ifname_place);
    struct rtattr* linkinfo_place = nlbrctl::add_place(&msg.header, sizeof(msg), IFLA_LINKINFO);
    struct rtattr* infokind_place = nlbrctl::add_place(&msg.header, sizeof(msg), IFLA_INFO_KIND);
    nlbrctl::add_atribute_without_bound(&msg.header, strlen("bridge"), sizeof(msg), "bridge", IFLA_LINKINFO);
    add_place_end(&msg.header, infokind_place);
    add_place_end(&msg.header, linkinfo_place);

    iov.iov_base            = &msg.header;
    iov.iov_len             = msg.header.nlmsg_len;

    msg.nladdr.nl_family    = AF_NETLINK;

    msg.body.msg_name       = &msg.nladdr;
    msg.body.msg_namelen    = sizeof(msg.nladdr);
    msg.body.msg_iov        = &iov;
    msg.body.msg_iovlen     = 1;

    if (sendmsg(rthandle.fd, &msg.body, 0) < 0) {
        ERROR("failed to send message: %d\n", errno);
        close(rthandle.fd);
        return -1;
    }
    
    /* ONLY FOR DEBUG, DONT PAY ATTENTION */
    char buf[1024];
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifinfo;
    int ret;

    ret = recv(rthandle.fd, buf, sizeof(buf), 0);
    if (ret < 0) {
        perror("recv");
        close(rthandle.fd);
        return -1;
    }

    // recv parse
    for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, ret); nlh = NLMSG_NEXT(nlh, ret)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
            if (err->error != 0) {
                fprintf(stderr, "Netlink error: %s\n", strerror(-err->error));
                close(rthandle.fd);
                return -1;
            }
        } else if (nlh->nlmsg_type == NLMSG_DONE) {
            break;
        }
    }

    close(rthandle.fd);
    
    return 0;
}

int main() {
    nlbrctl::add_bridge("br0");
}