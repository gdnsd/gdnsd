/* Copyright © 2013 Faidon Liambotis <paravoid@debian.org>
 *
 * This file is part of gdnsd.
 *
 * gdnsd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef GDNSD_SENDMMSG_H
#define GDNSD_SENDMMSG_H

#include <sys/socket.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "config.h"

#if (defined(HAVE_RECVMMSG) || defined(SYS_recvmmsg) || defined(__NR_recvmmsg)) && \
    (defined(HAVE_SENDMMSG) || defined(SYS_sendmmsg) || defined(__NR_sendmmsg))
#define USE_MMSG 1

#ifndef MSG_WAITFORONE
#define MSG_WAITFORONE 0x10000
#endif // MSG_WAITFORONE

#ifndef HAVE_RECVMMSG
static int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                    unsigned int flags, struct timespec *timeout) {
#if defined(SYS_recvmmsg)
        return syscall(SYS_recvmmsg, sockfd, msgvec, vlen, flags, timeout);
#elif defined(__NR_recvmmsg)
        return syscall(__NR_recvmmsg, sockfd, msgvec, vlen, flags, timeout);
#endif
}
#endif // HAVE_RECVMMSG

#ifndef HAVE_SENDMMSG
static int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags) {
#if defined(SYS_sendmmsg)
        return syscall(SYS_sendmmsg, sockfd, msgvec, vlen, flags);
#elif defined(__NR_sendmmsg)
        return syscall(__NR_sendmmsg, sockfd, msgvec, vlen, flags);
#endif
}
#endif // HAVE_SENDMMSG

#else
#undef USE_MMSG
#endif

#endif // GDNSD_SENDMMSG_H
