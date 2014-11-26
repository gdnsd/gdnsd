/* Copyright © 2016 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_MCP_H
#define GDNSD_MCP_H

// These define the protocol for the socket between MCP and runtime while
// starting up and shutting down, which consists entirely of 1-byte messages.
// During normal runtime operations there are no messages over the socket, it's
// simply held open to verify both sides are alive, and to pass the eventual
// shutdown message from the MCP to the runtime.  If at any time either side
// detects an unexpected close of the socket or any other error (e.g. an
// invalid or unexpected message), it will exit its process (causing the other
// to do the same due to close, if it hadn't already).  Thus they always live
// and die together; one cannot exist (for very long) without the other.
static const char MSG_2MCP_BIND_SOCKS = 'B';
static const char MSG_2RT_OK_TO_LISTEN = 'O';
static const char MSG_2MCP_LISTENING = 'L';
static const char MSG_2RT_SHUTDOWN = 'S';
static const char MSG_2MCP_SHUTDOWN = 'X';

#endif // GDNSD_MCP_H
