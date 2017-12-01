/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_DAEMON_H
#define GDNSD_DAEMON_H

#include <stdbool.h>

// This ignores SIGPIPE and detects systemd, which in turn affects log output
// and enables ready notification below).
// If "daemonize" is set, also does traditional daemonization and ignores
// SIGHUP in the final process.
void gdnsd_init_daemon(const bool daemonize);

// Notify systemd (if applicable) or fg process that a daemon is fully online and ready
void gdnsd_daemon_notify_ready(void);

#endif // GDNSD_DAEMON_H
