/* Copyright © 2011 Brandon L Black <blblack@gmail.com>
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


/**********************************************************************
 * There's really no good way around the dlsym problem, but this
 *  contains the ugliness to this one tiny source file.  This method
 *  throws aliasing warnings (which are probably technically correct),
 *  and the only other sane method will throw required warnings about
 *  casting between function and object pointers (which is technically
 *  undefined behavior in Standard C).  In either case, POSIX requires
 *  that the pointer works as expected in practice.
 *
 * References:
 *  http://www.opengroup.org/onlinepubs/9699919799/functions/dlsym.html
 *  http://geniusdex.net/page/20/using-dlsym-in-c.html
 *  etc... (google for dlsym aliasing function pointer)
 **********************************************************************/

// Disable strict-aliasing warnings under gcc 4.2+ for this file
#if defined __GNUC__ && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 1))
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

#include "gdnsd-plugapi-priv.h"
#include <dlfcn.h>

gdnsd_gen_func_ptr gdnsd_dlsym_fptr(void* restrict handle, const char* restrict symbol) {
    gdnsd_gen_func_ptr rval;
    *(void**)(&rval) = dlsym(handle, symbol);
    return rval;
}
