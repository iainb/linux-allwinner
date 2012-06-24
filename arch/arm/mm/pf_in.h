/*
 *  Fault Injection Test harness (FI)
 *  Copyright (C) Intel Crop.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 *  USA.
 *
 */

#ifndef __PF_H_
#define __PF_H_

enum reason_type {
	NOT_ME,	/* page fault is not in regions */
	NOTHING,	/* access others point in regions */
	REG_READ,	/* read from addr to reg */
	REG_WRITE,	/* write from reg to addr */
	IMM_WRITE,	/* write from imm to addr */
	OTHERS	/* Other instructions can not intercept */
};

#endif /* __PF_H_ */
