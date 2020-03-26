/*
Copyright (C) 2016-2020, Alexandre Gazet.

Copyright (C) 2014-2015, Quarkslab.

This file is part of ret-sync.

ret-sync is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _CORE_H
#define _CORE_H

#include "sync.h"


#define TIMER_PERIOD 100
#define CONF_FILE "\\.sync"

//menu identifiers
#define MENU_ENABLE_SYNC 0
#define MENU_DISABLE_SYNC 1
#define MENU_IDB_LIST 2

//functions
HRESULT sync(PSTR Args);
HRESULT syncoff();
HRESULT idblist();
void coreInit(PLUG_INITSTRUCT* initStruct);
void coreStop();
void coreSetup();

#endif // _CORE_H
