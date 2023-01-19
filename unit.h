
#ifndef UNIT_HEAD
#define UNIT_HEAD

#include "hde64.h"
#include "file.h"
#include "hook.h"
#include "mem.h"
#include "nt.h"
#include "pe.h"
#include "sys.h"

#pragma once

// This function initialization unit library
// If you use unit library you must call this function in you program
BOOLEAN InitializationUnit();

// This function iUnnitialization unit library
// If you use unit library you must call this function in you program
BOOLEAN UnInitializationUnit();

#endif