#pragma once
#include <Windows.h>


namespace Offsets
{
	DWORD64		 OFFSET_HEALTH = 0x3E0;
	DWORD64		 OFFSET_ENTITYLIST = 0x1767348;
	DWORD64		 OFFSET_GLOW_DISTANCE = 0x2FC;
	DWORD64		 GLOW_ENABLE = 0x380;
	DWORD64		 GLOW_CONTEXT = 0x310;
	DWORD64		 GLOW_COLORS = 0x1d0;		 /*	this is for RGB color	*/
	DWORD64		 GLOW_DURATION = 0x2D0;	 // set CAREFULLY
	DWORD64		 GLOW_STYLE = 0x27C;		 // controls the style and look of glow
	DWORD64		 GLOW_IMPORTANCE = 0x320;	 // set to 1 to prevent enemies from hiding behind wall
	DWORD64		 GLOW_TIME_REAL = 0xEE4;	 // 0x2EC has to be the same as this
}