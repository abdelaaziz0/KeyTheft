#pragma once

__declspec(dllimport) void BeaconPrintf(int type, const char * fmt, ...);
__declspec(dllimport) void BeaconOutput(int type, const char * data, int len);
