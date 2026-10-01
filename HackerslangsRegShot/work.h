#pragma once
#include "common.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>

#define WM_WORKER_PROGRESS (WM_APP + 1)
#define WM_WORKER_FINISHED (WM_APP + 2)
#define WM_WORKER_EXECUTE_FN (WM_APP + 3)

#define FUNC_SHOTONLY  1
#define FUNC_SHOTSAVE 2
#define FUNC_LOAD 3
#define FUNC_SAVE 4
#define FUNC_COMPARE 5

typedef struct {
    HWND hWnd; // Main window handle to send messages back to
    unsigned int hFunc;
    void* func;
    void* funcArgs;
    HANDLE hCancelEvent;
} WorkerData;

DWORD WINAPI WorkerThreadProc(LPVOID lpParam);

DWORD DoShotSave(WorkerData* data);