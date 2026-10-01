#include "common.h"
#include "work.h"

VOID CreateWorkerThread(HWND hWnd, unsigned int hFunc, void* funcArgs, HANDLE hCancelEvent) {
    WorkerData* data = (WorkerData*)MYALLOC0(sizeof(WorkerData));
    if (!data) {
        MessageBox(hWnd, TEXT("Out of memory"), TEXT("Error"), MB_ICONERROR);
        return;
    }
    ZeroMemory(data, sizeof(*data));
    data->hWnd = hWnd;
    data->hFunc = hFunc;
    data->funcArgs = funcArgs;
    data->hCancelEvent = hCancelEvent;
    // start worker and keep handle so we can wait/close it on cancel/finish
    HANDLE hThread = CreateThread(NULL, 0, WorkerThreadProc, data, 0, NULL);
    if (!hThread) {
        MYFREE(data);
        MessageBox(hWnd, TEXT("Failed to create worker thread"), TEXT("Error"), MB_ICONERROR);
        return;
    }
}

// Background Worker Thread
DWORD WINAPI WorkerThreadProc(LPVOID lpParam) {
    WorkerData* data = (WorkerData*)lpParam;
    HWND hWnd = data->hWnd;

    switch (data->hFunc)
    {
    case FUNC_SHOTONLY:
        //DoShotOnly(data);
        break;
    case FUNC_SHOTSAVE:
        DoShotSave(data);
        break;
    case FUNC_LOAD:
        break;
    case FUNC_SAVE:
        break;
    case FUNC_COMPARE:
        break;
    default:
        break;
    }

    return 0;
}

//LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
//    switch (msg) {
//    case WM_WORKER_EXECUTE_FN:
//        auto pFn = (void(*)())(wParam);
//        int ret = -1;
//        if (pFn) {
//            ret = (*pFn)();            // execute on UI thread
//        }
//        MYFREE(pFn);             // release ownership
//
//        return ret;
//    }
//
//    return DefWindowProc(hwnd, msg, wParam, lParam);
//}

// inside DoShotSave - check the cancel event between long steps
DWORD DoShotSave(WorkerData* data) {
    if (!data) return 1;
    LPREGSHOT lpParam = (LPREGSHOT)data->funcArgs;

    // pre-check
    if (data->hCancelEvent && WaitForSingleObject(data->hCancelEvent, 0) == WAIT_OBJECT_0)
        return 1;

    // perform shot
    Shot(lpParam);
    MessageBeep((UINT)-1);
    // check cancel after expensive call
    if (data->hCancelEvent && WaitForSingleObject(data->hCancelEvent, 0) == WAIT_OBJECT_0)
        return 1;

    if (!fDontDisplayInfoAfterShot) {
        DisplayShotInfo(data->hWnd, lpMenuShot);
    }

    // save shot
    SaveShot(lpParam);

    PostMessage(data->hWnd, WM_WORKER_FINISHED, (WPARAM)FUNC_SHOTSAVE, (LPARAM)data);

    return 0;
}