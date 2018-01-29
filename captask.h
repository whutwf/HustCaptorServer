#ifndef HUST_CAP_TASK_H
#define HUST_CAP_TASK_H

enum Cap_State
{
    No_State=0,
    Init_State ,
    InitErr_State ,
    GetIf_State,
    SetIf_State,
    StartCap_State,
    CapFull_State,
    StopCap_State
};

enum Cap_Cmd
{
    GetIf_Cmd=0,
    SetIf_Cmd,
    SetFilter_Cmd,
    StartCap_Cmd,
    StartCapErr_Cmd,
    StopCap_Cmd,
    StopCapErr_Cmd,
    CapIsFull_Cmd,
    CapIsEmpty_Cmd
};

enum Cap_Cmd_Res
{
    GetIf_Content=0,
    GetIf_End,
};

typedef struct
{
    int cmd;
    int info;
    char buf[16];
} Com_Cmd_Info;

void start();

#endif