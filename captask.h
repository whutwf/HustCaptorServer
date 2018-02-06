#ifndef HUST_CAP_TASK_H
#define HUST_CAP_TASK_H

#define CONTENT_END					"\04\04"        /**< 串口传输信息尾部标志 */
#define CONTENT_START				"\03\03"        /**< 串口传输信息开始标志 */
#define CMD_BUF_LEN 28

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
    char buf[CMD_BUF_LEN];
} Com_Cmd_Info;

void start();

#endif