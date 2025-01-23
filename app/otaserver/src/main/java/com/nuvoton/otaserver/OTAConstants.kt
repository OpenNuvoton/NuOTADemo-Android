package com.nuvoton.otaserver

import androidx.annotation.Keep

/**
 * Created by cchsu20 on 2018/5/21.
 */
class OTAConstants {
    @Keep
    companion object {
        /***************************************/
        /* CMD*/
        /***************************************/
        val CMD_CONNECT                 = 0x80    /* ok */
        val CMD_WRITE                   = 0x83
        val CMD_DH_KEY                  = 0x86    /* ok */
        val CMD_AUTH_KEY                = 0x87

        val CMD_DISCONNECT              = 0x8E
        val CMD_GET_VERSION             = 0x8F    /* ok */
        val CMD_ASK                     = 0x4F

        val STS_OK                      = 0x00
        val CMD_RETRUN_VAL              = 0xE0
        val CMD_ECDH_KEY                = 0xD0
        val CMD_STS_PASS                = 0x5A
        val CMD_STS_FAIL                = 0xA5
        val STS_REBOOT                  = 0x01   //=> 通知App，client會重開。Client會主動斷線。
        val ERR_CMD_CONNECT             = 0x7F
        val ERR_CMD_INVALID             = 0x7E
        val ERR_CMD_CHECKSUM            = 0x7D
        val ERR_ISP_CONFIG              = 0x7C
        val ERR_ISP_WRITE               = 0x7B
        val ERR_INVALID_ADDRESS         = 0x7A
        val ERR_OVER_RANGE              = 0x79
        val ERR_PAGE_ALIGN              = 0x78
        val ERR_ISP_ERASE               = 0x77
        val ERR_DH_KEY                  = 0x76
        val ERR_DH_ARGUMENT             = 0x75
        val ERR_AUTH_KEY                = 0x74
        val ERR_AUTH_KEY_OVER           = 0x73
        val ERR_CMD_KEY_EXCHANGE        = 0x72
        val ERR_CMD_IDENTIFY            = 0x71
        val ERR_SPI_INVALID_PAGESIZE    = 0x70
        val ERR_TIMEOUT                 = 0x6F
        val ERR_OLD_FW_VER              = 0x6E    //=>通知App，檢查FW INFO中的版本，client已是新的了。
    }
}