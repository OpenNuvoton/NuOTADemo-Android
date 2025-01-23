package com.nuvoton.otaserver.utility

/**
 * Created by cchsu20 on 2018/7/9.
 */

enum class OTACommand(val raw: Long, val reqLen: Int, val rspLen: Int) {
    // -1 means the value is not defined
    CMD_DISCONNECT(0x008E, 4, 4),
    CMD_CONNECT(0x0080, 0, 24),
    CMD_ECDH_PUB0(0x8600, 32, 4),
    CMD_ECDH_PUB1(0x8601, 32, 4),
    CMD_ECDH_GET_PUB0(0x8602, 0, 36),//
    CMD_ECDH_GET_PUB1(0x8603, 0, 36),//
    CMD_ECDH_RAND_PUB0(0x8604, 32, 4),
    CMD_ECDH_RAND_PUB1(0x8605, 32, 4),
    CMD_ECDH_GET_RAND_PUB0(0x8606, 0, 36),
    CMD_ECDH_GET_RAND_PUB1(0x8607, 0, 36),
    CMD_GET_VERSION(0x008F, -1, -1),
    CMD_ERASE(0x0081, -1, -1),
    CMD_WRITE(0x0002, -1, -1),
    CMD_SET_MASS_WRITE(0x8300, 8, 4),
    CMD_MASS_WRITE(0x8301, 48, 4),
    CMD_GET_ID(0x0085, -1, -1),
    CMD_READ_CONFIG(0x0082, -1, -1),
    CMD_UPDATE_CFG(0x009A, -1, -1),
    CMD_READ_OTP(0x008D, -1, -1),
    CMD_WRITE_OTP(0x8D00, -1, -1),
    CMD_RESET(0x0081, -1, -1),
    CMD_SET_REGION_LOCK(0x0097, -1, -1),
    CMD_XOM_SET(0x0091, -1, -1),
    CMD_XOM_ERASE(0x0090, -1, -1),
    CMD_ERASE_KPROM(0x9801, 32, 4),
    CMD_SET_KPROM(0x0098, 32, 4),
    CMD_AUTH_KPROM(0x0087, 32, 4),
    CMD_GET_RAND_IV(0x8608, -1, -1),
    CMD_SET_RAND_IV(0x8609, -1, -1),
    CMD_GET_ID_SIGNATURE(0x0089, -1, -1),
    CMD_IDENTIFY_SERVER(0x8700, -1, -1),
    CMD_MASS_ERASE(0x0099, -1, -1),
    CMD_EXEC_VENDOR_FUNC(0x8FF0, -1, -1),
    CMD_ERROR(0xFFFF, -1, -1);

    companion object {
        fun get(value: Long): OTACommand {
            var command = CMD_ERROR
            OTACommand.values().forEach { it -> if (it.raw == value) command = it }
            return command
        }
    }
}

enum class OTAStatusCode(val raw: Long) {
    STS_OK(0x00000000),
    STS_REBOOT(0x01000000),
    ERR_CMD_CONNECT(0x7F000000),
    ERR_CMD_INVALID(0x7E000000),
    ERR_CMD_CHECKSUM(0x7D000000),
    ERR_ISP_CONFIG(0x7C000000),
    ERR_ISP_WRITE(0x7B000000),
    ERR_INVALID_ADDRESS(0x7A000000),
    ERR_OVER_RANGE(0x79000000),
    ERR_PAGE_ALIGN(0x78000000),
    ERR_ISP_ERASE(0x77000000),
    ERR_DH_KEY(0x76000000),
    ERR_DH_ARGUMENT(0x75000000),
    ERR_AUTH_KEY(0x74000000),
    ERR_AUTH_KEY_OVER(0x73000000),
    ERR_CMD_KEY_EXCHANGE(0x72000000),
    ERR_CMD_IDENTIFY(0x71000000),
    ERR_SPI_INVALID_PAGESIZE(0x70000000),
    ERR_TIMEOUT(0x6F000000),
    ERR_PARAMETER(0x53000000),
    ERR_OLD_FW_VER(0x6E000000)
}