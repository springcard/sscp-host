/**
 * @file sscp-consts.h
 * @brief SSCP protocol constants and command identifiers.
 *
 * This header defines the constant values used by the SSCP protocol, including:
 * - Command identifiers
 * - Sub-command codes
 * - Fixed protocol values and limits
 *
 * These constants are shared by both host-side and device-side implementations
 * to ensure protocol consistency.
 *
 * @note This file contains protocol-level definitions only.
 *       It does not declare functions or data structures.
 */
#ifndef __SSCP_CONST_H__
#define __SSCP_CONST_H__

#define SSCP_PROTOCOL_AUTHENTICATE 0x20
#define SSCP_PROTOCOL_SECURE 0x21

#define SSCP_CMD_CHANGE_READER_KEYS 0x000003
#define SSCP_CMD_SET_BAUDRATE 0x000005
#define SSCP_CMD_SET_RS485_ADDRESS 0x000006
#define SSCP_CMD_OUTPUTS 0x000007
#define SSCP_CMD_GET_INFOS 0x000008
#define SSCP_CMD_SCAN_A_RAW 0x00000F
#define SSCP_CMD_GET_SERIAL_NUMBER 0x00001F
#define SSCP_CMD_OUTPUT_RGB 0x000050
#define SSCP_CMD_RELEASE_RF 0x000052
#define SSCP_CMD_GET_READER_TYPE 0x000057
#define SSCP_CMD_EXTERNAL_LED_COLORS 0x00005A
#define SSCP_CMD_TRANSCEIVE_APDU 0x00005F
#define SSCP_CMD_SCAN_GLOBAL 0x0000B0

#endif
