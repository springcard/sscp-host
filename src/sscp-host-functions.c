/**
 * @file sscp-host-functions.c
 * @brief High-level SSCP host-side helper functions.
 *
 * This module provides convenience wrappers around the low-level SSCP exchange
 * functions (e.g. SSCP_ExchangeRaw(), SSCP_Exchange(), ...), implementing common
 * reader operations such as:
 * - Establishing an authenticated SSCP session (mutual authentication + session keys)
 * - Operating the reader outputs (LED / buzzer)
 * - Fetching reader identification and configuration information
 * - Performing NFC polling and APDU transceive through the reader
 * - Getting simple communication/statistics counters
 *
 * @note This file is part of the host-side ("control panel") implementation.
 *       Transport-specific details (RS-485, USB, TCP, ...) are handled in sscp-host-serial.c
 *       and related modules.
 */
#include "sscp-host_i.h"

/**
 * @brief Enable extra trace output during SSCP_Authenticate().
 *
 * When set to TRUE, the authentication routine prints raw exchanged bytes and
 * intermediate values (A, B, nonces, HMAC checks).
 *
 * @warning Do not enable this in production builds: it can leak sensitive material
 *          to logs (even if keys are not printed, traffic and nonces still help
 *          attackers).
 */
BOOL SSCP_DEBUG_AUTHENTICATE = FALSE;

/**
 * @brief Perform SSCP mutual authentication and derive session keys.
 *
 * This function runs the SSCP mutual authentication procedure between the host
 * (control panel) and the reader, then derives the session keys used to protect
 * subsequent exchanges (HMAC and optional AES encryption, depending on the SSCP
 * profile/commands used).
 *
 * High-level sequence:
 * - The host initiates authentication by sending a fresh random challenge (rA).
 * - The reader replies with its own random challenge (rB) and an authentication
 *   proof (typically an HMAC computed with the shared long-term key).
 * - The host verifies the reader's proof, then replies with its own proof
 *   (typically an HMAC over the transcript and/or rB).
 * - Both sides derive session keys from the established material and reset/
 *   initialize the session state (counters, flags, etc.).
 *
 * On success, the SSCP context is updated with:
 * - Session keys (encryption/authentication)
 * - Session counters (typically reset to 1)
 * - Internal flags indicating an authenticated session is active
 *
 * @param[in,out] ctx
 *   SSCP context. Must be initialized before calling this function.
 *   On success, it is updated with derived session data and keys.
 *
 * @param[in] authKeyValue
 *   16-byte long-term authentication key shared with the reader.
 *   This key is not a session key: it is the static key used to authenticate
 *   and bootstrap the session.
 *   If this parameter is NULL, the default (transport) key is used.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* error code.
 *
 * @note This function performs network/transport exchanges with the reader.
 *       It may take a noticeable amount of time depending on the underlying
 *       transport and timeout configuration.
 *
 * @warning Never log or expose @p authKeyValue. If you enable debug traces for
 *          authentication, be aware that captured transcripts may help an attacker.
 */
LONG SSCP_Authenticate(SSCP_CTX_ST* ctx, const BYTE authKeyValue[16])
{
	static const BYTE SSCP_DEFAULT_AUTH_KEY[16] = { 0xE7, 0x4A, 0x54, 0x0F, 0xA0, 0x7C, 0x4D, 0xB1, 0xB4, 0x64, 0x21, 0x12, 0x6D, 0xF7, 0xAD, 0x36 };	
	BYTE command[256] = { 0 };
	DWORD commandSz = 0;
	BYTE response[256] = { 0 };
	DWORD responseSz = 0;
	BYTE rndA[16] = { 0 };
	BYTE rndB[16] = { 0 };
	BYTE rndAp[16] = { 0 };
	BYTE A[4] = { 0 };
	BYTE B[4] = { 0 };
	BYTE hA[32] = { 0 };
	BYTE hB[32] = { 0 };
	LONG rc;
	int offset;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	if (authKeyValue == NULL)
		authKeyValue = SSCP_DEFAULT_AUTH_KEY;

	if (SSCP_SELFTEST)
	{
		static const BYTE R[] = { 0x75, 0xCC, 0xF7, 0xB1, 0xF7, 0xFE, 0xA6, 0xF7, 0x58, 0x71, 0xFC, 0xF6, 0xDC, 0x75, 0x59, 0x23 };
		memcpy(rndA, R, 16);
	}
	else
	{
		if (!SSCP_GetRandom(rndA, sizeof(rndA)))
			return SSCP_ERR_INTERNAL_FAILURE;
	}


	/* 1st step */
	/* -------- */
	commandSz = 0;
	command[commandSz++] = 0x00;
	command[commandSz++] = 0x00;
	memcpy(&command[commandSz], rndA, 16);
	commandSz += 16;

	if (SSCP_SELFTEST)
	{
		static const BYTE R[] = {
			0x53, 0x77, 0x07, 0xAD, 0x48, 0x6F, 0x07, 0xAD, 0x75, 0xCC, 0xF7, 0xB1, 0xF7, 0xFE, 0xA6, 0xF7,
			0x58, 0x71, 0xFC, 0xF6, 0xDC, 0x75, 0x59, 0x23, 0xC8, 0xEE, 0x7C, 0x37, 0x5C, 0x21, 0xEA, 0xC5,
			0x1B, 0xD9, 0x7C, 0x51, 0xC6, 0x9F, 0x39, 0x5B, 0x69, 0xF6, 0x61, 0x77, 0x07, 0xD9, 0x44, 0x29,
			0x40, 0xC3, 0x9B, 0xEB, 0xFA, 0x0B, 0x44, 0x59, 0xCE, 0xBF, 0x6C, 0xD5, 0xE6, 0x10, 0xEA, 0x1F,
			0xF4, 0x4B, 0x34, 0x1E, 0x29, 0x16, 0x54, 0xA9
		};

		if (SSCP_DEBUG_AUTHENTICATE)
		{
			DWORD i;
			SSCP_Trace("<");
			for (i = 0; i < commandSz; i++)
				SSCP_Trace("%02X", command[i]);
			SSCP_Trace("\n");
		}

		memcpy(response, R, sizeof(R));
		responseSz = sizeof(R);

		if (SSCP_DEBUG_AUTHENTICATE)
		{
			DWORD i;
			SSCP_Trace(">");
			for (i = 0; i < responseSz; i++)
				SSCP_Trace("%02X", response[i]);
			SSCP_Trace("\n");
		}
	}
	else
	{
		rc = SSCP_ExchangeRaw(ctx, ctx->address, SSCP_PROTOCOL_AUTHENTICATE, command, commandSz, response, sizeof(response), &responseSz);
		if (rc)
			return rc;
	}

	offset = 0;
	memcpy(B, &response[offset], 4);
	offset += 4;
	memcpy(A, &response[offset], 4);
	offset += 4;
	memcpy(rndAp, &response[offset], 16);
	offset += 16;
	memcpy(rndB, &response[offset], 16);
	offset += 16;
	/* Offset is now on hB */

	if (SSCP_DEBUG_AUTHENTICATE)
	{
		DWORD i;
		SSCP_Trace("B ");
		for (i = 0; i < 4; i++)
			SSCP_Trace("%02X", B[i]);
		SSCP_Trace("\n");
		SSCP_Trace("A ");
		for (i = 0; i < 4; i++)
			SSCP_Trace("%02X", A[i]);
		SSCP_Trace("\n");
		SSCP_Trace("RndA' ");
		for (i = 0; i < 16; i++)
			SSCP_Trace("%02X", rndAp[i]);
		SSCP_Trace("\n");
		SSCP_Trace("RndB  ");
		for (i = 0; i < 16; i++)
			SSCP_Trace("%02X", rndB[i]);
		SSCP_Trace("\n");
	}

	/* Compute hB on our side */
	if (!SSCP_HMAC(authKeyValue, response, offset, hB))
		return SSCP_ERR_INTERNAL_FAILURE;

	/* Compare with received hB */
	if (memcmp(hB, &response[offset], 32))
	{
		if (SSCP_DEBUG_AUTHENTICATE)
		{
			DWORD i;
			SSCP_Trace("Wrong HCMAC in Authenticate\n");
			SSCP_Trace("Received: ");
			for (i = 0; i < 32; i++)
				SSCP_Trace("%02X", response[offset + i]);
			SSCP_Trace("\n");
			SSCP_Trace("Computed: ");
			for (i = 0; i < 32; i++)
				SSCP_Trace("%02X", hB[i]);
			SSCP_Trace("\n");
		}

		return SSCP_ERR_WRONG_RESPONSE_SIGNATURE;
	}

	/* 2nd step */
	/* -------- */
	commandSz = 0;
	memcpy(&command[commandSz], A, 4);
	commandSz += 4;
	memcpy(&command[commandSz], rndB, 16);
	commandSz += 16;

	/* Compute hA */
	if (!SSCP_HMAC(authKeyValue, command, commandSz, hA))
		return SSCP_ERR_INTERNAL_FAILURE;

	/* Append hA to the command */
	memcpy(&command[commandSz], hA, 32);
	commandSz += 32;

	if (SSCP_SELFTEST)
	{
		static const BYTE R[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x08 };
		memcpy(response, R, sizeof(R));
		responseSz = sizeof(R);
	}
	else
	{
		rc = SSCP_ExchangeRaw(ctx, ctx->address, 0x20, command, commandSz, response, sizeof(response), &responseSz);
		if (rc)
			return rc;
	}

	/* Expected response is an ACK */

	/* Compute session keys */
	/* -------------------- */
	if (!SSCP_ComputeSessionKeys(ctx, authKeyValue, rndA, rndB))
		return SSCP_ERR_INTERNAL_FAILURE;

	/* Initialize the counter to 1 */
	ctx->counter = 1;

	ctx->stats.sessionCount++;
	ctx->stats.whenSession = time(NULL);

	return SSCP_SUCCESS;
}

/**
 * @brief Set the RS-485 address of the reader.
 *
 * This function sends the SSCP command that updates the reader RS-485 address.
 * The new address is stored in the reader and will be used for subsequent
 * communications on the RS-485 bus.
 *
 * @param[in,out] ctx
 *   SSCP context. Must be initialized and associated with the target reader.
 *
 * @param[in] address
 *   New RS-485 address to assign to the reader.
 *   Valid range is 0 to 127 (7-bit address).
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* error code.
 *
 * @retval SSCP_ERR_INVALID_CONTEXT
 *   The @p ctx parameter is NULL.
 *
 * @retval SSCP_ERR_INVALID_PARAMETER
 *   The requested address is outside the valid range.
 *
 * @note Changing the address of the reader may immediately affect bus
 *       communication. The host must use the new address for any further
 *       exchanges; see SSCP_SelectAddress().
 *
 * @note This command is typically only meaningful for RS-485 transports.
 */
LONG SSCP_SetAddress(SSCP_CTX_ST* ctx, BYTE address)
{
	BYTE data[1];
	LONG rc;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	if (address > 127)
		return SSCP_ERR_INVALID_PARAMETER;

	data[0] = address;

	rc = SSCP_Exchange(ctx, SSCP_CMD_SET_RS485_ADDRESS, data, sizeof(data), NULL, 0, NULL);

	return rc;
}

/**
 * @brief Set the RS-485 communication baudrate of the reader.
 *
 * This function configures the reader RS-485 baudrate by issuing the
 * corresponding SSCP command. The baudrate is selected using a predefined
 * enumeration defined by the SSCP specification.
 *
 * Supported baudrates are:
 * - 9600
 * - 19200
 * - 38400
 * - 57600
 * - 115200
 *
 * @param[in,out] ctx
 *   SSCP context. Must be initialized and associated with the target reader.
 *
 * @param[in] baudrate
 *   Desired baudrate in bits per second.
 *   Must be one of the supported values listed above.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* error code.
 *
 * @retval SSCP_ERR_INVALID_CONTEXT
 *   The @p ctx parameter is NULL.
 *
 * @retval SSCP_ERR_INVALID_PARAMETER
 *   The requested baudrate is not supported.
 *
 * @note After changing the baudrate, communication parameters on the host side
 *       must be updated accordingly, otherwise further exchanges will fail;
 *       see SSCP_SelectBaudrate().
 */
LONG SSCP_SetBaudrate(SSCP_CTX_ST* ctx, DWORD baudrate)
{
	BYTE data[1];
	LONG rc;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	switch (baudrate)
	{
		case 9600:
			data[0] = 0x00;
		break;
		case 19200:
			data[0] = 0x01;
		break;
		case 38400:
			data[0] = 0x02;
		break;
		case 57600:
			data[0] = 0x03;
		break;
		case 115200:
			data[0] = 0x04;
		break;

		default:
			return SSCP_ERR_INVALID_PARAMETER;
	}

	rc = SSCP_Exchange(ctx, SSCP_CMD_SET_BAUDRATE, data, sizeof(data), NULL, 0, NULL);

	return rc;
}

/**
 * @brief Change the reader long-term authentication key.
 *
 * This function updates the reader long-term authentication key by issuing
 * the SSCP "ChangeReaderKeys" command.
 *
 * The new key replaces the current authentication key stored in the reader
 * non-volatile memory. After a successful change:
 * - All subsequent SSCP authentication attempts must use the new key.
 * - The old key becomes permanently invalid.
 *
 * @param[in,out] ctx
 *   SSCP context. Must be initialized and associated with an authenticated
 *   reader session.
 *
 * @param[in] newKey
 *   Pointer to the new 16-byte authentication key to be written to the reader.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* error code.
 *
 * @retval SSCP_ERR_INVALID_CONTEXT
 *   The @p ctx parameter is NULL.
 *
 * @retval SSCP_ERR_INVALID_PARAMETER
 *   The @p newKey parameter is NULL.
 *
 * @note This operation is security-critical.
 *       It should only be executed after a successful SSCP authentication
 *       using the current valid key.
 *
 * @warning If the new key is lost or mismatched with the control panel
 *          configuration, the reader will no longer be accessible and may
 *          require factory reset or secure recovery procedures.
 */
LONG SSCP_ChangeKey(SSCP_CTX_ST* ctx, const BYTE newKey[16])
{
	BYTE data[17];
	LONG rc;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	if (newKey == NULL)
		return SSCP_ERR_INVALID_PARAMETER;		

	data[0] = 0x04;
	memcpy(&data[1], newKey, 16);

	rc = SSCP_Exchange(ctx, SSCP_CMD_CHANGE_READER_KEYS, data, sizeof(data), NULL, 0, NULL);

	return rc;
}

/**
 * @brief Control the reader main outputs (bi-colour LED and buzzer).
 *
 * This issues the SSCP "OutPuts" command (00h 07h) to set LED colour and to
 * activate LED and buzzer for the specified durations.
 *
 * @param[in,out] ctx SSCP context.
 * @param[in] ledColor LED colour selector:
 *   - 0x00: LED off
 *   - 0x01: green
 *   - 0x02: red
 *   - 0x03: orange
 * @param[in] ledDuration LED duration in multiples of 100 ms.
 *   0xFF keeps the LED on indefinitely (until reset or another command).
 * @param[in] buzzerDuration Buzzer duration in multiples of 100 ms.
 *   0xFF keeps the buzzer on indefinitely (until reset or another command).
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 *
 */
LONG SSCP_Outputs(SSCP_CTX_ST* ctx, BYTE ledColor, BYTE ledDuration, BYTE buzzerDuration)
{
	BYTE data[3];
	LONG rc;

	data[0] = ledColor;
	data[1] = ledDuration;
	data[2] = buzzerDuration;

	rc = SSCP_Exchange(ctx, SSCP_CMD_OUTPUTS, data, sizeof(data), NULL, 0, NULL);

	return rc;
}

/**
 * @brief Advanced control of the reader main outputs (tri-colour LED and buzzer).
 *
 * This issues the SSCP "OutputRGB" command (00h 50h) to set LED colour and to
 * activate LED and buzzer for the specified durations.
 *
 * @param[in,out] ctx SSCP context.
 * @param[in] ledColor RGB LED colour selector.
 * @param[in] ledDuration LED duration in multiples of 100 ms.
 *   0xFF keeps the LED on indefinitely (until reset or another command).
 * @param[in] buzzerDuration Buzzer duration in multiples of 100 ms.
 *   0xFF keeps the buzzer on indefinitely (until reset or another command).
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 *
 * @note This command is outside the SPAC SSCPv2 Standard. Not all readers support it.
 * 
 */
LONG SSCP_OutputsRGB(SSCP_CTX_ST* ctx, DWORD ledColor, BYTE ledDuration, BYTE buzzerDuration)
{
	BYTE data[6];
	LONG rc;

	data[0] = 0x80; /* Activate expert mode */
	data[1] = (BYTE) (ledColor >> 16);
	data[2] = (BYTE) (ledColor >> 8);
	data[3] = (BYTE) (ledColor >> 0);
	data[4] = ledDuration;
	data[5] = buzzerDuration;

	rc = SSCP_Exchange(ctx, SSCP_CMD_OUTPUT_RGB, data, sizeof(data), NULL, 0, NULL);

	return rc;
}

/**
 * @brief Control the reader external full-colour LED ramp.
 *
 * This issues the SSCP "ExternalLEDColors" command (00h 5Ah) to set LED colour.
 *
 * @param[in,out] ctx SSCP context.
 * @param[in] param1 Value of RGB components (R in MSB and B in LSB)
 * @param[in] param2 Value of RGB components (R in MSB and B in LSB)
 * @param[in] param3 Value of RGB components (R in MSB and B in LSB)s.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 *
 * @note Not all readers support this command.
 * 
 */
LONG SSCP_ExternalLEDRGB(SSCP_CTX_ST* ctx, DWORD param1, DWORD param2, DWORD param3)
{
	BYTE data[9];
	LONG rc;

	data[0] = (BYTE) (param1 >> 16);
	data[1] = (BYTE) (param1 >> 8);
	data[2] = (BYTE) (param1 >> 0);
	data[3] = (BYTE) (param2 >> 16);
	data[4] = (BYTE) (param2 >> 8);
	data[5] = (BYTE) (param2 >> 0);
	data[6] = (BYTE) (param3 >> 16);
	data[7] = (BYTE) (param3 >> 8);
	data[8] = (BYTE) (param3 >> 0);

	rc = SSCP_Exchange(ctx, SSCP_CMD_EXTERNAL_LED_COLORS, data, sizeof(data), NULL, 0, NULL);

	return rc;
}

/**
 * @brief Retrieve basic reader settings (firmware version, baudrate, address, voltage).
 *
 * This issues the SSCP "GetInfos" command (00h 08h).
 *
 * @param[in,out] ctx SSCP context.
 * @param[out] version Optional pointer receiving the firmware version byte.
 * @param[out] baudrate Optional pointer receiving the configured RS-485 baudrate selector.
 * @param[out] address Optional pointer receiving the current RS-485 address.
 * @param[out] voltage Optional pointer receiving the reader supply voltage in millivolts
 *   encoded as a big-endian 16-bit value (as returned by the reader).
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 */
LONG SSCP_GetInfos(SSCP_CTX_ST* ctx, BYTE *version, BYTE* baudrate, BYTE* address, WORD* voltage)
{
	BYTE responseData[16] = { 0 };
	DWORD responseDataSz = 0;
	LONG rc;

	rc = SSCP_Exchange_NoDataIn(ctx, SSCP_CMD_GET_INFOS, responseData, sizeof(responseData), &responseDataSz);
	if (rc)
		return rc;

	if (responseDataSz < 5)
		return SSCP_ERR_UNSUPPORTED_RESPONSE_LENGTH;

	if (version != NULL)
		*version = responseData[0];
	if (baudrate != NULL)
		*baudrate = responseData[1];
	if (address != NULL)
		*address = responseData[2];
	if (voltage != NULL)
		*voltage = (responseData[3] << 8) | (responseData[4]);

	return SSCP_SUCCESS;
}

/**
 * @brief Get the reader serial number.
 *
 * This issues the SSCP "GetSerialNumber" command (00h 1Fh).
 * The returned serial number is formatted here as:
 *   "<letter><8-hex-digits>" (e.g. "S15330272"),
 * matching the reader response structure (1 ASCII letter + 4 bytes).
 *
 * @param[in,out] ctx SSCP context.
 * @param[out] serialNumber Output buffer receiving a NUL-terminated string.
 * @param[in] maxSerialNumberSz Size of @p serialNumber in bytes.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 *
 * @note If the reader does not implement this feature, the serial number is
 *       expected to be 00000000 or FFFFFFFF (spec behaviour).
 */
LONG SSCP_GetSerialNumber(SSCP_CTX_ST* ctx, char* serialNumber, BYTE maxSerialNumberSz)
{
	BYTE responseData[16] = { 0 };
	DWORD responseDataSz = 0;
	LONG rc;

	if (serialNumber == NULL)
		return SSCP_ERR_INVALID_PARAMETER;

	memset(serialNumber, 0, maxSerialNumberSz);

	rc = SSCP_Exchange_NoDataIn(ctx, SSCP_CMD_GET_SERIAL_NUMBER, responseData, sizeof(responseData), &responseDataSz);
	if (rc)
		return rc;

	if (responseDataSz != 5)
		return SSCP_ERR_UNSUPPORTED_RESPONSE_LENGTH;

	snprintf(serialNumber, maxSerialNumberSz, "%c%02X%02X%02X%02X", responseData[0], responseData[1], responseData[2], responseData[3], responseData[4]);

	return SSCP_SUCCESS;
}

/**
 * @brief Get the reader type / reference string.
 *
 * This issues the SSCP "GetReaderType" command (00h 57h).
 *
 * @param[in,out] ctx SSCP context.
 * @param[out] readerType Output buffer receiving an ASCII, NUL-terminated string.
 * @param[in] maxReaderTypeSz Size of @p readerType in bytes.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 *
 * @note The reader may return either a NUL-terminated string or a raw ASCII
 *       buffer; this implementation stops on NUL or when the output buffer is full.
 */
LONG SSCP_GetReaderType(SSCP_CTX_ST* ctx, char* readerType, BYTE maxReaderTypeSz)
{
	BYTE responseData[32] = { 0 };
	DWORD responseDataSz = 0;
	DWORD i;
	LONG rc;

	if (readerType == NULL)
		return SSCP_ERR_INVALID_PARAMETER;

	memset(readerType, 0, maxReaderTypeSz);

	rc = SSCP_Exchange_NoDataIn(ctx, SSCP_CMD_GET_READER_TYPE, responseData, sizeof(responseData), &responseDataSz);
	if (rc)
		return rc;

	for (i = 0; i < responseDataSz; i++)
	{
		if (i >= maxReaderTypeSz)
			break; /* Don't overwrite the last '\0' */
		readerType[i] = (char)responseData[i];
		if (responseData[i] == 0x00)
			break; /* EOT */
	}

	return SSCP_SUCCESS;
}

/**
 * @brief Scan for a contactless tag using the SSCP ScanGlobal sequence (ISO A/B).
 *
 * This function uses the SSCP "ScanGlobal" command (00h B0h) with a fixed filter
 * selecting ISO14443-A and ISO14443-B polling.
 *
 * Depending on the detected technology, the function returns:
 * - @p protocol = 0x0001 for ISO14443-A, with UID (and optionally ATS)
 * - @p protocol = 0x0002 for ISO14443-B, with PUPI/UID
 * - @p protocol = 0 when no tag is present
 *
 * @param[in,out] ctx SSCP context.
 * @param[out] protocol Receives the detected protocol identifier (0, 0x0001, 0x0002).
 * @param[out] uid Optional buffer to receive the UID/PUPI bytes.
 * @param[in] maxUidSz Size of @p uid in bytes.
 * @param[out] actUidSz If @p uid is non-NULL, receives the actual UID/PUPI length.
 * @param[out] ats Optional buffer to receive the ATS (ISO14443-A only, if present).
 * @param[in] maxAtsSz Size of @p ats in bytes.
 * @param[out] actAtsSz If @p ats is non-NULL, receives the actual ATS length.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 *
 * @note The reader can be slow for ScanGlobal; this function enforces a minimum
 *       guard time between polls (see SSCP_GuardTime()).
 */
LONG SSCP_ScanNFC(SSCP_CTX_ST* ctx, WORD* protocol, BYTE uid[], BYTE maxUidSz, BYTE* actUidSz, BYTE ats[], BYTE maxAtsSz, BYTE* actAtsSz)
{
	BYTE filter[] = { 0x00, 0x07 };
	BYTE responseData[32] = { 0 };
	DWORD responseDataSz = 0;
	BYTE responseType = 0;
	LONG rc;
	BYTE length;
	DWORD offset = 0;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	if (protocol == NULL)
		return SSCP_ERR_INVALID_PARAMETER;
	if ((uid != NULL) && (actUidSz == NULL))
		return SSCP_ERR_INVALID_PARAMETER;
	if ((ats != NULL) && (actAtsSz == NULL))
		return SSCP_ERR_INVALID_PARAMETER;

	*protocol = 0;
	if (actUidSz != NULL)
		*actUidSz = 0;
	if (actAtsSz != NULL)
		*actAtsSz = 0;

	/* Make sure we don't call this function too often, because the reader is __slow__ */
	SSCP_GuardTime(ctx, SSCP_SCAN_GLOBAL_GUARD_TIME);

	/* Command is SCAN_GLOBAL */
	rc = SSCP_Exchange(ctx, SSCP_CMD_SCAN_GLOBAL, filter, sizeof(filter), responseData, sizeof(responseData), &responseDataSz);
	if (rc)
		return rc;

	if (responseDataSz < 1)
		return SSCP_ERR_WRONG_RESPONSE_LENGTH;

	responseType = responseData[offset++];

	switch (responseType)
	{
		case 0x00 :
			/* No tag */
		break;

		case 0x01 :
			/* ISOA */
			*protocol = 0x0001;
			if (responseDataSz < 6)
				return SSCP_ERR_UNSUPPORTED_RESPONSE_LENGTH;
			if (responseData[offset++] != 1)
				return SSCP_ERR_UNSUPPORTED_RESPONSE_VALUE;
			/* Skip ATQA and SAK */
			offset += 3;
			/* This is UIDLen */
			length = responseData[offset++];
			if (offset + length > responseDataSz)
				return SSCP_ERR_UNSUPPORTED_RESPONSE_VALUE; /* Not a valid length */
			if (actUidSz != NULL)
				*actUidSz = length;
			if (length > maxUidSz)
				return SSCP_ERR_OUTPUT_BUFFER_OVERFLOW;
			if (uid != NULL)
				memcpy(uid, &responseData[offset], length);
			offset += length;
			if (offset < responseDataSz)
			{
				/* This is ATSLen */
				length = responseData[offset]; /* ATSLen is part of the ATS itself, so no offset increment */
				if (offset + length > responseDataSz)
					return SSCP_ERR_UNSUPPORTED_RESPONSE_VALUE; /* Not a valid length */
				if (actAtsSz != NULL)
					*actAtsSz = length;
				if (length > maxAtsSz)
					return SSCP_ERR_OUTPUT_BUFFER_OVERFLOW;
				if (ats != NULL)
					memcpy(ats, &responseData[offset], length);
				offset += length;
			}
		break;

		case 0x02 :
			/* ISOB */
			*protocol = 0x0002;
			if (responseDataSz < 4)
				return SSCP_ERR_UNSUPPORTED_RESPONSE_LENGTH;
			if (responseData[offset++] != 1)
				return SSCP_ERR_UNSUPPORTED_RESPONSE_VALUE;
			/* Skip RFU */
			offset += 1;
			/* This is UIDLen */
			length = responseData[offset++];
			if (offset + length > responseDataSz)
				return SSCP_ERR_UNSUPPORTED_RESPONSE_VALUE; /* Not a valid length */
			if (actUidSz != NULL)
				*actUidSz = length;
			if (length > maxUidSz)
				return SSCP_ERR_OUTPUT_BUFFER_OVERFLOW;
			if (uid != NULL)
				memcpy(uid, &responseData[offset], length);
		break;

		default:
			return SSCP_ERR_UNSUPPORTED_RESPONSE_STATUS;
	}

	return SSCP_SUCCESS;
}

/**
 * @brief Scan for an ISO14443-A tag using the SSCP Scan_A_RAW command.
 *
 * This issues the SSCP "Scan_A_RAW" command (00h 0Fh) and returns basic
 * ISO14443-A parameters (ATQA, SAK, UID and optional ATS).
 *
 * @param[in,out] ctx SSCP context.
 * @param[out] protocol Receives 0x0001 if a card is present, or 0 if none.
 * @param[out] uid Optional buffer to receive the UID bytes.
 * @param[in] maxUidSz Size of @p uid in bytes.
 * @param[out] actUidSz If @p uid is non-NULL, receives the actual UID length.
 * @param[out] ats Optional buffer to receive the ATS bytes (if present).
 * @param[in] maxAtsSz Size of @p ats in bytes.
 * @param[out] actAtsSz If @p ats is non-NULL, receives the actual ATS length.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 *
 * @note The current implementation always requests ATS (RATS=0x01 in the command
 *       payload, per specification).
 * @note A guard time is enforced to avoid over-polling the reader.
 */
LONG SSCP_ScanARaw(SSCP_CTX_ST* ctx, WORD *protocol, BYTE uid[], BYTE maxUidSz, BYTE* actUidSz, BYTE ats[], BYTE maxAtsSz, BYTE* actAtsSz)
{
	BYTE ats_spec[] = { 0x01 };
	BYTE responseData[32] = { 0 };
	DWORD responseDataSz = 0;
	BYTE cardCount = 0;
	LONG rc;
	BYTE length;
	DWORD offset = 0;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	if (protocol == NULL)
		return SSCP_ERR_INVALID_PARAMETER;
	if ((uid != NULL) && (actUidSz == NULL))
		return SSCP_ERR_INVALID_PARAMETER;
	if ((ats != NULL) && (actAtsSz == NULL))
		return SSCP_ERR_INVALID_PARAMETER;

	*protocol = 0;
	if (actUidSz != NULL)
		*actUidSz = 0;
	if (actAtsSz != NULL)
		*actAtsSz = 0;

	/* Make sure we don't call this function too often, because the reader is __slow__ */
	SSCP_GuardTime(ctx, SSCP_SCAN_GLOBAL_GUARD_TIME);

	/* Command is SCAN_A_RAW */
	rc = SSCP_Exchange(ctx, SSCP_CMD_SCAN_A_RAW, ats_spec, sizeof(ats_spec), responseData, sizeof(responseData), &responseDataSz);
	if (rc)
		return rc;

	if (responseDataSz < 1)
		return SSCP_ERR_WRONG_RESPONSE_LENGTH;

	cardCount = responseData[offset++];

	switch (cardCount)
	{
		case 0x00 :
			/* No tag */
		break;

		case 0x01 :
			/* ISOA present */
			*protocol = 0x0001;
			if (responseDataSz < 5)
				return SSCP_ERR_UNSUPPORTED_RESPONSE_LENGTH;
			/* Skip ATQA and SAK */
			offset += 3;
			/* This is UIDLen */
			length = responseData[offset++];
			if (offset + length > responseDataSz)
				return SSCP_ERR_UNSUPPORTED_RESPONSE_VALUE; /* Not a valid length */
			if (actUidSz != NULL)
				*actUidSz = length;
			if (length > maxUidSz)
				return SSCP_ERR_OUTPUT_BUFFER_OVERFLOW;
			if (uid != NULL)
				memcpy(uid, &responseData[offset], length);
			offset += length;
			if (offset < responseDataSz)
			{
				/* This is ATSLen */
				length = responseData[offset]; /* ATSLen is part of the ATS itself, so no offset increment */
				if (offset + length > responseDataSz)
					return SSCP_ERR_UNSUPPORTED_RESPONSE_VALUE; /* Not a valid length */
				if (actAtsSz != NULL)
					*actAtsSz = length;
				if (length > maxAtsSz)
					return SSCP_ERR_OUTPUT_BUFFER_OVERFLOW;
				if (ats != NULL)
					memcpy(ats, &responseData[offset], length);
				offset += length;
			}
		break;

		default:
			return SSCP_ERR_UNSUPPORTED_RESPONSE_STATUS;
	}

	return SSCP_SUCCESS;
}

/**
 * @brief Exchange an APDU with the currently selected contactless card.
 *
 * This issues the SSCP "TransceiveAPDU" command (00h 5Fh), which lets the host
 * send a command APDU to the card and receive the response APDU.
 *
 * @param[in,out] ctx SSCP context.
 * @param[in] commandApdu APDU command bytes to send (may be NULL if size is 0).
 * @param[in] commandApduSz Size of @p commandApdu in bytes.
 * @param[out] responseApdu Buffer receiving the APDU response bytes (excluding status byte).
 * @param[in] maxResponseApduSz Size of @p responseApdu in bytes.
 * @param[out] actResponseApduSz Receives the actual response APDU length.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 *
 * @retval SSCP_ERR_NFC_CARD_MUTE_OR_REMOVED The card did not answer (timeout).
 * @retval SSCP_ERR_NFC_CARD_COMM_ERROR RF communication error (CRC/parity/framing...).
 *
 */
LONG SSCP_TransceiveNFC(SSCP_CTX_ST* ctx, const BYTE commandApdu[], DWORD commandApduSz, BYTE responseApdu[], DWORD maxResponseApduSz, DWORD* actResponseApduSz)
{
	BYTE *commandFull = NULL;
	BYTE responseData[256] = { 0 };
	DWORD responseDataSz = 0;
	BYTE responseStatus = 0;
	LONG rc;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	if (commandApdu == NULL && commandApduSz > 0)
		return SSCP_ERR_INVALID_PARAMETER;

    /* Allocated the two buffers */
    commandFull = calloc(commandApduSz, 1);
    if (commandFull == NULL)
        return SSCP_ERR_OUT_OF_MEMORY;
	commandFull[0] = 0x00; /* Reserved */
	memcpy(&commandFull[1], commandApdu, commandApduSz);

	if (actResponseApduSz != NULL)
		*actResponseApduSz = 0;

	/* Command is TRANSCEIVE APDU */
	rc = SSCP_Exchange(ctx, SSCP_CMD_TRANSCEIVE_APDU, commandFull, 1 + commandApduSz, responseData, sizeof(responseData), &responseDataSz);

	/* Free the allocated buffer ASAP */
	free(commandFull);

	if (rc)
		return rc;

	if (responseDataSz < 1)
		return SSCP_ERR_WRONG_RESPONSE_LENGTH;

	responseStatus = responseData[0];

	switch (responseStatus)
	{
		case 0x00:
			/* No error */
			if (actResponseApduSz != NULL)
				*actResponseApduSz = responseDataSz - 1;
			if (responseDataSz - 1 > maxResponseApduSz)
				return SSCP_ERR_OUTPUT_BUFFER_OVERFLOW;
			memcpy(responseApdu, &responseData[1], responseDataSz - 1);
		break;

		case 0x01:
			/* Card timeout */
			return SSCP_ERR_NFC_CARD_MUTE_OR_REMOVED;
		break;

		case 0x02:
			/* Card communication error */
			return SSCP_ERR_NFC_CARD_COMM_ERROR;
		break;

	default:
		return SSCP_ERR_UNSUPPORTED_RESPONSE_STATUS;
	}

	return SSCP_SUCCESS;
}

/**
 * @brief Release the RF field / card context on the reader.
 *
 * This issues the SSCP "ReleaseRF" command (as mapped by SSCP_CMD_RELEASE_RF),
 * which tells the reader to stop RF communication and release internal state.
 *
 * @param[in,out] ctx SSCP context.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 */
LONG SSCP_ReleaseNFC(SSCP_CTX_ST* ctx)
{
	return SSCP_Exchange_NoDataInOut(ctx, SSCP_CMD_RELEASE_RF);
}

/**
 * @brief Retrieve communication statistics from the SSCP context.
 *
 * This function does not talk to the reader: it aggregates counters maintained
 * locally by the host-side SSCP stack.
 *
 * @param[in,out] ctx SSCP context.
 * @param[out] stats Output structure filled with statistics.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* code.
 */
LONG SSCP_GetStatistics(SSCP_CTX_ST* ctx, SSCP_STATISTICS_ST* stats)
{
	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;
	if (stats == NULL)
		return SSCP_ERR_INVALID_PARAMETER;

	memset(stats, 0, sizeof(SSCP_STATISTICS_ST));

	if (ctx->stats.whenOpen)
		stats->totalTime = (DWORD) (time(NULL) - ctx->stats.whenOpen);
	stats->bytesSent = ctx->stats.bytesSent;
	stats->bytesReceived = ctx->stats.bytesReceived;
	stats->totalErrors = ctx->stats.errorCount;
	stats->sessionCount = ctx->stats.sessionCount;
	if (ctx->stats.whenSession)
		stats->sessionTime = (DWORD)(time(NULL) - ctx->stats.whenSession);
	stats->sessionCounter = ctx->counter;

	return SSCP_SUCCESS;
}

