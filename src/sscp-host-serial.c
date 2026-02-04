/**
 * @file sscp-host-serial.c
 * @brief Host-side SSCP context management and serial/RS-485 transport helpers.
 *
 * This module provides the "host/control panel" entry points to:
 * - allocate/free an SSCP context
 * - open/close the communication channel
 * - select the reader address (RS-485) and configure the serial line baudrate
 *
 * The actual platform-specific I/O primitives are implemented by the lower-level
 * serial backend (SSCP_SerialOpen/Close/Configure/SetTimeouts), which typically
 * maps to a COM port on Windows and a POSIX TTY file descriptor on Linux.
 *
 * @note This module is transport-facing. SSCP protocol commands (authentication,
 *       NFC scan, APDU transceive, LEDs, buzzer, etc.) are implemented in higher
 *       layers (e.g. sscp-host-functions.c).
 */
#include "sscp-host_i.h"

BOOL SSCP_SELFTEST = FALSE;

/**
 * @brief Allocate and initialize a new SSCP context.
 *
 * This function allocates a zero-initialized SSCP context structure and sets
 * platform-dependent communication fields to invalid defaults.
 *
 * @return A pointer to a newly allocated SSCP context on success, or NULL if
 *         memory allocation fails.
 *
 * @note The returned context must be released afterwards using SSCP_Free().
 */
SSCP_CTX_ST* SSCP_Alloc(void)
{
	struct _SSCP_CTX_ST* ctx = calloc(sizeof(struct _SSCP_CTX_ST), 1);
	if (ctx == NULL)
		return NULL;

#ifdef _WIN32
	ctx->commHandle = INVALID_HANDLE_VALUE;
#else
	ctx->commFd = -1;
#endif

	return ctx;
}

/**
 * @brief Close (if needed) and free an SSCP context.
 *
 * This function first calls SSCP_Close() to ensure the communication channel is
 * closed, then releases the memory associated with the context.
 *
 * @param[in,out] ctx SSCP context to free (may be NULL).
 */
void SSCP_Free(SSCP_CTX_ST *ctx)
{
	/* Just in case... */
	SSCP_Close(ctx);

	if (ctx != NULL)
		free(ctx);
}

/**
 * @brief Open and configure the serial/RS-485 communication channel.
 *
 * This function opens the underlying serial device/port and applies the initial
 * communication settings:
 * - Baudrate configuration
 * - Default receive timeouts (first byte / subsequent bytes)
 * - Default SSCP address selection (0x00, meaning RS-232 by convention)
 *
 * @param[in,out] ctx SSCP context.
 * @param[in] commName Platform-specific port identifier (e.g. "COM3" on Windows,
 *                     "/dev/ttyUSB0" on Linux).
 * @param[in] commBaudrate Initial baudrate in bits per second (e.g. 115200).
 * @param[in] commFlags Reserved for future use (currently ignored).
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* error code.
 *
 * @retval SSCP_ERR_INVALID_CONTEXT The @p ctx parameter is NULL.
 * @retval SSCP_ERR_INVALID_PARAMETER The @p commName parameter is NULL.
 *
 */
LONG SSCP_Open(SSCP_CTX_ST* ctx, const char* commName, DWORD commBaudrate, DWORD commFlags)
{
	LONG rc;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	if (commName == NULL)
		return SSCP_ERR_INVALID_PARAMETER;

	rc = SSCP_SerialOpen(ctx, commName);
	if (rc)
		return rc;

	rc = SSCP_SerialConfigure(ctx, commBaudrate);
	if (rc)
	{
		SSCP_SerialClose(ctx);
		return rc;
	}

	/* Default timeouts */
	rc = SSCP_SerialSetTimeouts(ctx, SSCP_RESPONSE_FIRST_TIMEOUT, SSCP_RESPONSE_NEXT_TIMEOUT);
	if (rc)
	{
		SSCP_SerialClose(ctx);
		return rc;
	}

	ctx->address = 0x00; /* Default is RS232 */

	ctx->stats.whenOpen = time(NULL);

	return SSCP_SUCCESS;
}

/**
 * @brief Close the communication channel associated with an SSCP context.
 *
 * @param[in,out] ctx SSCP context.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* error code returned
 *         by the serial backend.
 *
 * @retval SSCP_ERR_INVALID_CONTEXT The @p ctx parameter is NULL.
 */
LONG SSCP_Close(SSCP_CTX_ST* ctx)
{
	LONG rc;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	rc = SSCP_SerialClose(ctx);
	
	return rc;
}

/**
 * @brief Select the current SSCP target address on an RS-485 bus.
 *
 * This function updates the address used by subsequent SSCP exchanges.
 * It does not send any command to the reader; it only changes the local
 * context selection.
 *
 * @param[in,out] ctx SSCP context.
 * @param[in] address SSCP/RS-485 address to use (typically 0..127).
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* error code.
 *
 * @retval SSCP_ERR_INVALID_CONTEXT The @p ctx parameter is NULL.
 *
 * @note Address 0x00 is the broadcast address, commonly used on RS-232
 *       (point-to-point) connections, where addressing is not required.
 */
LONG SSCP_SelectAddress(SSCP_CTX_ST* ctx, BYTE address)
{
	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	ctx->address = address;

	return SSCP_SUCCESS;
}

/**
 * @brief Change the local serial baudrate used to communicate with the reader.
 *
 * This function reconfigures the underlying serial port to the given baudrate.
 * It does not instruct the reader to change its own baudrate; for that, use the
 * SSCP command-level function that updates the reader configuration (e.g.
 * SSCP_SetBaudrate()).
 *
 * @param[in,out] ctx SSCP context.
 * @param[in] baudrate Desired baudrate in bits per second.
 *
 * @return SSCP_SUCCESS on success, otherwise an SSCP_ERR_* error code.
 *
 * @retval SSCP_ERR_INVALID_CONTEXT The @p ctx parameter is NULL.
 *
 */
LONG SSCP_SelectBaudrate(SSCP_CTX_ST* ctx, DWORD baudrate)
{
	LONG rc;

	if (ctx == NULL)
		return SSCP_ERR_INVALID_CONTEXT;

	rc = SSCP_SerialConfigure(ctx, baudrate);
	if (rc)
	{
		SSCP_SerialClose(ctx);
		return rc;
	}

	return SSCP_SUCCESS;
}

