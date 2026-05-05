#include <stdio.h>

#include "project.h"

void showStatistics(SSCP_CTX_ST* ctx)
{
	SSCP_STATISTICS_ST stats;

	if (SSCP_GetStatistics(ctx, &stats) == 0)
	{
		printf("Total SSCP time:       %ds\n", stats.totalTime);
		printf("Recovered SSCP errors: %d\n", stats.totalErrors);
		printf("Total bytes sent:      %d\n", stats.bytesSent);
		printf("Total bytes received:  %d\n", stats.bytesReceived);
		printf("Number of sessions:    %d\n", stats.sessionCount);
		printf("Last session time:     %ds\n", stats.sessionTime);
		printf("Last session counter:  %d\n", stats.sessionCounter);
	}
}

static LONG showReaderInfos(SSCP_CTX_ST* ctx)
{
	LONG rc;
	BYTE version;
	BYTE baudrate;
	BYTE address;
	WORD voltage;
	char serialNumber[64];
	char readerType[64];

	rc = SSCP_GetInfos(ctx, &version, &baudrate, &address, &voltage);
	if (rc)
	{
		printf("SSCP_GetInfos failed (err. %d)\n", rc);
		return rc;
	}
	printf("SSCP_GetInfos OK, version=%02X, baudrate=%02X, address=%02X, voltage=%04X\n", version, baudrate, address, voltage);

	rc = SSCP_GetSerialNumber(ctx, serialNumber, sizeof(serialNumber));
	if (rc)
	{
		printf("SSCP_GetSerialNumber failed (err. %d)\n", rc);
		return rc;
	}
	printf("SSCP_GetSerialNumber OK, serialNumber=%s\n", serialNumber);

	rc = SSCP_GetReaderType(ctx, readerType, sizeof(readerType));
	if (rc)
	{
		printf("SSCP_GetReaderType failed (err. %d)\n", rc);
		return rc;
	}
	printf("SSCP_GetReaderType OK, readerType=%s\n", readerType);

	return 0;
}

int main(int argc, char** argv)
{
	SSCP_TOOL_PARAMS_ST params;
	SSCP_CTX_ST* ctx;
	LONG rc;
	DWORD i;
	int parseRc;

	SSCP_ToolInitParams(&params);
	parseRc = SSCP_ToolParseParams(argc, argv, &params);
	if (parseRc == SSCP_TOOL_PARSE_HELP)
		return 0;
	if (parseRc != SSCP_TOOL_PARSE_OK)
		return -1;

	ctx = SSCP_Alloc();
	if (ctx == NULL)
	{
		printf("SSCP_Alloc failed\n");
		return -1;
	}

	rc = SSCP_Open(ctx, params.serialPortName, params.serialBitrate, 0);
	if (rc)
	{
		printf("SSCP_Open failed (err. %d)\n", rc);
		goto sscp_error;
	}

	rc = SSCP_SelectAddress(ctx, params.readerAddress); /* RS485 */
	if (rc)
	{
		printf("SSCP_SelectAddress(0x%02X) failed (err. %d)\n", params.readerAddress, rc);
		goto sscp_error;
	}

	rc = SSCP_Authenticate(ctx, params.hasAuthKey ? params.authKey : NULL);
	if (rc)
	{
		printf("SSCP_Authenticate failed (err. %d)\n", rc);
		goto sscp_error;
	}
	printf("SSCP_Authenticate OK\n");

	switch (params.command)
	{
		case SSCP_TOOL_COMMAND_INFO:
			rc = showReaderInfos(ctx);
			if (rc)
				goto sscp_error;
			goto sscp_success;

		case SSCP_TOOL_COMMAND_OUTPUTS:
			rc = SSCP_Outputs(ctx, params.outputLedColor, params.outputLedDuration, params.outputBuzzerDuration);
			if (rc)
			{
				printf("SSCP_Outputs failed (err. %d)\n", rc);
				goto sscp_error;
			}
			printf("SSCP_Outputs OK\n");
			goto sscp_success;

		case SSCP_TOOL_COMMAND_OUTPUTS_RGB:
			rc = SSCP_OutputsRGB(ctx, params.outputRgbColor, params.outputLedDuration, params.outputBuzzerDuration);
			if (rc)
			{
				printf("SSCP_OutputsRGB failed (err. %d)\n", rc);
				goto sscp_error;
			}
			printf("SSCP_OutputsRGB OK\n");
			goto sscp_success;

		case SSCP_TOOL_COMMAND_SET_ADDRESS:
			rc = SSCP_SetAddress(ctx, params.newReaderAddress);
			if (rc)
			{
				printf("SSCP_SetAddress(0x%02X) failed (err. %d)\n", params.newReaderAddress, rc);
				goto sscp_error;
			}
			printf("SSCP_SetAddress OK\n");
			goto sscp_success;

		case SSCP_TOOL_COMMAND_SET_KEY:
			rc = SSCP_SetKey(ctx, params.newAuthKey);
			if (rc)
			{
				printf("SSCP_SetKey failed (err. %d)\n", rc);
				goto sscp_error;
			}
			printf("SSCP_SetKey OK\n");
			goto sscp_success;

		case SSCP_TOOL_COMMAND_POLL:
		default:
			break;
	}

	rc = SSCP_Outputs(ctx, 0x02, 0x0A, 0x02);
	if (rc)
	{
		printf("SSCP_Outputs failed (err. %d)\n", rc);
		goto sscp_error;
	}

	rc = showReaderInfos(ctx);
	if (rc)
		goto sscp_error;

	for (;;)
	{
		WORD protocol;
		BYTE uid[32];
		BYTE uidLen;
		BYTE ats[32];
		BYTE atsLen;

		rc = SSCP_ScanNFC(ctx, &protocol, uid, sizeof(uid), &uidLen, ats, sizeof(ats), &atsLen);

		if (rc)
		{
			printf("SSCP_ScanNFC failed (err. %d)\n", rc);
			goto sscp_error;
		}

		if (protocol == 0)
		{
			/* No card found, keep on polling */
			continue;
		}

		printf("SSCP_ScanNFC OK, card present, protocol=%04X\n", protocol);
		printf("\tUID=");
		for (i = 0; i < uidLen; i++)
			printf("%02X", uid[i]);
		printf("\n");
		if (atsLen)
		{
			printf("\tATS=");
			for (i = 0; i < atsLen; i++)
				printf("%02X", ats[i]);
			printf("\n");
		}

		SSCP_Outputs(ctx, 0x01, 0x0A, 0x02);

		for (;;)
		{
			BYTE commandApdu[256];
			DWORD commandApduSz;
			BYTE responseApdu[256];
			DWORD responseApduSz;

			commandApduSz = 0;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0xA4;
			commandApdu[commandApduSz++] = 0x04;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x02;
			commandApdu[commandApduSz++] = 0x3F;
			commandApdu[commandApduSz++] = 0x00;

			/*
			commandApduSz = 0;
			commandApdu[commandApduSz++] = 0x90;
			commandApdu[commandApduSz++] = 0x5A;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x03;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x00;

			commandApduSz = 0;
			commandApdu[commandApduSz++] = 0x60;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x00;
			*/

			printf("C-APDU=");
			for (i = 0; i < commandApduSz; i++)
				printf("%02X", commandApdu[i]);
			printf("\n");

			rc = SSCP_TransceiveNFC(ctx, commandApdu, commandApduSz, responseApdu, sizeof(responseApdu), &responseApduSz);

			if (rc)
			{
				switch (rc)
				{
					case SSCP_ERR_NFC_CARD_MUTE_OR_REMOVED:
						printf("SSCP_TransceiveNFC : card mute or removed\n");
						break;

					case SSCP_ERR_NFC_CARD_COMM_ERROR:
						printf("SSCP_TransceiveNFC : card communication error\n");
						break;

					default:
						printf("SSCP_TransceiveNFC failed (err. %d)\n", rc);
						goto sscp_error;
				}
			}

			if (responseApduSz == 0)
			{
				/* Card mute, card removed, or card communication error */
				break;
			}

			printf("R-APDU=");
			for (i = 0; i < responseApduSz; i++)
				printf("%02X", responseApdu[i]);
			printf("\n");

			break;
		}

		SSCP_Outputs(ctx, 0x02, 0x0A, 0x02);
		
		rc = SSCP_ReleaseNFC(ctx);
		if (rc)
		{
			printf("SSCP_ReleaseNFC failed (err. %d)\n", rc);
			goto sscp_error;
		}
	}

sscp_success:
	if (ctx != NULL)
	{
		SSCP_Close(ctx);
		showStatistics(ctx);
		SSCP_Free(ctx);
		ctx = NULL;
	}

	return 0;

sscp_error:
	if (ctx != NULL)
	{
		SSCP_Close(ctx);
		showStatistics(ctx);
		SSCP_Free(ctx);
		ctx = NULL;
	}
	return -1;
}
