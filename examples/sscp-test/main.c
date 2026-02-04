#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sscp-host.h>

extern BOOL SSCP_SELFTEST;
extern BOOL SSCP_DEBUG_EXCHANGE;
extern BOOL SSCP_DEBUG_AUTHENTICATE;

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

int main(int argc, char** argv)
{
#ifdef _WIN32
	const char* sscpSerialPortName = "COM8";	
#else
	const char* sscpSerialPortName = "/dev/ttyUSB0";
#endif
	SSCP_CTX_ST* ctx;
	LONG rc;
	DWORD i;

	SSCP_SELFTEST = TRUE;	
	SSCP_DEBUG_EXCHANGE = TRUE;
	SSCP_DEBUG_AUTHENTICATE = TRUE;

	ctx = SSCP_Alloc();
	if (ctx == NULL)
	{
		printf("SSCP_Alloc failed\n");
		return -1;
	}
	
	rc = SSCP_Authenticate(ctx, NULL);
	if (rc)
	{
		printf("SSCP_Authenticate (SelfTest) failed\n");
		return -1;
	}

	rc = SSCP_Outputs(ctx, 0x02, 0x0A, 0x00);
	if (rc)
	{
		printf("SSCP_Outputs (SelfTest) failed\n");
		return -1;
	}

	printf("SelfTest OK\n");

	SSCP_SELFTEST = FALSE;

	SSCP_Free(ctx);

	ctx = SSCP_Alloc();
	if (ctx == NULL)
	{
		printf("SSCP_Alloc failed\n");
		return -1;
	}

	rc = SSCP_Open(ctx, sscpSerialPortName, 38400, 0);
	if (rc)
	{
		printf("SSCP_Open failed (err. %d)\n", rc);
		goto sscp_error;
	}

	rc = SSCP_SelectAddress(ctx, 0x01); /* RS485 */
	if (rc)
	{
		printf("SSCP_SelectAddress(0x01) failed (err. %d)\n", rc);
		goto sscp_error;
	}	

	rc = SSCP_Authenticate(ctx, NULL);
	if (rc)
	{
		printf("SSCP_Authenticate failed (err. %d)\n", rc);
		goto sscp_error;
	}
	printf("SSCP_Authenticate OK\n");

	{
		BYTE version;
		BYTE baudrate;
		BYTE address;
		WORD voltage;
		rc = SSCP_GetInfos(ctx, &version, &baudrate, &address, &voltage);
		if (rc)
		{
			printf("SSCP_GetInfos failed (err. %d)\n", rc);
			goto sscp_error;
		}
		printf("SSCP_GetInfos OK, version=%02X, baudrate=%02X, address=%02X, voltage=%04X\n", version, baudrate, address, voltage);
	}

	{
		char serialNumber[64];
		rc = SSCP_GetSerialNumber(ctx, serialNumber, sizeof(serialNumber));
		if (rc)
		{
			printf("SSCP_GetSerialNumber failed (err. %d)\n", rc);
			goto sscp_error;
		}
		printf("SSCP_GetSerialNumber OK, serialNumber=%s\n", serialNumber);
	}

	{
		char readerType[64];
		rc = SSCP_GetReaderType(ctx, readerType, sizeof(readerType));
		if (rc)
		{
			printf("SSCP_GetReaderType failed (err. %d)\n", rc);
			goto sscp_error;
		}
		printf("SSCP_GetReaderType OK, readerType=%s\n", readerType);
	}

	SSCP_OutputsRGB(ctx, 0x2244FF, 0xFF, 0);

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
			printf("SSCP_ScanNFC: no card found\n");
			goto card_error;
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

		{
			BYTE commandApdu[256];
			DWORD commandApduSz;
			BYTE responseApdu[256];
			DWORD responseApduSz;

			commandApduSz = 0;
			commandApdu[commandApduSz++] = 0x90;
			commandApdu[commandApduSz++] = 0x60;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x00;
			commandApdu[commandApduSz++] = 0x00;

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
				goto card_error;
			}

			printf("R-APDU=");
			for (i = 0; i < responseApduSz; i++)
				printf("%02X", responseApdu[i]);
			printf("\n");
		}
	}

card_error:	
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

