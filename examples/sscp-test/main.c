#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <sscp-host.h>

extern BOOL SSCP_SELFTEST;
extern BOOL SSCP_DEBUG_SERIAL;
extern BOOL SSCP_DEBUG_EXCHANGE;
extern BOOL SSCP_DEBUG_AUTHENTICATE;

typedef struct
{
	const char* serialPortName;
	DWORD serialBitrate;
	BYTE readerAddress;
	BOOL verbose;
} SSCP_TEST_PARAMS_ST;

#ifdef _WIN32
static char* optarg;
static int optind = 1;
static int opterr = 1;
static int optopt;

static int getopt(int argc, char* const argv[], const char* optstring)
{
	static const char* next = NULL;
	const char* option;
	const char* optdecl;

	if ((next == NULL) || (*next == '\0'))
	{
		if (optind >= argc)
			return -1;

		option = argv[optind];
		if ((option[0] != '-') || (option[1] == '\0'))
			return -1;

		if (strcmp(option, "--") == 0)
		{
			optind++;
			return -1;
		}

		next = option + 1;
		optind++;
	}

	optopt = *next++;
	optdecl = strchr(optstring, optopt);

	if ((optdecl == NULL) || (optopt == ':'))
	{
		if (opterr && (optstring[0] != ':'))
			fprintf(stderr, "Unknown option '-%c'\n", optopt);
		return '?';
	}

	if (optdecl[1] == ':')
	{
		if (*next != '\0')
		{
			optarg = (char*) next;
			next = NULL;
		}
		else if (optind < argc)
		{
			optarg = argv[optind++];
			next = NULL;
		}
		else
		{
			if (opterr && (optstring[0] != ':'))
				fprintf(stderr, "Option '-%c' requires an argument\n", optopt);
			return (optstring[0] == ':') ? ':' : '?';
		}
	}
	else
	{
		optarg = NULL;
	}

	return optopt;
}
#endif

static void showUsage(const char* programName)
{
	fprintf(stderr, "Usage: %s [connection options]\n", programName);
	fprintf(stderr, "Connection options:\n");
	fprintf(stderr, "  -p serial_port  Serial port name (default: COM8 on Windows, /dev/ttyUSB0 otherwise)\n");
	fprintf(stderr, "  -b bitrate      Connection bitrate: 9600, 38400, or 115200 (default: 38400)\n");
	fprintf(stderr, "  -a address      Reader address in hexadecimal, from 0x00 to 0x7F (default: 0x01)\n");
	fprintf(stderr, "  -v, --verbose   Enable serial, exchange, and authentication debug traces\n");
	fprintf(stderr, "  -h              Show this help\n");
	fprintf(stderr, "Address values are hexadecimal; the 0x prefix is optional.\n");
}

static void initParams(SSCP_TEST_PARAMS_ST* params)
{
#ifdef _WIN32
	params->serialPortName = "COM8";
#else
	params->serialPortName = "/dev/ttyUSB0";
#endif
	params->serialBitrate = 38400;
	params->readerAddress = 0x01;
	params->verbose = FALSE;
}

static const char* skipHexPrefix(const char* value)
{
	if ((value != NULL) && (value[0] == '0') && ((value[1] == 'x') || (value[1] == 'X')))
		return value + 2;

	return value;
}

static int parseBitrate(const char* value, DWORD* bitrate)
{
	char* end;
	unsigned long parsed;

	if ((value == NULL) || (*value == '\0') || (bitrate == NULL))
		return -1;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if ((errno != 0) || (*end != '\0'))
		return -1;

	switch (parsed)
	{
		case 9600:
		case 38400:
		case 115200:
			*bitrate = (DWORD) parsed;
			return 0;

		default:
			return -1;
	}
}

static int parseReaderAddress(const char* value, BYTE* out)
{
	char* end;
	const char* hex;
	unsigned long parsed;

	if ((value == NULL) || (*value == '\0') || (out == NULL))
		return -1;

	hex = skipHexPrefix(value);
	if (*hex == '\0')
		return -1;

	errno = 0;
	parsed = strtoul(hex, &end, 16);
	if ((errno != 0) || (*end != '\0') || (parsed > 0x7F))
		return -1;

	*out = (BYTE) parsed;
	return 0;
}

static int parseParams(int argc, char** argv, SSCP_TEST_PARAMS_ST* params)
{
	int opt;

	opterr = 0;
	optind = 1;
	optarg = NULL;
	optopt = 0;

	for (;;)
	{
		if ((optind < argc) && (strcmp(argv[optind], "--verbose") == 0))
		{
			params->verbose = TRUE;
			optind++;
			continue;
		}

		opt = getopt(argc, argv, "+p:b:a:vh");
		if (opt == -1)
			break;

		switch (opt)
		{
			case 'p':
				if ((optarg == NULL) || (optarg[0] == '\0'))
				{
					fprintf(stderr, "Invalid serial port name\n");
					showUsage(argv[0]);
					return -1;
				}
				params->serialPortName = optarg;
				break;

			case 'b':
				if (parseBitrate(optarg, &params->serialBitrate) != 0)
				{
					fprintf(stderr, "Invalid bitrate '%s'\n", optarg);
					showUsage(argv[0]);
					return -1;
				}
				break;

			case 'a':
				if (parseReaderAddress(optarg, &params->readerAddress) != 0)
				{
					fprintf(stderr, "Invalid reader address '%s'\n", optarg);
					showUsage(argv[0]);
					return -1;
				}
				break;

			case 'v':
				params->verbose = TRUE;
				break;

			case 'h':
				showUsage(argv[0]);
				return 1;

			case '?':
			default:
				if ((optopt == 'p') || (optopt == 'b') || (optopt == 'a'))
					fprintf(stderr, "Option '-%c' requires an argument\n", optopt);
				else
					fprintf(stderr, "Unknown option '-%c'\n", optopt);
				showUsage(argv[0]);
				return -1;
		}
	}

	if (optind < argc)
	{
		fprintf(stderr, "Unexpected argument '%s'\n", argv[optind]);
		showUsage(argv[0]);
		return -1;
	}

	return 0;
}

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
	SSCP_TEST_PARAMS_ST params;
	SSCP_CTX_ST* ctx;
	LONG rc;
	DWORD i;
	int parseRc;

	initParams(&params);
	parseRc = parseParams(argc, argv, &params);
	if (parseRc != 0)
		return (parseRc > 0) ? 0 : -1;

	SSCP_SELFTEST = TRUE;	
	if (params.verbose)
	{
		SSCP_DEBUG_SERIAL = TRUE;
		SSCP_DEBUG_EXCHANGE = TRUE;
		SSCP_DEBUG_AUTHENTICATE = TRUE;
	}

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
