/**
 * @file params.c
 * @brief Command-line parsing for the sscp-tool example.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "project.h"

#ifdef _WIN32
static char* optarg;
static int optind = 1;
static int opterr = 1;
static int optopt;

/*
 * Small getopt-compatible parser for MSVC builds.
 *
 * The example intentionally uses getopt on every platform, but the Microsoft C
 * runtime does not provide it. This local implementation supports the option
 * forms used by this tool: short options, short options with required
 * arguments, grouped flag options, and "--" as an end-of-options marker.
 */
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

void SSCP_ToolShowUsage(const char* programName)
{
	fprintf(stderr, "Usage: %s [connection options] [command]\n", programName);
	fprintf(stderr, "Connection options:\n");
	fprintf(stderr, "  -p serial_port  Serial port name (default: COM8 on Windows, /dev/ttyUSB0 otherwise)\n");
	fprintf(stderr, "  -b bitrate      Connection bitrate: 9600, 38400, or 115200 (default: 38400)\n");
	fprintf(stderr, "  -a address      Reader address in hexadecimal, from 0x00 to 0x7F (default: 0x01)\n");
	fprintf(stderr, "  -k auth_key     Authentication key as 16 hexadecimal bytes, optionally prefixed with 0x\n");
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "  -I              Print reader information and exit\n");
	fprintf(stderr, "  -U c d b        Call SSCP_Outputs(c, d, b) and exit\n");
	fprintf(stderr, "  -R rgb d b      Call SSCP_OutputsRGB(rgb, d, b) and exit\n");
	fprintf(stderr, "  -A address      Set the reader address and exit\n");
	fprintf(stderr, "  -B bitrate      Set the reader bitrate: 9600, 19200, 38400, 57600, or 115200 and exit\n");
	fprintf(stderr, "  -K new_key      Set the reader key and exit\n");
	fprintf(stderr, "  -h              Show this help\n");
	fprintf(stderr, "Address, key, and RGB color values are hexadecimal; the 0x prefix is optional.\n");
	fprintf(stderr, "Output duration values accept decimal or 0x-prefixed hexadecimal input.\n");
	fprintf(stderr, "The -B command connects with -b, then changes the reader bitrate.\n");
}

void SSCP_ToolInitParams(SSCP_TOOL_PARAMS_ST* params)
{
	if (params == NULL)
		return;

#ifdef _WIN32
	params->serialPortName = "COM8";
#else
	params->serialPortName = "/dev/ttyUSB0";
#endif
	params->serialBitrate = 38400;
	params->readerAddress = 0x01;
	memset(params->authKey, 0, sizeof(params->authKey));
	params->hasAuthKey = FALSE;
	params->command = SSCP_TOOL_COMMAND_POLL;
	params->outputLedColor = 0;
	params->outputLedDuration = 0;
	params->outputBuzzerDuration = 0;
	params->outputRgbColor = 0;
	params->newReaderAddress = 0;
	params->newReaderBitrate = 0;
	memset(params->newAuthKey, 0, sizeof(params->newAuthKey));
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

static int parseReaderBitrate(const char* value, DWORD* bitrate)
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
		case 19200:
		case 38400:
		case 57600:
		case 115200:
			*bitrate = (DWORD) parsed;
			return 0;

		default:
			return -1;
	}
}

static int hexNibble(char value)
{
	if ((value >= '0') && (value <= '9'))
		return value - '0';
	if ((value >= 'a') && (value <= 'f'))
		return value - 'a' + 10;
	if ((value >= 'A') && (value <= 'F'))
		return value - 'A' + 10;
	return -1;
}

static const char* skipHexPrefix(const char* value)
{
	if ((value != NULL) && (value[0] == '0') && ((value[1] == 'x') || (value[1] == 'X')))
		return value + 2;

	return value;
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

static int parseByteValue(const char* value, BYTE* out)
{
	char* end;
	unsigned long parsed;

	if ((value == NULL) || (*value == '\0') || (out == NULL))
		return -1;

	errno = 0;
	parsed = strtoul(value, &end, 0);
	if ((errno != 0) || (*end != '\0') || (parsed > 0xFF))
		return -1;

	*out = (BYTE) parsed;
	return 0;
}

static int parseRgbValue(const char* value, DWORD* out)
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
	if ((errno != 0) || (*end != '\0') || (parsed > 0xFFFFFF))
		return -1;

	*out = (DWORD) parsed;
	return 0;
}

static int parseAuthKey(const char* value, BYTE authKey[16])
{
	const char* hex;
	size_t hexLen;
	size_t i;

	if ((value == NULL) || (authKey == NULL))
		return -1;

	hex = skipHexPrefix(value);
	hexLen = strlen(hex);
	if (hexLen != 32)
		return -1;

	for (i = 0; i < 16; i++)
	{
		int high = hexNibble(hex[i * 2]);
		int low = hexNibble(hex[(i * 2) + 1]);

		if ((high < 0) || (low < 0))
			return -1;

		authKey[i] = (BYTE) ((high << 4) | low);
	}

	return 0;
}

static int setCommand(SSCP_TOOL_PARAMS_ST* params, SSCP_TOOL_COMMAND_EN command, const char* programName)
{
	if (params->command != SSCP_TOOL_COMMAND_POLL)
	{
		fprintf(stderr, "Only one command option may be specified\n");
		SSCP_ToolShowUsage(programName);
		return SSCP_TOOL_PARSE_ERROR;
	}

	params->command = command;
	return SSCP_TOOL_PARSE_OK;
}

int SSCP_ToolParseParams(int argc, char** argv, SSCP_TOOL_PARAMS_ST* params)
{
	int opt;

	if (params == NULL)
		return SSCP_TOOL_PARSE_ERROR;

	opterr = 0;
	optind = 1;
	optarg = NULL;
	optopt = 0;

	while ((opt = getopt(argc, argv, "+p:b:a:k:IURB:A:K:h")) != -1)
	{
		switch (opt)
		{
			case 'p':
				if ((optarg == NULL) || (optarg[0] == '\0'))
				{
					fprintf(stderr, "Invalid serial port name\n");
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				params->serialPortName = optarg;
				break;

			case 'b':
				if (parseBitrate(optarg, &params->serialBitrate) != 0)
				{
					fprintf(stderr, "Invalid bitrate '%s'\n", optarg);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				break;

			case 'a':
				if (parseReaderAddress(optarg, &params->readerAddress) != 0)
				{
					fprintf(stderr, "Invalid reader address '%s'\n", optarg);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				break;

			case 'k':
				if (parseAuthKey(optarg, params->authKey) != 0)
				{
					fprintf(stderr, "Invalid authentication key\n");
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				params->hasAuthKey = TRUE;
				break;

			case 'I':
				if (setCommand(params, SSCP_TOOL_COMMAND_INFO, argv[0]) != SSCP_TOOL_PARSE_OK)
					return SSCP_TOOL_PARSE_ERROR;
				break;

			case 'U':
				if (setCommand(params, SSCP_TOOL_COMMAND_OUTPUTS, argv[0]) != SSCP_TOOL_PARSE_OK)
					return SSCP_TOOL_PARSE_ERROR;
				if ((optind + 3) > argc)
				{
					fprintf(stderr, "Option '-U' requires 3 arguments\n");
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				if (parseByteValue(argv[optind], &params->outputLedColor) != 0)
				{
					fprintf(stderr, "Invalid SSCP_Outputs LED color '%s'\n", argv[optind]);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				if (parseByteValue(argv[optind + 1], &params->outputLedDuration) != 0)
				{
					fprintf(stderr, "Invalid SSCP_Outputs LED duration '%s'\n", argv[optind + 1]);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				if (parseByteValue(argv[optind + 2], &params->outputBuzzerDuration) != 0)
				{
					fprintf(stderr, "Invalid SSCP_Outputs buzzer duration '%s'\n", argv[optind + 2]);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				optind += 3;
				break;

			case 'R':
				if (setCommand(params, SSCP_TOOL_COMMAND_OUTPUTS_RGB, argv[0]) != SSCP_TOOL_PARSE_OK)
					return SSCP_TOOL_PARSE_ERROR;
				if ((optind + 3) > argc)
				{
					fprintf(stderr, "Option '-R' requires 3 arguments\n");
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				if (parseRgbValue(argv[optind], &params->outputRgbColor) != 0)
				{
					fprintf(stderr, "Invalid SSCP_OutputsRGB color '%s'\n", argv[optind]);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				if (parseByteValue(argv[optind + 1], &params->outputLedDuration) != 0)
				{
					fprintf(stderr, "Invalid SSCP_OutputsRGB LED duration '%s'\n", argv[optind + 1]);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				if (parseByteValue(argv[optind + 2], &params->outputBuzzerDuration) != 0)
				{
					fprintf(stderr, "Invalid SSCP_OutputsRGB buzzer duration '%s'\n", argv[optind + 2]);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				optind += 3;
				break;

			case 'A':
				if (setCommand(params, SSCP_TOOL_COMMAND_SET_ADDRESS, argv[0]) != SSCP_TOOL_PARSE_OK)
					return SSCP_TOOL_PARSE_ERROR;
				if (parseReaderAddress(optarg, &params->newReaderAddress) != 0)
				{
					fprintf(stderr, "Invalid new reader address '%s'\n", optarg);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				break;

			case 'B':
				if (setCommand(params, SSCP_TOOL_COMMAND_SET_BITRATE, argv[0]) != SSCP_TOOL_PARSE_OK)
					return SSCP_TOOL_PARSE_ERROR;
				if (parseReaderBitrate(optarg, &params->newReaderBitrate) != 0)
				{
					fprintf(stderr, "Invalid new reader bitrate '%s'\n", optarg);
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				break;

			case 'K':
				if (setCommand(params, SSCP_TOOL_COMMAND_SET_KEY, argv[0]) != SSCP_TOOL_PARSE_OK)
					return SSCP_TOOL_PARSE_ERROR;
				if (parseAuthKey(optarg, params->newAuthKey) != 0)
				{
					fprintf(stderr, "Invalid new authentication key\n");
					SSCP_ToolShowUsage(argv[0]);
					return SSCP_TOOL_PARSE_ERROR;
				}
				break;

			case 'h':
				SSCP_ToolShowUsage(argv[0]);
				return SSCP_TOOL_PARSE_HELP;

			case '?':
			default:
				if ((optopt == 'p') || (optopt == 'b') || (optopt == 'a') || (optopt == 'k') || (optopt == 'A') || (optopt == 'B') || (optopt == 'K'))
					fprintf(stderr, "Option '-%c' requires an argument\n", optopt);
				else
					fprintf(stderr, "Unknown option '-%c'\n", optopt);
				SSCP_ToolShowUsage(argv[0]);
				return SSCP_TOOL_PARSE_ERROR;
		}
	}

	if (optind < argc)
	{
		fprintf(stderr, "Unexpected argument '%s'\n", argv[optind]);
		SSCP_ToolShowUsage(argv[0]);
		return SSCP_TOOL_PARSE_ERROR;
	}

	return SSCP_TOOL_PARSE_OK;
}
