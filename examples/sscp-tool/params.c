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
	fprintf(stderr, "Usage: %s [-p serial_port] [-b bitrate] [-a address] [-k auth_key]\n", programName);
	fprintf(stderr, "  -p serial_port  Serial port name (default: COM8 on Windows, /dev/ttyUSB0 otherwise)\n");
	fprintf(stderr, "  -b bitrate      Connection bitrate: 9600, 38400, or 115200 (default: 38400)\n");
	fprintf(stderr, "  -a address      Reader address in hexadecimal, from 0x00 to 0x7F (default: 0x01)\n");
	fprintf(stderr, "  -k auth_key     Authentication key as 16 hexadecimal bytes, optionally prefixed with 0x\n");
	fprintf(stderr, "  -h              Show this help\n");
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
	unsigned long parsed;

	if ((value == NULL) || (*value == '\0') || (out == NULL))
		return -1;

	errno = 0;
	parsed = strtoul(value, &end, 16);
	if ((errno != 0) || (*end != '\0') || (parsed > 0x7F))
		return -1;

	*out = (BYTE) parsed;
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

int SSCP_ToolParseParams(int argc, char** argv, SSCP_TOOL_PARAMS_ST* params)
{
	int opt;

	if (params == NULL)
		return SSCP_TOOL_PARSE_ERROR;

	opterr = 0;
	optind = 1;
	optarg = NULL;
	optopt = 0;

	while ((opt = getopt(argc, argv, "p:b:a:k:h")) != -1)
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

			case 'h':
				SSCP_ToolShowUsage(argv[0]);
				return SSCP_TOOL_PARSE_HELP;

			case '?':
			default:
				if ((optopt == 'p') || (optopt == 'b') || (optopt == 'a') || (optopt == 'k'))
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
