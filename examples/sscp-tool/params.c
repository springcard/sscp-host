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
	fprintf(stderr, "Usage: %s [-p serial_port] [-b bitrate]\n", programName);
	fprintf(stderr, "  -p serial_port  Serial port name (default: COM8 on Windows, /dev/ttyUSB0 otherwise)\n");
	fprintf(stderr, "  -b bitrate      Connection bitrate: 9600, 38400, or 115200 (default: 38400)\n");
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

int SSCP_ToolParseParams(int argc, char** argv, SSCP_TOOL_PARAMS_ST* params)
{
	int opt;

	if (params == NULL)
		return SSCP_TOOL_PARSE_ERROR;

	opterr = 0;
	while ((opt = getopt(argc, argv, "p:b:h")) != -1)
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

			case 'h':
				SSCP_ToolShowUsage(argv[0]);
				return SSCP_TOOL_PARSE_HELP;

			case '?':
			default:
				if ((optopt == 'p') || (optopt == 'b'))
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
