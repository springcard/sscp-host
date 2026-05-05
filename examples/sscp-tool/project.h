#ifndef SSCP_TOOL_PROJECT_H
#define SSCP_TOOL_PROJECT_H

/**
 * @file project.h
 * @brief Shared declarations for the sscp-tool example.
 */

#include <sscp-host.h>

#define SSCP_TOOL_PARSE_OK 0
#define SSCP_TOOL_PARSE_HELP 1
#define SSCP_TOOL_PARSE_ERROR (-1)

/**
 * Command-line configuration for the SSCP tool example.
 *
 * The strings stored here point either to static defaults or to argv entries.
 * They must therefore be used while argv is still alive.
 */
typedef struct
{
	const char* serialPortName;
	DWORD serialBitrate;
	BYTE readerAddress;
	BYTE authKey[16];
	BOOL hasAuthKey;
} SSCP_TOOL_PARAMS_ST;

/**
 * Fill the parameter structure with the platform defaults used by the tool.
 */
void SSCP_ToolInitParams(SSCP_TOOL_PARAMS_ST* params);

/**
 * Parse command-line options and update the provided parameter structure.
 *
 * @return SSCP_TOOL_PARSE_OK on success, SSCP_TOOL_PARSE_HELP when usage was
 *         printed on request, or SSCP_TOOL_PARSE_ERROR on invalid input.
 */
int SSCP_ToolParseParams(int argc, char** argv, SSCP_TOOL_PARAMS_ST* params);

/**
 * Print the command-line usage for the tool.
 */
void SSCP_ToolShowUsage(const char* programName);

#endif
