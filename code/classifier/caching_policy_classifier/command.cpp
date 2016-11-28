#include "command.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstring>
#include <iostream>

#ifdef WIN32
#include <Windows.h>
#endif

int command(std::string cmd, std::function<void(const std::string&)> callback/*=nullptr*/)
{
#ifdef WIN32
	// Disable file system redirection
	PVOID OldValue = NULL;
	if (!Wow64DisableWow64FsRedirection(&OldValue))
	{
		std::cerr << "Error: Failed to disable x64 filesystem redirection" << std::endl;
		return -1;
	}

	auto pipe = _popen(cmd.c_str(), "rt");

	//  Immediately re-enable redirection. Note that any resources
	//  associated with OldValue are cleaned up by this call.
	if (FALSE == Wow64RevertWow64FsRedirection(OldValue))
	{
		//  Failure to re-enable redirection should be considered
		//  a criticial failure and execution aborted.
		std::cerr << "Error: Failed to revert x64 filesystem redirection" << std::endl;
		return -1;
	}

#else
	auto pipe = popen(cmd.c_str(), "r");
#endif

	if (pipe == NULL)
	{
		return -1;
	}

	/* Read pipe until end of file, or an error occurs. */
	char buffer[128];
	while (fgets(buffer, 128, pipe))
	{
		auto line = std::string{ buffer };

		if (callback)
		{
			callback(line);
		}
		else
		{
			// TODO: uncomment?
			//std::cout << line << std::endl;
		}
	}

	/* Close pipe and print return value of pipe. */
	if (std::feof(pipe))
	{
#ifdef WIN32
		_pclose(pipe);
#else
		pclose(pipe);
#endif
	}
	else
	{
		std::cerr << "Error: Failed to read the pipe to the end" << std::endl;
	}

	return 0;
}