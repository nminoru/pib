/*
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include "pibnetd.h"


void __pib_report_info(const char *filename, int lineno, const char *format, ...)
{
	int ret;
	va_list arg;
	char buffer[1024];

	va_start(arg, format);
	ret = vsprintf(buffer, format, arg);
	va_end(arg);

	sprintf(buffer + ret, "\n");

	fputs(buffer, stdout);
	fflush(stdout);

	syslog(LOG_INFO, buffer);
}


void __pib_report_debug(const char *filename, int lineno, const char *format, ...)
{
	int ret;
	va_list arg;
	char buffer[1024];

	va_start(arg, format);
	ret = vsprintf(buffer, format, arg);
	va_end(arg);

	sprintf(buffer + ret, " at %s(%u)\n", filename, lineno);

	fputs(buffer, stdout);
	fflush(stdout);

	syslog(LOG_INFO, buffer);
}


void __pib_report_err(const char *filename, int lineno, const char *format, ...)
{
	int ret;
	va_list arg;
	char buffer[1024];

	va_start(arg, format);
	ret = vsprintf(buffer, format, arg);
	va_end(arg);

	sprintf(buffer + ret, " at %s(%u)\n", filename, lineno);

	fputs(buffer, stderr);
	fflush(stderr);

	syslog(LOG_ERR, buffer);
}
