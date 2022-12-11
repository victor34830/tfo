/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
** tfo_printf.c for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**
*/

#include "tfo_config.h"


#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#ifndef TFO_PRINTF_TEST
#include <threads.h>
#include <pthread.h>
#endif
#ifdef PER_THREAD_LOGS
#include <rte_lcore.h>
#endif

#include "tfo_printf.h"
#include "tfo_common.h"

#ifdef PRINTF_DEFINED
#undef printf
#undef fprintf
#undef fflush
#undef PRINTF_DEFINED
#endif

#ifdef TFO_PRINTF_TEST
#define DEBUG_PRINT_TO_BUF
#define thread_local
#endif

#ifdef DEBUG_PRINT_TO_BUF
static thread_local char *buf;
static thread_local unsigned head;
static thread_local unsigned tail;
static thread_local size_t size = 2U << 21;
static thread_local bool write_before_overwrite;
#endif

#ifdef PER_THREAD_LOGS
static thread_local FILE *thread_stdout;
#endif

#ifndef TFO_PRINTF_TEST
#if 0
// This is only needed if we can call pthread_cleanup_push()
static void
write_buf_on_exit(__attribute__((unused)) void *p)
{
	tfo_printf_dump(NULL);
}
#endif

#ifdef PER_THREAD_LOGS
void
open_thread_log(const char *template)
{
	char name_buf[(template ? strlen(template) + 4 : 0) + 1];
	const char *dot;
	FILE *fp;

	if (!template) {
		thread_stdout = stdout;
		return;
	}

	if ((dot = strrchr(template, '.')))
		snprintf(name_buf, sizeof(name_buf), "%.*s.%u%s", (int)(dot - template), template, rte_lcore_id(), dot);
	else
		snprintf(name_buf, sizeof(name_buf), "%s.%u", template, rte_lcore_id());

	fp = fopen(name_buf, "a");

	if (!fp) {
		fprintf(stderr, "Failed to open thread stdout '%s' - errno %d (%m)\n", name_buf, errno);
		return;
	}

	thread_stdout = fp;
}
#endif

#ifdef DEBUG_PRINT_TO_BUF
void
tfo_printf_init(size_t buf_size, bool no_overwrite)
{
	if (buf_size)
		size = buf_size;

	buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);

	buf[0] = '\0';

	write_before_overwrite = no_overwrite;

	/* The following doesn't work since pthread_cleanup_push() and pthread_cleanup_pop()
	    have to be paired in the same function which is impossible for us.
	   For now, the application will have to call tfo_printf_dump(). */
/*
	if (no_overwrite)
		pthread_cleanup_push(write_buf_on_exit, NULL);
*/
}
#endif

#else

static void
tfo_printf_init_test(void)
{
	static char my_buf[10240];

	buf = my_buf;
	buf[0] = '\0';
	size = sizeof(my_buf);
}
#endif

#ifdef DEBUG_PRINT_TO_BUF
void
tfo_printf_dump(const char *msg)
{
	const char *eq = "=====================";
	FILE *fp;

#ifdef PER_THREAD_LOGS
	fp = thread_stdout;
#else
	fp = stdout;
#endif

	if (msg)
		fprintf(fp, "\n%s %s %s\n", eq, msg, eq);

	if (tail > head)
		fwrite(buf + head, 1, tail - head, fp);
	else if (tail != head) {
		fwrite(buf + head, 1, size - head, fp);
		fwrite(buf, 1, tail, fp);
	}

	if (msg)
		fprintf(fp, "%s %s end %s\n", eq + 2, msg, eq + 2);

	head = tail = 0;
}

__attribute__((format (printf, 1, 0)))
static int
tfo_vprintf(const char *format, va_list ap)
{
	unsigned len;
	unsigned old_tail = tail;
	const char *s;
	size_t format_len;
	FILE *fp;

#ifdef PER_THREAD_LOGS
	fp = thread_stdout;
#else
	fp = stdout;
#endif

	len = vsnprintf(buf + tail, size - tail, format, ap);

	if (len < size - tail) {
		/* It all fitted */
		tail += len;
		if (old_tail < head && head <= tail)
			head = tail + 1;
	} else if (write_before_overwrite) {
		fwrite(buf, 1, tail, fp);

		len = vsnprintf(buf, size, format, ap);

		tail = len;
	} else {
		char buf_copy[len + 1];

		len = vsnprintf(buf_copy, sizeof(buf_copy), format, ap);

		/* Overwrite the '\0' at the end of the buffer */
		buf[size - 1] = buf_copy[size - tail - 1];

		memcpy(buf, buf_copy + (size - tail - 1) + 1, len - (size - tail - 1));
		tail = len - (size - tail - 1) - 1;

		if (head <= tail)
			head = tail + 1;
	}

	/* If the format starts or ends with "ERROR", we want to
	 * write the buffer */
	s = format;
	if (s[0] == ' ')
		s++;
	if ((!strncmp(s, "ERROR ", 6) && (format_len = strlen(format))) ||
	    ((format_len = strlen(format)) >= 6 &&
	     (!strcmp(format + format_len - 5, "ERROR") || !strcmp(format + format_len - 6, "ERROR\n")))) {
		tfo_printf_dump(NULL);
		if (format[format_len - 1] != '\n')
			fprintf(fp, "\n");
	}

	return len;
}
#endif

__visible int
tfo_printf(const char *format, ...)
{
	va_list args;
	int ret;
	FILE *fp;

	va_start(args, format);

#ifdef DEBUG_PRINT_TO_BUF
	if (buf)
		ret = tfo_vprintf(format, args);
	else
#endif
	{
#ifdef PER_THREAD_LOGS
		fp = thread_stdout ? thread_stdout : stdout;
#else
		fp = stdout;
#endif
		ret = vfprintf(fp, format, args);
	}

	va_end(args);

	return ret;
}

__visible int
tfo_fprintf(FILE *fp, const char *format, ...)
{
	va_list args;
	int ret;

	va_start(args, format);

#ifdef DEBUG_PRINT_TO_BUF
	if (fp == stdout && buf)
		ret = tfo_vprintf(format, args);
	else
#endif
	{
#ifdef PER_THREAD_LOGS
		if (fp == stdout && thread_stdout)
			fp = thread_stdout;
#endif
		ret = vfprintf(fp, format, args);
	}

	va_end(args);

	return ret;
}

__visible int
tfo_fflush(FILE *fp)
{
	if (fp == stdout) {
#ifdef DEBUG_PRINT_TO_BUF
		if (buf)
			return 0;
#endif

#ifdef PER_THREAD_LOGS
		fp = thread_stdout;
#endif
	}

	return fflush(fp);
}

#ifdef TFO_PRINTF_TEST
int main(int argc, char **argv)
{
	char line[71];
	int i;

	tfo_printf_init_test();
	for (i = 0; i < sizeof(line) - 1; i++) {
		if (i < 10)
			line[i] = '0' + i;
		else if (i < 10 + 26)
			line[i] = 'A' - 10 + i;
		else if (i < 10 + 26 + 26)
			line[i] = 'a' - 10 - 26 + i;
		else
			line[i] = '!' - 10 - 26 - 26 + i;
	}
	line[sizeof(line) - 1] = '\0';

	for (i = 0; i < 155; i++) {
		tfo_printf("%3d: %s\n", i, line);

#if 0
		if (tail >= head)
			printf("%s", buf + head);
		else {
			printf("%.*s", size - head, buf + head);
			printf("%s", buf);
		}
		printf("----\n");
#endif

		if (i >= 153) {
			printf("\n=== Start buf dump ===\n");
			tfo_printf_dump(NULL);
			printf("\n=== End buf dump ===\n");
		}
	}
}
#endif
