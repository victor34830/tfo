/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
** tfo_printf.c for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#ifndef TFO_PRINTF_TEST
#include <pthread.h>
#endif

#include "tfo_printf.h"

#ifdef TFO_PRINTF_TEST
#define thread_local
#else
#define thread_local __thread
#endif

static thread_local char *buf;
static thread_local unsigned head;
static thread_local unsigned tail;
static thread_local size_t size = 2U << 21;
static thread_local bool write_before_overwrite;

#ifndef TFO_PRINTF_TEST
#if 0
// This is only needed if we can call pthread_cleanup_push()
static void
write_buf_on_exit(__attribute__((unused)) void *p)
{
	tfo_printf_dump();
}
#endif

void
tfo_printf_init(size_t buf_size, bool no_overwrite)
{
	if (buf_size)
		size = buf_size;

	buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
fprintf(stderr, "mmap buf %p, size %zu\n", buf, size);

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

int
tfo_printf(const char *format, ...)
{
	unsigned len;
	va_list args;
	unsigned old_tail = tail;
	int ret;

	va_start(args, format);

	if (!buf) {
		ret = vprintf(format, args);
		va_end(args);
		return ret;
	}

	len = vsnprintf(buf + tail, size - tail, format, args);
	va_end(args);

	if (len < size - tail) {
		/* It all fitted */
		tail += len;
		if (old_tail < head && head <= tail)
			head = tail + 1;
	} else if (write_before_overwrite) {
		fwrite(buf, 1, tail, stdout);

		va_start(args, format);
		len = vsnprintf(buf, size, format, args);
		va_end(args);

		tail = len;
	} else {
		char buf_copy[len + 1];

		va_start(args, format);
		len = vsnprintf(buf_copy, sizeof(buf_copy), format, args);
		va_end(args);

		/* Overwrite the '\0' at the end of the buffer */
		buf[size - 1] = buf_copy[size - tail - 1];

		memcpy(buf, buf_copy + (size - tail - 1) + 1, len - (size - tail - 1));
		tail = len - (size - tail - 1) - 1;

		if (head <= tail)
			head = tail + 1;
	}

	return len;
}

void
tfo_printf_dump(const char *msg)
{
	static char eq[] = "==============================";

	if (msg)
		printf("\n%s %s %s\n", eq, buf, eq);

	if (tail > head)
		fwrite(buf + head, 1, tail - head, stdout);
	else if (tail != head) {
		fwrite(buf + head, 1, size - head, stdout);
		fwrite(buf, 1, tail, stdout);
	}

	if (msg)
		printf("%s %s end %s\n", eq + 2, buf, eq + 2);

	head = tail = 0;
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
			tfo_printf_dump();
			printf("\n=== End buf dump ===\n");
		}
	}
}
#endif
