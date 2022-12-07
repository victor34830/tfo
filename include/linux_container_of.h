/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CONTAINER_OF_H
#define _LINUX_CONTAINER_OF_H

#if 0
#include <linux/build_bug.h>
#include <linux/err.h>
#else
#include <assert.h>
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

#define typeof_member(T, m)	typeof(((T*)0)->m)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#ifdef container_of
#undef container_of
#endif
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wpointer-arith\"") \
	((type *)(__mptr - offsetof(type, member))); \
_Pragma("GCC diagnostic pop") \
		})

#ifndef const_container_of
#define const_container_of(ptr, type, member) ({			\
	const void *__mptr = (const void *)(ptr);			\
	static_assert(__same_type(*(ptr), ((const type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wpointer-arith\"") \
	((const type *)(__mptr - offsetof(type, member))); \
_Pragma("GCC diagnostic pop") \
		})
#endif

#if 0
/**
 * container_of_safe - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 * If IS_ERR_OR_NULL(ptr), ptr is returned unchanged.
 */
#define container_of_safe(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of_safe()");	\
	IS_ERR_OR_NULL(__mptr) ? ERR_CAST(__mptr) :			\
		((type *)(__mptr - offsetof(type, member))); })

#endif

#endif	/* _LINUX_CONTAINER_OF_H */
