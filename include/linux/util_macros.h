/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HELPER_MACROS_H_
#define _LINUX_HELPER_MACROS_H_

/**
 * find_closest - locate the closest element in a sorted array
 * @x: The reference value.
 * @a: The array in which to look for the closest element. Must be sorted
 *  in ascending order.
 * @as: Size of 'a'.
 *
 * Returns the index of the element closest to 'x'.
 * Note: If using an array of negative numbers (or mixed positive numbers),
 *       then be sure that 'x' is of a signed-type to get good results.
 */
#define find_closest(x, a, as)						\
({									\
	typeof(as) __fc_i, __fc_as = (as) - 1;				\
	long __fc_mid_x, __fc_x = (x);					\
	long __fc_left, __fc_right;					\
	typeof(*a) const *__fc_a = (a);					\
	for (__fc_i = 0; __fc_i < __fc_as; __fc_i++) {			\
		__fc_mid_x = (__fc_a[__fc_i] + __fc_a[__fc_i + 1]) / 2;	\
		if (__fc_x <= __fc_mid_x) {				\
			__fc_left = __fc_x - __fc_a[__fc_i];		\
			__fc_right = __fc_a[__fc_i + 1] - __fc_x;	\
			if (__fc_right < __fc_left)			\
				__fc_i++;				\
			break;						\
		}							\
	}								\
	(__fc_i);							\
})

/**
 * find_closest_descending - locate the closest element in a sorted array
 * @x: The reference value.
 * @a: The array in which to look for the closest element. Must be sorted
 *  in descending order.
 * @as: Size of 'a'.
 *
 * Similar to find_closest() but 'a' is expected to be sorted in descending
 * order. The iteration is done in reverse order, so that the comparison
 * of '__fc_right' & '__fc_left' also works for unsigned numbers.
 */
#define find_closest_descending(x, a, as)				\
({									\
	typeof(as) __fc_i, __fc_as = (as) - 1;				\
	long __fc_mid_x, __fc_x = (x);					\
	long __fc_left, __fc_right;					\
	typeof(*a) const *__fc_a = (a);					\
	for (__fc_i = __fc_as; __fc_i >= 1; __fc_i--) {			\
		__fc_mid_x = (__fc_a[__fc_i] + __fc_a[__fc_i - 1]) / 2;	\
		if (__fc_x <= __fc_mid_x) {				\
			__fc_left = __fc_x - __fc_a[__fc_i];		\
			__fc_right = __fc_a[__fc_i - 1] - __fc_x;	\
			if (__fc_right < __fc_left)			\
				__fc_i--;				\
			break;						\
		}							\
	}								\
	(__fc_i);							\
})

#endif
