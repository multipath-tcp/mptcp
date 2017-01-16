#ifndef TESTS_H
#define TESTS_H

#define TEST_ASSERT_VAL(text, cond)					 \
do {									 \
	if (!(cond)) {							 \
		pr_debug("FAILED %s:%d %s\n", __FILE__, __LINE__, text); \
		return -1;						 \
	}								 \
} while (0)

#define TEST_ASSERT_EQUAL(text, val, expected)				 \
do {									 \
	if (val != expected) {						 \
		pr_debug("FAILED %s:%d %s (%d != %d)\n",		 \
			 __FILE__, __LINE__, text, val, expected);	 \
		return -1;						 \
	}								 \
} while (0)

enum {
	TEST_OK   =  0,
	TEST_FAIL = -1,
	TEST_SKIP = -2,
};

struct test {
	const char *desc;
	int (*func)(void);
};

/* Tests */
int test__vmlinux_matches_kallsyms(void);
int test__openat_syscall_event(void);
int test__openat_syscall_event_on_all_cpus(void);
int test__basic_mmap(void);
int test__PERF_RECORD(void);
int test__perf_evsel__roundtrip_name_test(void);
int test__perf_evsel__tp_sched_test(void);
int test__syscall_openat_tp_fields(void);
int test__pmu(void);
int test__attr(void);
int test__dso_data(void);
int test__dso_data_cache(void);
int test__dso_data_reopen(void);
int test__parse_events(void);
int test__hists_link(void);
int test__python_use(void);
int test__bp_signal(void);
int test__bp_signal_overflow(void);
int test__task_exit(void);
int test__sw_clock_freq(void);
int test__code_reading(void);
int test__sample_parsing(void);
int test__keep_tracking(void);
int test__parse_no_sample_id_all(void);
int test__dwarf_unwind(void);
int test__hists_filter(void);
int test__mmap_thread_lookup(void);
int test__thread_mg_share(void);
int test__hists_output(void);
int test__hists_cumulate(void);
int test__switch_tracking(void);
int test__fdarray__filter(void);
int test__fdarray__add(void);
int test__kmod_path__parse(void);
int test__thread_map(void);
int test__llvm(void);
int test__bpf(void);
int test_session_topology(void);

#if defined(__arm__) || defined(__aarch64__)
#ifdef HAVE_DWARF_UNWIND_SUPPORT
struct thread;
struct perf_sample;
int test__arch_unwind_sample(struct perf_sample *sample,
			     struct thread *thread);
#endif
#endif
#endif /* TESTS_H */
