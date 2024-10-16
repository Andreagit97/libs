
#include <libscap/scap.h>
#include <gtest/gtest.h>
#include <sinsp.h>
#include <libsinsp_test_var.h>

class savefile_test : public testing::Test {
public:
	struct safe_scap_event {
		scap_evt* evt;
		safe_scap_event(scap_evt* evt): evt(evt) {}
		~safe_scap_event() {
			if(evt) {
				free(evt);
			}
		}
	};

private:
	// todo!: we use sinsp_evt* because we are at sinsp level but we should move these tests to scap
	// level
	sinsp_evt* get_evt_by_num(uint64_t evt_num) {
		sinsp_evt* evt;
		int ret = SCAP_SUCCESS;
		while(ret != SCAP_EOF) {
			ret = m_inspector->next(&evt);
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error("Error reading event: " + m_inspector->getlasterr());
			}
			if(ret == SCAP_SUCCESS && evt->get_num() == evt_num) {
				return evt;
			}
		}
		return NULL;
	}

	std::unique_ptr<safe_scap_event> _create_event(uint64_t ts,
	                                               uint64_t tid,
	                                               ppm_event_code event_type,
	                                               uint32_t n,
	                                               va_list args) {
		struct scap_sized_buffer event_buf = {NULL, 0};
		size_t event_size = 0;
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		va_list args2;
		va_copy(args2, args);

		int32_t ret =
		        scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);

		if(ret != SCAP_INPUT_TOO_SMALL) {
			va_end(args2);
			throw std::runtime_error("cannot compute the size of the event: " + std::string(error));
		}

		event_buf.buf = malloc(event_size);
		event_buf.size = event_size;

		if(event_buf.buf == NULL) {
			va_end(args2);
			throw std::runtime_error("cannot alloc memory for the event" + std::string(error));
		}

		// Store our buf inside a unique_ptr to avoid memory leaks
		auto p = std::make_unique<safe_scap_event>((scap_evt*)event_buf.buf);

		ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args2);

		if(ret != SCAP_SUCCESS) {
			event_buf.size = 0;
			va_end(args2);
			throw std::runtime_error("cannot encode the event:" + std::string(error));
		}

		p->evt->ts = ts;
		p->evt->tid = tid;

		va_end(args2);
		return p;
	}

protected:
	void open_filepath(const std::string file_path) {
		m_inspector = std::make_unique<sinsp>();
		m_inspector->open_savefile(file_path);
	}

	void open_filename(const std::string file_name) {
		std::string path = LIBSINSP_TEST_SCAP_FILES_DIR + file_name;
		m_inspector = std::make_unique<sinsp>();
		m_inspector->open_savefile(path);
	}

	void assert_event_type_count(ppm_event_code event_type, uint64_t expected_count) {
		sinsp_evt* evt = nullptr;
		int ret = SCAP_SUCCESS;
		uint64_t count = 0;

		while(ret != SCAP_EOF) {
			ret = m_inspector->next(&evt);
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error("Error reading event: " + m_inspector->getlasterr());
			}

			if(evt->get_type() == event_type) {
				count++;
			}
		}
		ASSERT_EQ(count, expected_count);
	}

	void assert_no_event_type(ppm_event_code event_type) {
		sinsp_evt* evt = nullptr;
		int ret = SCAP_SUCCESS;
		while(ret != SCAP_EOF) {
			ret = m_inspector->next(&evt);
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error("Error reading event: " + m_inspector->getlasterr());
			}
			if(evt->get_type() == event_type) {
				FAIL();
			}
		}
	}

	std::unique_ptr<safe_scap_event> create_event(uint64_t ts,
	                                              uint64_t tid,
	                                              ppm_event_code event_type,
	                                              uint32_t n,
	                                              ...) {
		va_list args;
		va_start(args, n);
		auto ret = _create_event(ts, tid, event_type, n, args);
		va_end(args);

		return ret;
	}

	void assert_event_num_equal(uint64_t evt_num, std::unique_ptr<safe_scap_event> expected) {
		// Current event in the scap-file.
		auto curr = get_evt_by_num(evt_num);
		if(!curr) {
			FAIL() << "Event with num (" << evt_num << ") not found in the file";
		}

		char error[SCAP_LASTERR_SIZE] = {'\0'};
		ASSERT_TRUE(scap_compare_events(curr->get_scap_evt(), expected->evt, error)) << error;
	}

	void assert_conversion(enum conversion_result expected_res,
	                       std::unique_ptr<safe_scap_event> evt_to_convert,
	                       std::unique_ptr<safe_scap_event> expected_evt) {
		char error[SCAP_LASTERR_SIZE] = {'\0'};

		auto storage = std::make_unique<safe_scap_event>((scap_evt*)malloc(expected_evt->evt->len));

		// First we check the conversion result matches the expected result
		ASSERT_EQ(scap_convert_event(storage->evt, evt_to_convert->evt, error), expected_res)
		        << "Different conversion results: " << error;

		if(!scap_compare_events(storage->evt, expected_evt->evt, error)) {
			printf("\nExpected event:\n");
			scap_print_event(expected_evt->evt);
			printf("\nConverted event:\n");
			scap_print_event(storage->evt);
			FAIL() << error;
		}
		SUCCEED();
	}

	std::unique_ptr<sinsp> m_inspector;
};
