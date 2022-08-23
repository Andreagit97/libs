#include "../../event_class/event_class.h"

#if defined(__NR_accept) && defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

TEST(SyscallExit, acceptX_INET)
{
	auto evt_test = new event_test(__NR_accept, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create the server socket. */
	int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	struct sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, server_socket_fd, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	struct sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	int connected_socket_fd = syscall(__NR_accept, server_socket_fd, NULL, NULL);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, connected_socket_fd, 2);
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, connected_socket_fd);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)connected_socket_fd);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The server performs an `accept` so the `client` is the src. */
	evt_test->assert_tuple_inet_param(2, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	/* we expect 0 elements in the queue so 0%. */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	/* we expect 0 elements. */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)QUEUE_LENGTH);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, acceptX_INET6)
{
	auto evt_test = new event_test(__NR_accept, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create the server socket. */
	int32_t server_socket_fd = syscall(__NR_socket, AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	struct sockaddr_in6 server_addr;
	evt_test->server_fill_sockaddr_in6(&server_addr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, server_socket_fd, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET6, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	struct sockaddr_in6 client_addr;
	evt_test->client_fill_sockaddr_in6(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	int connected_socket_fd = syscall(__NR_accept, server_socket_fd, NULL, NULL);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, connected_socket_fd, 2);
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, connected_socket_fd);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)connected_socket_fd);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The server performs an `accept` so the `client` is the src. */
	evt_test->assert_tuple_inet6_param(2, PPM_AF_INET6, IPV6_CLIENT, IPV6_SERVER, IPV6_PORT_CLIENT_STRING, IPV6_PORT_SERVER_STRING);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	/* we expect 0 elements in the queue so 0%. */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	/* we expect 0 elements. */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)QUEUE_LENGTH);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#ifdef __NR_unlinkat
TEST(SyscallExit, acceptX_UNIX)
{
	auto evt_test = new event_test(__NR_accept, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create the server socket. */
	int32_t server_socket_fd = syscall(__NR_socket, AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);

	struct sockaddr_un server_addr;
	evt_test->server_fill_sockaddr_un(&server_addr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, server_socket_fd, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	int32_t client_socket_fd = syscall(__NR_socket, AF_UNIX, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);

	struct sockaddr_un client_addr;
	evt_test->client_fill_sockaddr_un(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	int connected_socket_fd = syscall(__NR_accept, server_socket_fd, NULL, NULL);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

	/* In unix sockets the maximum queue length seems to be 512. */
	FILE *f = fopen("/proc/sys/net/unix/max_dgram_qlen", "r");
	if(f == NULL)
	{
		FAIL() << "'fopen' must not fail." << std::endl;
	}
	int unix_max_queue_len = 0;
	if(fscanf(f, "%d", &unix_max_queue_len) != 1)
	{
		fclose(f);
		FAIL() << "'fscanf' must not fail." << std::endl;
	}
	fclose(f);

	/* Cleaning phase */
	syscall(__NR_shutdown, connected_socket_fd, 2);
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, connected_socket_fd);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);
	syscall(__NR_unlinkat, 0, UNIX_CLIENT, 0);
	syscall(__NR_unlinkat, 0, UNIX_SERVER, 0);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)connected_socket_fd);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The server performs an `accept` so the `client` is the src. */
	evt_test->assert_tuple_unix_param(2, PPM_AF_UNIX, UNIX_SERVER);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	/* we expect 0 elements in the queue so 0%. */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	/* we expect 0 elements. */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)unix_max_queue_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif /* __NR_unlinkat */

TEST(SyscallExit, acceptX_failure)
{
	auto evt_test = new event_test(__NR_accept, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mock_fd = -1;
	struct sockaddr *addr = NULL;
	socklen_t *addrlen = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "accept", syscall(__NR_accept, mock_fd, addr, addrlen));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(2);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif
