/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#pragma once

/* Advanced capture options */
#define RW_SNAPLEN_EVENT 4096
#define DPI_LOOKAHEAD_SIZE 16
#define PPM_NULL_RDEV MKDEV(1, 3)
#define PPM_PORT_MYSQL 3306
#define PPM_PORT_POSTGRES 5432
#define PPM_PORT_STATSD 8125
#define PPM_PORT_MONGODB 27017

/* Convert seconds to nanoseconds */
#define SECOND_TO_NS 1000000000
