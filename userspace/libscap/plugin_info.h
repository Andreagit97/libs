/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <stdbool.h>

//
// This file contains the prototype and type definitions of sinsp/scap plugins
//

//
// API versions of this plugin engine
//
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0
#define PLUGIN_API_VERSION_PATCH 0

//
// There are two plugin types: source plugins and extractor plugins.
//
// Source plugins implement a new sinsp/scap event source and have the
// ability to provide events to the event loop. Optionally, they can
// extract fields from events so they can be displayed/used in
// filters.
//
// Extractor plugins do not provide events, but have the ability to
// extract fields from events created by other plugins. A good example
// of an extractor plugin is a json extractor, which can extract
// information from any json payload, regardless of where the payloads
// come from.
//
typedef enum ss_plugin_type
{
	TYPE_SOURCE_PLUGIN = 1,
	TYPE_EXTRACTOR_PLUGIN = 2
}ss_plugin_type;

typedef bool (*cb_wait_t)(void* wait_ctx);

typedef struct async_extractor_info
{
	uint64_t evtnum;
	uint32_t ftype;
	const char *field;
	const char* arg;
	uint8_t* data;
	uint32_t datalen;
	uint32_t field_present;
	char* res_str;
	uint64_t res_u64;
	int32_t rc;
	cb_wait_t cb_wait;
	void* wait_ctx;
} async_extractor_info;

// This struct represents an event returned by the plugin, and is used
// below in next()/next_batch().
// - data: pointer to a memory buffer pointer. The plugin will set it
//   to point to the memory containing the next event. Once returned,
//   the memory is owned by the plugin framework and will be freed via
//   a call to free().
// - datalen: pointer to a 32bit integer. The plugin will set it the size of the
//   buffer pointed by data.
// - ts: the event timestamp. Can be (uint64_t)-1, in which case the engine will
//   automatically fill the event time with the current time.
typedef struct ss_plugin_event
{
	uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_event;

//
// This is the opaque pointer to the state of a plugin.
// It points to any data that might be needed plugin-wise. It is
// allocated by init() and must be destroyed by destroy().
// It is defined as void because the engine doesn't care what it is
// and it treats is as opaque.
//
typedef void ss_plugin_t;

//
// This is the opaque pointer to the state of an open instance of the source
// plugin.
// It points to any data that is needed while a capture is running. It is
// allocated by open() and must be destroyed by close().
// It is defined as void because the engine doesn't care what it is
// and it treats is as opaque.
//
typedef void ss_instance_t;

//
// Interface for a sinsp/scap source plugin
//
//
// NOTE: For all functions below that return a char *, the memory
// pointed to by the char * must be allocated by the plugin using
// malloc() and should be freed by the caller using free().
//
// For each function below, the exported symbol from the dynamic
// library should have a prefix of "plugin_"
// (e.g. plugin_get_required_api_version, plugin_init, etc.)
//
typedef struct
{
	//
	// Return the version of the plugin API used by this plugin.
	// Required: yes
	// Return value: the API version string, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// NOTE: to ensure correct interoperability between the engine and the plugins,
	//       we use a semver approach. Plugins are required to specify the version
	//       of the API they run against, and the engine will take care of checking
	//       and enforcing compatibility.
	//
	char* (*get_required_api_version)();
	//
	// Return the plugin type.
	// Required: yes
	// Should return TYPE_SOURCE_PLUGIN. It still makes sense to
	// have a function get_type() as the plugin interface will
	// often dlsym() functions from shared libraries, and can't
	// inspect any C struct type.
	//
	uint32_t (*get_type)();
	//
	// Initialize the plugin and, if needed, allocate its state.
	// Required: yes
	// Arguments:
	// - config: a string with the plugin configuration. The format of the
	//   string is chosen by the plugin itself.
	// - rc: pointer to an integer that will contain the initialization result,
	//   as a SCAP_* value (e.g. SCAP_SUCCESS=0, SCAP_FAILURE=1)
	// Return value: pointer to the plugin state that will be treated as opaque
	//   by the engine and passed to the other plugin functions.
	//   If rc is SCAP_FAILURE, this function should return NULL.
	//
	ss_plugin_t* (*init)(char* config, int32_t* rc);
	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	// Required: yes
	//
	void (*destroy)(ss_plugin_t* s);
	//
	// Return a string with the error that was last generated by
	// the plugin.
        // Required: yes
	//
	// In cases where any other api function returns an error, the
	// plugin should be prepared to return a human-readable error
	// string with more context for the error. The plugin manager
	// calls get_last_error() to access that string.
	//
	char* (*get_last_error)(ss_plugin_t* s);
	//
	// Return the unique ID of the plugin.
	// Required: yes
	// EVERY SOURCE PLUGIN (see get_type()) MUST OBTAIN AN OFFICIAL ID FROM THE
	// FALCOSECURITY ORGANIZATION, OTHERWISE IT WON'T PROPERLY COEXIST WITH OTHER PLUGINS.
	//
	uint32_t (*get_id)();
	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	char* (*get_name)();
	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	// Required: yes
	//
	char* (*get_description)();
	//
	// Return a string containing contact info (url, email, twitter, etc) for
	// the plugin authors.
	// Required: yes
	//
	char* (*get_contact)();
	//
	// Return the version of this plugin itself
	// Required: yes
	// Return value: a string with a version identifier, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// This differs from the api version in that this versions the
	// plugin itself, as compared to the plugin interface. When
	// reading capture files, the major version of the plugin that
	// generated events must match the major version of the plugin
	// used to read events.
	//
	char* (*get_version)();
	//
	// Return a string describing the events generated by this source plugin.
	// Required: yes
	// Example event sources would be strings like "syscall",
	// "k8s_audit", etc.  The source can be used by extractor
	// plugins to filter the events they receive.
	//
	char* (*get_event_source)();
	//
	// Return the list of extractor fields exported by this plugin. Extractor
	// fields can be used in Falco rule conditions and sysdig filters.
	// Required: no
	// Return value: a string with the list of fields encoded as a json
	//   array.
	//   Each field entry is a json object with the following properties:
	//     "type": one of "string", "uint64"
	//     "name": a string with a name for the field
	//     "desc": a string with a description of the field
	// Example return value:
	// [
	//    {"type": "string", "name": "field1", "desc": "Describing field 1"},
	//    {"type": "uint64", "name": "field2", "desc": "Describing field 2"}
	// ]
	char* (*get_fields)();
	//
	// Open the source and start a capture.
	// Required: yes
	// Arguments:
	// - s: the plugin state returned by init()
	// - params: the open parameters, as a string. The format is defined by the plugin
	//   itsef
	// - rc: pointer to an integer that will contain the open result, as a SCAP_* value
	//   (e.g. SCAP_SUCCESS=0, SCAP_FAILURE=1)
	// Return value: a pointer to the open context that will be passed to next(),
	//   close(), event_to_string() and extract_*.
	//
	ss_instance_t* (*open)(ss_plugin_t* s, char* params, int32_t* rc);
	//
	// Close a capture.
	// Required: yes
	// Arguments:
	// - s: the plugin context, returned by init(). Can be NULL.
	// - h: the capture context, returned by open(). Can be NULL.
	//
	void (*close)(ss_plugin_t* s, ss_instance_t* h);
	//
	// Return the next event.
	// Required: yes
	// Arguments:
	// - s: the plugin context, returned by init(). Can be NULL.
	// - h: the capture context, returned by open(). Can be NULL.
	//
        // - evt: pointer to a ss_plugin_event pointer. The plugin should
        //   allocate a ss_plugin_event struct using malloc(), as well as
	//   allocate the data buffer within the ss_plugin_event struct.
	//   Both the struct and data buffer are owned by the plugin framework
	//   and will free them using free().
	//
	// Return value: the status of the operation (e.g. SCAP_SUCCESS=0, SCAP_FAILURE=1,
	//   SCAP_TIMEOUT=-1)
	//
	int32_t (*next)(ss_plugin_t* s, ss_instance_t* h, ss_plugin_event **evt);
	//
	// Return the read progress.
	// Required: no
	// Arguments:
	// - progress_pct: the read progress, as a number between 0 (no data has been read)
	//   and 10000 (100% of the data has been read). This encoding allows the engine to
	//   print progress decimals without requiring to deal with floating point numbers
	//   (which could cause incompatibility problems with some languages).
	// Return value: a string representation of the read
	//   progress. This might include the progress percentage
	//   combined with additional context added by the plugin. If
	//   NULL, progress_pct should be used.
	// NOTE: reporting progress is optional and in some case could be impossible. However,
	//       when possible, it's recommended as it provides valuable information to the
	//       user.
	//
	char* (*get_progress)(ss_plugin_t* s, ss_instance_t* h, uint32_t* progress_pct);
	//
	// Return a text representation of an event generated by this source plugin.
	// Required: yes
	// Arguments:
	// - data: the buffer from an event produced by next().
	// - datalen: the length of the buffer from an event produced by next().
	// Return value: the text representation of the event. This is used, for example,
	//   by sysdig to print a line for the given event.
	//
	char *(*event_to_string)(ss_plugin_t *s, const uint8_t *data, uint32_t datalen);
	//
	// Extract a filter field value from an event.
	// We offer multiple versions of extract(), differing from each other only in
	// the type of the value they return (string, integer...).
	// Required: no
	// Arguments:
	// - evtnum: the number of the event that is bein processed
	// - id: the numeric identifier of the field to extract. It corresponds to the
	//   position of the field in the array returned by get_fields().
	// - arg: the field argument, if an argument has been specified for the field,
	//   otherwise it's NULL. For example:
	//    * if the field specified by the user is foo.bar[pippo], arg will be the
	//      string "pippo"
	//    * if the field specified by the user is foo.bar, arg will be NULL
	// - data: the buffer produced by next().
	// - datalen: the length of the buffer produced by next().
	// - field_present: nonzero if the field is present for the given event.
	// Return value: the produced value of the filter field. For extract_str(), a
	//   NULL return value means that the field is missing for the given event.
	//
	char *(*extract_str)(ss_plugin_t *s, uint64_t evtnum, const char * field, const char *arg, uint8_t *data, uint32_t datalen);
	uint64_t (*extract_u64)(ss_plugin_t *s, uint64_t evtnum, const char *field, const char *arg, uint8_t *data, uint32_t datalen, uint32_t *field_present);
	//
	// This is an optional, internal, function used to speed up event capture by
	// batching the calls to next().
	// On success:
	//   - nevts will be filled in with the number of events.
        //   - evts: pointer to an ss_plugin_event pointer. The plugin should
        //     allocate an array of contiguous ss_plugin_event structs using malloc(),
	//     as well as allocate each data buffer within each ss_plugin_event
	//     struct using malloc(). Both the array of structs and each data buffer are
	//     owned by the plugin framework and will free them using free().
	// Required: no
	//
	int32_t (*next_batch)(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts);
	//
	// This is an optional, internal, function used to speed up value extraction
	// Required: no
	//
	int32_t (*register_async_extractor)(ss_plugin_t *s, async_extractor_info *info);

	//
	// The following members are PRIVATE for the engine and should not be touched.
	//
	ss_plugin_t* state;
	ss_instance_t* handle;
	uint32_t id;
	char *name;
} source_plugin_info;

//
// Interface for a sinsp/scap extractor plugin
//
//
// NOTE: For all functions below that return a char *, the memory
// pointed to by the char * must be allocated by the plugin using
// malloc() and should be freed by the caller using free().
//
typedef struct
{
	//
	// Return the version of the plugin API used by this plugin.
	// Required: yes
	// Return value: the API version string, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// NOTE: to ensure correct interoperability between the engine and the plugins,
	//       we use a semver approach. Plugins are required to specify the version
	//       of the API they run against, and the engine will take care of checking
	//       and enforcing compatibility.
	//
	char* (*get_required_api_version)();
	//
	// Return the plugin type.
	// Required: yes
	// Should return TYPE_EXTRACTOR_PLUGIN. It still makes sense to
	// have a function get_type() as the plugin interface will
	// often dlsym() functions from shared libraries, and can't
	// inspect any C struct type.
	//
	uint32_t (*get_type)();
	//
	// Initialize the plugin and, if needed, allocate its state.
	// Required: yes
	// Arguments:
	// - config: a string with the plugin configuration. The format of the
	//   string is chosen by the plugin itself.
	// - rc: pointer to an integer that will contain the initialization result,
	//   as a SCAP_* value (e.g. SCAP_SUCCESS=0, SCAP_FAILURE=1)
	// Return value: pointer to the plugin state that will be treated as opaque
	//   by the engine and passed to the other plugin functions.
	//
	ss_plugin_t* (*init)(char* config, int32_t* rc);
	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	// Required: yes
	//
	void (*destroy)(ss_plugin_t* s);
	//
	// Return a string with the error that was last generated by
	// the plugin.
        // Required: yes
	//
	// In cases where any other api function returns an error, the
	// plugin should be prepared to return a human-readable error
	// string with more context for the error. The plugin manager
	// calls get_last_error() to access that string.
	//
	char* (*get_last_error)(ss_plugin_t* s);
	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	char* (*get_name)();
	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	// Required: yes
	//
	char* (*get_description)();
	//
	// Return a string containing contact info (url, email, twitter, etc) for
	// the plugin author.
	// Required: yes
	//
	char* (*get_contact)();
	//
	// Return the version of this plugin itself
	// Required: yes
	// Return value: a string with a version identifier, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// This differs from the api version in that this versions the
	// plugin itself, as compared to the plugin interface. When
	// reading capture files, the major version of the plugin that
	// generated events must match the major version of the plugin
	// used to read events.
	//
	char* (*get_version)();
	//
	// Return a string describing the event sources that this
	// extractor plugin can consume.
	// Required: no
	// Return value: a json array of strings containing event
	//   sources returned by a source plugin's get_event_source()
	//   function.
	// This function is optional--if NULL then the exctractor
	// plugin will receive every event.
	//
	char* (*get_extract_event_sources)();
	//
	// Return the list of extractor fields exported by this plugin. Extractor
	// fields can be used in Falco rules and sysdig filters.
	// Required: yes
	// Return value: a string with the list of fields encoded as a json
	//   array.
	//
	char* (*get_fields)();
	//
	// Extract a filter field value from an event.
	// We offer multiple versions of extract(), differing from each other only in
	// the type of the value they return (string, integer...).
	// Required: for plugins of type TYPE_EXTRACTOR_PLUGIN only
	// Arguments:
	// - evtnum: the number of the event that is being processed
	// - id: the numeric identifier of the field to extract. It corresponds to the
	//   position of the field in the array returned by get_fields().
	// - arg: the field argument, if an argument has been specified for the field,
	//   otherwise it's NULL. For example:
	//    * if the field specified by the user is foo.bar[pippo], arg will be the
	//      string "pippo"
	//    * if the field specified by the user is foo.bar, arg will be NULL
	// - data: the buffer produced by next().
	// - datalen: the length of the buffer produced by next().
	// - field_present: nonzero if the field is present for the given event.
	// Return value: the produced value of the filter field. For extract_str(), a
	// NULL return value means that the field is missing for the given event.
	//
	char *(*extract_str)(ss_plugin_t *s, uint64_t evtnum, const char *field, const char *arg, uint8_t *data, uint32_t datalen);
	uint64_t (*extract_u64)(ss_plugin_t *s, uint64_t evtnum, const char *field, const char *arg, uint8_t *data, uint32_t datalen, uint32_t *field_present);
} extractor_plugin_info;
