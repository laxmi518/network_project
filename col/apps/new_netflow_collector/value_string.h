
#ifndef VALUE_STRING_H
#define VALUE_STRING_H

/**
*   @file value_string.h
*   @author Ritesh
*   @brief For converting 2d array to key and value 
*/


/** @brief	Struct for the val_to_str functions */
typedef struct _value_string {
    uint32_t  value;
    const char   *strptr;
} value_string;

/** @brief	Struct for the str_to_str functions */
typedef struct _string_string {
    const char   *value;
    const char   *strptr;
} string_string;

/** @brief	Struct for the rval_to_str functions */
typedef struct _range_string {
    uint32_t        value_min;
    uint32_t        value_max;
    const char   *strptr;
} range_string;

#endif