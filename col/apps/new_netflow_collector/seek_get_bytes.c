/**
*   @file seek_get_bytes.c
*   @author Ritesh
*   @brief Converts the given pointer to corresponding unsigned int 
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "seek_get_bytes.h"
#include "pint.h"

/** 
*   @brief  Ensures the buffer doesnot overflows and the data is available for next byte
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     NULL/next_pointer
*/
static const uint8_t *ensure_contiguous(void *buf, const int offset, int length, int total_len) {
	int start_offset, end_offset;
    
	if (offset < 0) {
        return NULL;
	}
    
	start_offset = offset;
	end_offset = start_offset + length;
    
	if (end_offset <= total_len) {
		return buf + offset;
	}
    
	return NULL;
}

/** 
*   @brief  Process 1 byte of data
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     uint8_t
*/
uint8_t get_unit(void *buf, const int offset, int len) {
    const uint8_t *ptr;
	ptr = ensure_contiguous(buf, offset, sizeof(uint8_t), len);
	return *ptr;
}

/** 
*   @brief  Process 2 bytes of data
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     uint16_t (short int)
*/
uint16_t get_ntohs(void *buf, const int offset, int len) {
//    printf("Inside get ntohs %d %lud %d\n", offset, sizeof(uint16_t), len);
    const uint8_t *ptr;
    ptr = ensure_contiguous(buf, offset, sizeof(uint16_t), len);
    return pntohs(ptr);
}

/** 
*   @brief  Process 3 bytes of data
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     uint32_t    (int)
*/
uint32_t get_ntoh24(void *buf, const int offset, int len) {
//    printf("Inside get ntoh24 %d %lud %d\n", offset, 3, len);
    const uint8_t *ptr;
    ptr = ensure_contiguous(buf, offset, 3, len);
    return pntoh24(ptr);
}

/** 
*   @brief  Process 4 bytes of data
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     uint32_t    (int)
*/
uint32_t get_ntohl(void *buf, const int offset, int len) {
//    printf("Inside get ntohl %d %lud %d\n", offset, sizeof(uint32_t), len);
    const uint8_t *ptr;
    ptr = ensure_contiguous(buf, offset, sizeof(uint32_t), len);
    return pntohl(ptr);
}

/** 
*   @brief  Process 5 bytes of data
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     uint64_t    (long)
*/
uint64_t get_ntoh40(void *buf, const int offset, int len) {
//    printf("Inside get ntoh40 %d %lud %d\n", offset, 5, len);
    const uint8_t *ptr;
    ptr = ensure_contiguous(buf, offset, 5, len);
    return pntoh40(ptr);
}

/** 
*   @brief  Process 6 bytes of data
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     uint64_t    (long)
*/
uint64_t get_ntoh48(void *buf, const int offset, int len) {
//    printf("Inside get ntoh48 %d %lud %d\n", offset, 6, len);
    const uint8_t *ptr;
    ptr = ensure_contiguous(buf, offset, 6, len);
    return pntoh48(ptr);
}

/** 
*   @brief  Process 7 bytes of data
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     uint64_t    (long)
*/
uint64_t get_ntoh56(void *buf, const int offset, int len) {
//    printf("Inside get ntoh56 %d %lud %d\n", offset, 7, len);
    const uint8_t *ptr;
    ptr = ensure_contiguous(buf, offset, 7, len);
    return pntoh56(ptr);
}

/** 
*   @brief  Process 8 bytes of data
*   @param[in]  buf     pointer
*   @param[in]  offset  index from where data is be read
*   @param[in]  length  total length available
*   @return     uint64_t    (long)
*/
uint64_t get_ntoh64(void *buf, const int offset, int len) {
//    printf("Inside get ntoh64 %d %lud %d\n", offset, 8, len);
    const uint8_t *ptr;
    ptr = ensure_contiguous(buf, offset, 8, len);
    return pntoh64(ptr);
}

//long double get_ntoh128(void *buf, const int offset, int len) {
//    //    printf("Inside get ntoh64 %d %lud %d\n", offset, 8, len);
//    const uint8_t *ptr;
//    ptr = ensure_contiguous(buf, offset, 16, len);
//    return pntoh128(ptr);
//}

