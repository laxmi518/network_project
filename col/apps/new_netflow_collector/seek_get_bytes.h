#ifndef SEEK_GET_BYTES_H
#define SEEK_GET_BYTES_H

/**
*   @file seek_get_bytes.h
*   @author Ritesh
*   @brief Converts the given pointer to corresponding unsigned int 
*/

uint8_t get_unit(void *buf, const int offset, int len);
uint8_t  get_uint8(void *, const int offset, int length);
uint16_t get_ntohs(void *, const int offset, int length);
uint32_t get_ntoh24(void *, const int offset, int length);
uint32_t get_ntohl(void *, const int offset, int length);
uint64_t get_ntoh40(void *, const int offset, int length);
uint64_t get_ntoh48(void *, const int offset, int length);
uint64_t get_ntoh56(void *, const int offset, int length);
uint64_t get_ntoh64(void *, const int offset, int length);
//long double get_ntoh128(void *, const int offset, int length);


#endif