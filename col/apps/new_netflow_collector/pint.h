#ifndef PINT_H
#define PINT_H

/**
*    @file   pint.h
*    @brief    Definitions for extracting and translating integers safely and portably via pointers.
*/

#include <glib.h>


#define pntohs(p)   ((guint16) \
                    ((guint16)*((const uint8_t *)(p)+0)<<8|    \
                    (guint16)*((const uint8_t *)(p)+1)<<0))


#define pntoh24(p)  ((guint32)*((const guint8 *)(p)+0)<<16|  \
                    (guint32)*((const guint8 *)(p)+1)<<8|   \
                    (guint32)*((const guint8 *)(p)+2)<<0)


#define pntohl(p)   ((uint32_t)*((const uint8_t *)(p)+0)<<24|  \
                    (uint32_t)*((const uint8_t *)(p)+1)<<16|  \
                    (uint32_t)*((const uint8_t *)(p)+2)<<8|   \
                    (uint32_t)*((const uint8_t *)(p)+3)<<0)


#define pntoh40(p)  ((guint64)*((const guint8 *)(p)+0)<<32|  \
                    (guint64)*((const guint8 *)(p)+1)<<24|  \
                    (guint64)*((const guint8 *)(p)+2)<<16|  \
                    (guint64)*((const guint8 *)(p)+3)<<8|   \
                    (guint64)*((const guint8 *)(p)+4)<<0)


#define pntoh48(p)  ((guint64)*((const guint8 *)(p)+0)<<40|  \
                    (guint64)*((const guint8 *)(p)+1)<<32|  \
                    (guint64)*((const guint8 *)(p)+2)<<24|  \
                    (guint64)*((const guint8 *)(p)+3)<<16|  \
                    (guint64)*((const guint8 *)(p)+4)<<8|   \
                    (guint64)*((const guint8 *)(p)+5)<<0)


#define pntoh56(p)  ((guint64)*((const guint8 *)(p)+0)<<48|  \
                    (guint64)*((const guint8 *)(p)+1)<<40|  \
                    (guint64)*((const guint8 *)(p)+2)<<32|  \
                    (guint64)*((const guint8 *)(p)+3)<<24|  \
                    (guint64)*((const guint8 *)(p)+4)<<16|  \
                    (guint64)*((const guint8 *)(p)+5)<<8|   \
                    (guint64)*((const guint8 *)(p)+6)<<0)


#define pntoh64(p)  ((guint64)*((const guint8 *)(p)+0)<<56|  \
                    (guint64)*((const guint8 *)(p)+1)<<48|  \
                    (guint64)*((const guint8 *)(p)+2)<<40|  \
                    (guint64)*((const guint8 *)(p)+3)<<32|  \
                    (guint64)*((const guint8 *)(p)+4)<<24|  \
                    (guint64)*((const guint8 *)(p)+5)<<16|  \
                    (guint64)*((const guint8 *)(p)+6)<<8|   \
                    (guint64)*((const guint8 *)(p)+7)<<0)


#define pntoh128(p)  ((long double)*((const guint8 *)(p)+0)<<120|  \
                    (long double)*((const guint8 *)(p)+1)<<112|  \
                    (long double)*((const guint8 *)(p)+2)<<104|  \
                    (long double)*((const guint8 *)(p)+3)<<96|  \
                    (long double)*((const guint8 *)(p)+4)<<88|  \
                    (long double)*((const guint8 *)(p)+5)<<80|  \
                    (long double)*((const guint8 *)(p)+6)<<72|   \
                    (long double)*((const guint8 *)(p)+7)<<64)   \
                    (long double)*((const guint8 *)(p)+0)<<56|  \
                    (long double)*((const guint8 *)(p)+1)<<48|  \
                    (long double)*((const guint8 *)(p)+2)<<40|  \
                    (long double)*((const guint8 *)(p)+3)<<32|  \
                    (long double)*((const guint8 *)(p)+4)<<24|  \
                    (long double)*((const guint8 *)(p)+5)<<16|  \
                    (long double)*((const guint8 *)(p)+6)<<8|   \
                    (long double)*((const guint8 *)(p)+7)<<0)



#endif