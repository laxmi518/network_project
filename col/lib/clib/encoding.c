#include <Python.h>
#include "encoding.h"

char *get_encoded_msg(char *buffer, char *charset)
{
    Py_ssize_t ssize = (Py_ssize_t)strlen(buffer);
    PyObject *pyobject_unicode= PyUnicode_Decode(buffer,ssize,charset,"replace");
    if(pyobject_unicode==NULL)
    {
        zlog_error(c,"decode failed for: %s",buffer);
        return NULL;
    }
    PyObject *pystring= PyUnicode_AsUTF8String(pyobject_unicode);
    if(pystring == NULL)
    {
        zlog_error(c,"UTF-8 encode failed for: %s",buffer);
        return NULL;   
    }
    const char *encoded_str = PyString_AsString(pystring);
    char *encoded_str_dup = strdup(encoded_str);
    Py_DECREF(pystring);
    Py_DECREF(pyobject_unicode);
    zlog_debug(c,"Encoded string: %s",encoded_str_dup);
    return encoded_str_dup;
}
