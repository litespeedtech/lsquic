/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
MIT License

Copyright (c) 2020 LiteSpeed Technologies Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/* The LiteSpeed Structured Fields Parser parses structured fields decribed in
 * https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-19
 *
 * It provides a simple streaming interface which allows the user to process
 * structured fields in any manner.
 */

#ifndef LS_SFPARSER_H
#define LS_SFPARSER_H 1

enum ls_sf_dt
{   /* LS SF DT: LiteSpeed Structured Field Data Type */
    LS_SF_DT_INTEGER,
    LS_SF_DT_DECIMAL,

    /* Name only applies to dictionary names.  They may repeat: the
     * parser does not drop duplicates.
     */
    LS_SF_DT_NAME,

    /* Parameter name may apply to any applicable preceding Item or
     * Inner List.
     */
    LS_SF_DT_PARAM_NAME,

    /* The returned string does not include enclosing double quotes. */
    LS_SF_DT_STRING,

    LS_SF_DT_TOKEN,

    /* The byte sequence is not base64-decoded; it is up to the caller
     * to do so.  The returned string does not include the enclosing
     * colons.
     */
    LS_SF_DT_BYTESEQ,

    /* Note that true boolean values are serialized *without* the values.
     * The parser makes one up and passes a pointer to its internal buffer.
     */
    LS_SF_DT_BOOLEAN,

    /* The Inner List has a beginning and an end.  The returned strings
     * are opening and closing parentheses.
     */
    LS_SF_DT_INNER_LIST_BEGIN,
    LS_SF_DT_INNER_LIST_END,
};


enum ls_sf_tlt
{   /* LS SF TLT: LiteSpeed Structured Field Top-Level Type */
    LS_SF_TLT_DICTIONARY,
    LS_SF_TLT_LIST,
    LS_SF_TLT_ITEM,
};


/* Return 0 if parsed correctly, -1 on error, -2 if ran out of memory. */
int
ls_sf_parse (
    /* Expected type of top-level input.  This tells the parser how to
     * parse the input.
     */
    enum ls_sf_tlt,

    /* Input; does not have to be NUL-terminated: */
    const char *input, size_t input_sz,

    /* Callback function to call each time a token is parsed.  A non-zero
     * return value indicates that parsing should stop.
     */
    int (*callback)(
        /* The first argument to the callback is user-specified additional
         * data.
         */
        void *user_data,
        /* The second argument is the data type. */
        enum ls_sf_dt,
        /* The third and fourth arguments are NUL-terminated string and
         * its length, respectively.  The string can be modified, because
         * the parser makes a copy.
         */
        char *str, size_t len,
        /* Offset to the token in the input buffer.  In the special case
         * of an implicit boolean value, this value is negative: this is
         * because this value is not present in the input buffer.
         */
        int off),

    /* Additional data to pass to the callback: */
    void *user_data,

    /* Allocate memory from this memory buffer.  If set to NULL, regular
     * system memory allocator will be used.
     */
    char *mem_buf, size_t mem_buf_sz);



/* Convenience array with type names. */
extern const char *const ls_sf_dt2str[];


#endif
