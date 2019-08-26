#ifndef BASE64_H
#define BASE64_H

/*
 * Common Base64
 */

/* max. buffer size required for base64_encode() */
#define MAX_BASE64_ENCODED_SIZE(size) \
	((((size) + 2) / 3) * 4)
/* max. buffer size required for base64_decode() */
#define MAX_BASE64_DECODED_SIZE(size) \
	(((size) + 3) / 4 * 3)

struct base64_scheme {
	const char encmap[64];
	const unsigned char decmap[256];
};

/*
 * Low-level Base64 encoder
 */

struct base64_encoder {
	const struct base64_scheme *b64;

	/* state */
	unsigned int sub_pos;
	unsigned char buf;

	unsigned char w_buf[4];
	unsigned int w_buf_len;

	bool finished:1;
};

/* Returns TRUE when base64_encode_finish() was called on this encoder. */
static inline bool
base64_encode_is_finished(struct base64_encoder *enc)
{
	return enc->finished;
}

/* Initialize the Base64 encoder. The b64 parameter is the definition of the
   particular Base64 encoding scheme that is used.
 */
static inline void
base64_encode_init(struct base64_encoder *enc,
		   const struct base64_scheme *b64)
{
	i_zero(enc);
	enc->b64 = b64;
}

/* Reset the Base64 encoder to its initial state. */
static inline void
base64_encode_reset(struct base64_encoder *enc)
{
	const struct base64_scheme *b64 = enc->b64;

	base64_encode_init(enc, b64);
}

/* Translate the size of the next input to the size of the output once encoded.
   This yields the amount of data appended to the dest buffer by
   base64_encode_more() with the indicated src_size. */
size_t base64_encode_get_size(struct base64_encoder *enc, size_t src_size);

/* Translates binary data into some form of Base64. The src must not point to
   dest buffer. Returns TRUE when all the provided data is encoded. Returns
   FALSE when the space in the provided buffer is insufficient. The return value
   may be ignored. If src_pos_r is non-NULL, it's updated to first
   non-translated character in src.
 */
bool ATTR_NOWARN_UNUSED_RESULT
base64_encode_more(struct base64_encoder *enc, const void *src, size_t src_size,
		   size_t *src_pos_r, buffer_t *dest) ATTR_NULL(4);

/* Finishes Base64 encoding. Returns TRUE when all the provided data is encoded.
   Returns FALSE when the space in the provided buffer is insufficient. The
   return value may be ignored.
 */
bool ATTR_NOWARN_UNUSED_RESULT
base64_encode_finish(struct base64_encoder *enc, buffer_t *dest) ATTR_NULL(2);

/*
 * Generic Base64 API
 */

/* Translates binary data into some variant of Base64. The src must not point to
   dest buffer.

   The b64 parameter is the definition of the particular Base 64 encoding scheme
   that is used. See below for specific functions.
 */
static inline void
base64_scheme_encode(const struct base64_scheme *b64,
		     const void *src, size_t src_size, buffer_t *dest)
{
	struct base64_encoder enc;

	base64_encode_init(&enc, b64);
	base64_encode_more(&enc, src, src_size, NULL, dest);
	base64_encode_finish(&enc, dest);
}

/* Translates some variant of Base64 data into binary and appends it to dest
   buffer. dest may point to same buffer as src. Returns 1 if all ok, 0 if end
   of Base64 data found, -1 if data is invalid.

   The b64 parameter is the definition of the particular Base 64 encoding scheme
   that is expected. See below for specific functions.

   Any CR, LF characters are ignored, as well as whitespace at beginning or
   end of line.

   This function may be called multiple times for parsing the same stream.
   If src_pos is non-NULL, it's updated to first non-translated character in
   src. */
int base64_scheme_decode(const struct base64_scheme *b64,
			 const void *src, size_t src_size, size_t *src_pos_r,
			 buffer_t *dest) ATTR_NULL(4);

/* Decode given string to a buffer allocated from data stack.

   The decmap is the mapping table used for the specific base64 encoding
   variant. See below for specific functions.
 */
buffer_t *t_base64_scheme_decode_str(const struct base64_scheme *b64,
				     const char *str);

/* Returns TRUE if c is a valid encoding character (excluding '=') for the
   provided base64 mapping table */
static inline bool
base64_scheme_is_valid_char(const struct base64_scheme *b64, char c)
{
	return b64->decmap[(uint8_t)c] != 0xff;
}

/*
 * "base64" encoding scheme (RFC 4648, Section 4)
 */

extern struct base64_scheme base64_scheme;

/* Translates binary data into base64. See base64_scheme_encode(). */
static inline void
base64_encode(const void *src, size_t src_size, buffer_t *dest)
{
	base64_scheme_encode(&base64_scheme, src, src_size, dest);
}

/* Translates base64 data into binary and appends it to dest buffer. See
   base64_scheme_decode(). */
static inline int
base64_decode(const void *src, size_t src_size, size_t *src_pos_r,
	      buffer_t *dest) ATTR_NULL(3)
{
	return base64_scheme_decode(&base64_scheme, src, src_size,
				    src_pos_r, dest);
}

/* Decode given string to a buffer allocated from data stack. */
static inline buffer_t *t_base64_decode_str(const char *str)
{
	return t_base64_scheme_decode_str(&base64_scheme, str);
}

/* Returns TRUE if c is a valid base64 encoding character (excluding '=') */
static inline bool base64_is_valid_char(char c)
{
	return base64_scheme_is_valid_char(&base64_scheme, c);
}

/*
 * "base64url" encoding scheme (RFC 4648, Section 5)
 */

extern struct base64_scheme base64url_scheme;

/* Translates binary data into base64url. See base64_scheme_encode(). */
static inline void
base64url_encode(const void *src, size_t src_size, buffer_t *dest)
{
	base64_scheme_encode(&base64url_scheme, src, src_size, dest);
}

/* Translates base64url data into binary and appends it to dest buffer. See
   base64_scheme_decode(). */
static inline int
base64url_decode(const void *src, size_t src_size, size_t *src_pos_r,
		 buffer_t *dest) ATTR_NULL(3)
{
	return base64_scheme_decode(&base64url_scheme, src, src_size,
				    src_pos_r, dest);
}

/* Decode given string to a buffer allocated from data stack. */
static inline buffer_t *t_base64url_decode_str(const char *str)
{
	return t_base64_scheme_decode_str(&base64url_scheme, str);
}

/* Returns TRUE if c is a valid base64url encoding character (excluding '=') */
static inline bool base64url_is_valid_char(char c)
{
	return base64_scheme_is_valid_char(&base64url_scheme, c);
}

#endif
