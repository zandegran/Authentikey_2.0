/**************by ZANDEGRAN***************/
#include <pebble.h>


/********CONFIGURE THIS********/

const unsigned char sha1_key[] = {
	0x28,0x6D,0xC0,0x09,0x60,0xE9,0x90,0x23,0x2E,0x2B
};

// current time zone offset
#define TIME_ZONE_OFFSET +1

/******************************/


static int elapsed_seconds=0;
static int lineLength=140;
// size of the above key in bytes
#define SECRET_SIZE 10
// Truncate n decimal digits to 2^n for 6 digits
#define DIGITS_TRUNCATE 1000000

#define SHA1_SIZE 20



static Window *window;

static TextLayer *tokenLayer;
static TextLayer *tim;
static Layer *line_layer;
static BitmapLayer *key_layer;
static GBitmap *key;
/* from sha1.c from liboauth */

/* This code is public-domain - it is based on libcrypt 
 * placed in the public domain by Wei Dai and other contributors.
 */

#include <string.h>

/* header */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

union _buffer {
	uint8_t b[BLOCK_LENGTH];
	uint32_t w[BLOCK_LENGTH/4];
};

union _state {
	uint8_t b[HASH_LENGTH];
	uint32_t w[HASH_LENGTH/4];
};

typedef struct sha1nfo {
	union _buffer buffer;
	uint8_t bufferOffset;
	union _state state;
	uint32_t byteCount;
	uint8_t keyBuffer[BLOCK_LENGTH];
	uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

/* public API - prototypes - TODO: doxygen*/

/*
void sha1_init(sha1nfo *s);
void sha1_writebyte(sha1nfo *s, uint8_t data);
void sha1_write(sha1nfo *s, const char *data, size_t len);
uint8_t* sha1_result(sha1nfo *s);
void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength);
uint8_t* sha1_resultHmac(sha1nfo *s);
*/

/* code */
#define SHA1_K0 0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

const uint8_t sha1InitState[] = {
	0x01,0x23,0x45,0x67, // H0
	0x89,0xab,0xcd,0xef, // H1
	0xfe,0xdc,0xba,0x98, // H2
	0x76,0x54,0x32,0x10, // H3
	0xf0,0xe1,0xd2,0xc3  // H4
};

void sha1_init(sha1nfo *s) {
	memcpy(s->state.b,sha1InitState,HASH_LENGTH);
	s->byteCount = 0;
	s->bufferOffset = 0;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {
	return ((number << bits) | (number >> (32-bits)));
}

void sha1_hashBlock(sha1nfo *s) {
	uint8_t i;
	uint32_t a,b,c,d,e,t;

	a=s->state.w[0];
	b=s->state.w[1];
	c=s->state.w[2];
	d=s->state.w[3];
	e=s->state.w[4];
	for (i=0; i<80; i++) {
		if (i>=16) {
			t = s->buffer.w[(i+13)&15] ^ s->buffer.w[(i+8)&15] ^ s->buffer.w[(i+2)&15] ^ s->buffer.w[i&15];
			s->buffer.w[i&15] = sha1_rol32(t,1);
		}
		if (i<20) {
			t = (d ^ (b & (c ^ d))) + SHA1_K0;
		} else if (i<40) {
			t = (b ^ c ^ d) + SHA1_K20;
		} else if (i<60) {
			t = ((b & c) | (d & (b | c))) + SHA1_K40;
		} else {
			t = (b ^ c ^ d) + SHA1_K60;
		}
		t+=sha1_rol32(a,5) + e + s->buffer.w[i&15];
		e=d;
		d=c;
		c=sha1_rol32(b,30);
		b=a;
		a=t;
	}
	s->state.w[0] += a;
	s->state.w[1] += b;
	s->state.w[2] += c;
	s->state.w[3] += d;
	s->state.w[4] += e;
}

void sha1_addUncounted(sha1nfo *s, uint8_t data) {
	s->buffer.b[s->bufferOffset ^ 3] = data;
	s->bufferOffset++;
	if (s->bufferOffset == BLOCK_LENGTH) {
		sha1_hashBlock(s);
		s->bufferOffset = 0;
	}
}

void sha1_writebyte(sha1nfo *s, uint8_t data) {
	++s->byteCount;
	sha1_addUncounted(s, data);
}

void sha1_write(sha1nfo *s, const char *data, size_t len) {
	for (;len--;) sha1_writebyte(s, (uint8_t) *data++);
}

void sha1_pad(sha1nfo *s) {
	// Implement SHA-1 padding (fips180-2 §5.1.1)

	// Pad with 0x80 followed by 0x00 until the end of the block
	sha1_addUncounted(s, 0x80);
	while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);

	// Append length in the last 8 bytes
	sha1_addUncounted(s, 0); // We're only using 32 bit lengths
	sha1_addUncounted(s, 0); // But SHA-1 supports 64 bit lengths
	sha1_addUncounted(s, 0); // So zero pad the top bits
	sha1_addUncounted(s, s->byteCount >> 29); // Shifting to multiply by 8
	sha1_addUncounted(s, s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
	sha1_addUncounted(s, s->byteCount >> 13); // byte.
	sha1_addUncounted(s, s->byteCount >> 5);
	sha1_addUncounted(s, s->byteCount << 3);
}

uint8_t* sha1_result(sha1nfo *s) {
	int i;
	// Pad to complete the last block
	sha1_pad(s);

	// Swap byte order back
	for (i=0; i<5; i++) {
		uint32_t a,b;
		a=s->state.w[i];
		b=a<<24;
		b|=(a<<8) & 0x00ff0000;
		b|=(a>>8) & 0x0000ff00;
		b|=a>>24;
		s->state.w[i]=b;
	}

	// Return pointer to hash (20 characters)
	return s->state.b;
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength) {
	uint8_t i;
	memset(s->keyBuffer, 0, BLOCK_LENGTH);
	if (keyLength > BLOCK_LENGTH) {
		// Hash long keys
		sha1_init(s);
		for (;keyLength--;) sha1_writebyte(s, *key++);
		memcpy(s->keyBuffer, sha1_result(s), HASH_LENGTH);
	} else {
		// Block length keys are used as is
		memcpy(s->keyBuffer, key, keyLength);
	}
	// Start inner hash
	sha1_init(s);
	for (i=0; i<BLOCK_LENGTH; i++) {
		sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_IPAD);
	}
}

uint8_t* sha1_resultHmac(sha1nfo *s) {
	uint8_t i;
	// Complete inner hash
	memcpy(s->innerHash,sha1_result(s),HASH_LENGTH);
	// Calculate outer hash
	sha1_init(s);
	for (i=0; i<BLOCK_LENGTH; i++) sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_OPAD);
	for (i=0; i<HASH_LENGTH; i++) sha1_writebyte(s, s->innerHash[i]);
	return sha1_result(s);
}


/* end sha1.c */

uint32_t get_epoch_seconds() {
    time_t t = time(NULL);
    //struct tm *current_time = gmtime(&t);
    
	uint32_t unix_time;
	unix_time=t-(TIME_ZONE_OFFSET*3600);
	elapsed_seconds=unix_time%30;
    unix_time /= 30;
	return unix_time;
}

void handle_second_tick() {


	static char tokenText[] = "RYRYRY"; // Needs to be static because it's used by the system later.
    static char remtim[] = "00";
	sha1nfo s;
	uint8_t ofs;
	uint32_t otp;
	int i;
	uint32_t unix_time;
	char sha1_time[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	// TOTP uses seconds since epoch in the upper half of an 8 byte payload
	// TOTP is HOTP with a time based payload
	// HOTP is HMAC with a truncation function to get a short decimal key
	unix_time = get_epoch_seconds();
	sha1_time[4] = (unix_time >> 24) & 0xFF;
	sha1_time[5] = (unix_time >> 16) & 0xFF;
	sha1_time[6] = (unix_time >> 8) & 0xFF;
	sha1_time[7] = unix_time & 0xFF;

	// First get the HMAC hash of the time payload with the shared key
	sha1_initHmac(&s, sha1_key, SECRET_SIZE);
	sha1_write(&s, sha1_time, 8);
	sha1_resultHmac(&s);
	
	// Then do the HOTP truncation.  HOTP pulls its result from a 31-bit byte
	// aligned window in the HMAC result, then lops off digits to the left
	// over 6 digits.
	ofs=s.state.b[SHA1_SIZE-1] & 0xf;
	otp = 0;
	otp = ((s.state.b[ofs] & 0x7f) << 24) |
		((s.state.b[ofs + 1] & 0xff) << 16) |
		((s.state.b[ofs + 2] & 0xff) << 8) |
		(s.state.b[ofs + 3] & 0xff);
	otp %= DIGITS_TRUNCATE;
	
	// Convert result into a string.  Sure wish we had working snprintf...
	for(i = 0; i < 6; i++) {
		tokenText[5-i] = 0x30 + (otp % 10);
		otp /= 10;
	}
	tokenText[6]=0;
    otp=30-elapsed_seconds;
    lineLength=otp*140/30;
    for(i = 0; i < 2; i++) {
		remtim[1-i] = 0x30 + (otp % 10);
		otp /= 10;
	}
    
	text_layer_set_text(tim, remtim);
	text_layer_set_text(tokenLayer, tokenText);
}

void line_layer_update_callback(Layer *me, GContext* ctx) {
    (void)me;
    
    graphics_context_set_stroke_color(ctx, GColorWhite);
    graphics_draw_line(ctx, GPoint(4, 95), GPoint(lineLength-2, 95));
    graphics_draw_line(ctx, GPoint(3, 96), GPoint(lineLength-1, 96));
    graphics_draw_line(ctx, GPoint(2, 97), GPoint(lineLength, 97));
    graphics_draw_line(ctx, GPoint(2, 98), GPoint(lineLength, 98));
    graphics_draw_line(ctx, GPoint(3, 99), GPoint(lineLength-1, 99));
    graphics_draw_line(ctx, GPoint(4, 100), GPoint(lineLength-2, 100));
}

void handle_init() {

	window = window_create();
	window_stack_push(window, true /* Animated */);
	window_set_background_color(window, GColorBlack);
    tick_timer_service_subscribe	(	SECOND_UNIT,(TickHandler)handle_second_tick);
	// Init the text layer used to show the time
    tokenLayer=text_layer_create(GRect(4, 44, 144-4 /* width */, 168-44 /* height */));
	text_layer_set_text_color(tokenLayer, GColorWhite);
	text_layer_set_background_color(tokenLayer, GColorClear);
    text_layer_set_text_alignment(tokenLayer, GTextAlignmentCenter);
	text_layer_set_font(tokenLayer, fonts_get_system_font(FONT_KEY_BITHAM_34_MEDIUM_NUMBERS));
    layer_add_child(window_get_root_layer(window), text_layer_get_layer(tokenLayer));
    //Remaining Time
    tim=text_layer_create(GRect(60, 106, 50/* width */, 50 /* height */));
	text_layer_set_text_color(tim, GColorWhite);
	text_layer_set_background_color(tim, GColorClear);
	text_layer_set_font(tim, fonts_get_system_font(FONT_KEY_GOTHIC_24_BOLD));
    layer_add_child(window_get_root_layer(window), text_layer_get_layer(tim));
    
    // Progress Bar
    GRect bounds = layer_get_frame(window_get_root_layer(window));
    line_layer = layer_create(bounds);
    layer_set_update_proc(line_layer, line_layer_update_callback);
    layer_add_child(window_get_root_layer(window), line_layer);
    //Key
    key=gbitmap_create_with_resource(RESOURCE_ID_IMAGE_KEY);
    key_layer=bitmap_layer_create(GRect(27, 2, 98, 42));
    bitmap_layer_set_bitmap(key_layer, key);
    layer_add_child(window_get_root_layer(window), bitmap_layer_get_layer(key_layer));
    
    handle_second_tick();
}
void handle_deinit() {
    bitmap_layer_destroy(key_layer);
    gbitmap_destroy(key);
    text_layer_destroy(tokenLayer);
    text_layer_destroy(tim);
    window_destroy(window);
    // Note: Failure to de-init this here will result in instability and
    //       unable to allocate memory errors.
}

int main(void ) {
    
    handle_init();
    app_event_loop();
    handle_deinit();
}
