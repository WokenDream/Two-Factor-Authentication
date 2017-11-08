#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "lib/encoding.h"

#define SECRET_LEN 20

/**
 * internal use: assume hex char in upper case 
 */
uint8_t hex_char_to_byte(char c);

/**
 * internal use: assume length of input is 20
 */
uint8_t* hex_str_to_bytes(char* input);

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	const char* encoded_issuer = urlEncode(issuer);
	const char* encoded_accountname = urlEncode(accountName);
	uint8_t* hex_bytes = hex_str_to_bytes(secret_hex);
	uint8_t secret_base32[SECRET_LEN + 1] = {0}; // '\0' in the end is needed for "%s"
	base32_encode(hex_bytes, 10, secret_base32, SECRET_LEN);

	const int uri_len = 41 + 1 + strlen(encoded_accountname) + strlen(encoded_issuer) + strlen((char* )secret_base32);
	char hotp_buf[uri_len];
	char totp_buf[uri_len];
	snprintf(hotp_buf, uri_len, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_accountname, encoded_issuer, secret_base32);
	snprintf(totp_buf, uri_len, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_accountname, encoded_issuer, secret_base32);
	displayQRcode(hotp_buf);
	displayQRcode(totp_buf);

	return (0);
}

uint8_t hex_char_to_byte(char c) {
	return (c <= '9') ? (uint8_t)(c - '0') : (uint8_t)(c - 'A' + 10);
}

uint8_t* hex_str_to_bytes(char* input) {
	int i = 0;
	const int len = SECRET_LEN >> 1;
	uint8_t* hex = malloc(len);
	uint8_t upper, lower; // a hex need 4 bits
	while (i < len) {
		upper = hex_char_to_byte(input[i << 1]);
		lower = hex_char_to_byte(input[(i << 1) + 1]);
		hex[i] = (upper << 4) | lower;
		++i;
	}
	return hex;
}