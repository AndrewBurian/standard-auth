/*
	JWS implements JSON Web Signature objects as defined in RFC 7515.

	JSON Web Signature objects are a web-portable format for exchanging signed blobs of data.

	## JWS vs JWT

	JSON Web Tokens (JWT) is a commonly used format for auth tokens of all types.
	JWT's typically make use of JWS as the underlying object format to provide encoding and authentication.
	This package provides the generic JWS object and makes no assumptions about the data contained
	in the signed block. As such it can be used for JWTs, but does not implement any JWT specific features.
*/
package jws
