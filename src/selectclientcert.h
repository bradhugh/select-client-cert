#ifndef _SELECTCLIENTCERT_H_
#define _SELECTCLIENTCERT_H_

#include <nan.h>

v8::Local<v8::String> CreateUtf8String(v8::Isolate* isolate, const char* strData);

NAN_METHOD(SelectClientCert);

#endif