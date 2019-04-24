#include "selectclientcert.h"

NAN_METHOD(SelectClientCert)
{
    info.GetIsolate()->ThrowException(v8::Exception::Error(
		v8::String::NewFromUtf8(info.GetIsolate(), "SelectClientCert not implemented for Mac")));
}