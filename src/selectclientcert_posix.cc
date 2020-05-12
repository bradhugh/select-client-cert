#include "selectclientcert.h"

NAN_METHOD(SelectClientCert)
{
    info.GetIsolate()->ThrowException(v8::Exception::Error(
        CreateUtf8String(info.GetIsolate(), "SelectClientCert not implemented for Posix")));
}