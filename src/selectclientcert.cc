#include "selectclientcert.h"

v8::Local<v8::String> CreateUtf8String(v8::Isolate* isolate, const char* strData)
{
    return v8::String::NewFromUtf8(isolate, strData, v8::NewStringType::kNormal).ToLocalChecked();
}

NAN_MODULE_INIT(Initialize) {
    Nan::SetMethod(target, "selectClientCert", SelectClientCert);
}

NODE_MODULE(selectclientcert, Initialize)