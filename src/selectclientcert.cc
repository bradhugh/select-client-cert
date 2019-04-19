#include "selectclientcert.h"

NAN_MODULE_INIT(Initialize) {
    Nan::SetMethod(target, "selectClientCert", SelectClientCert);
}

NODE_MODULE(selectclientcert, Initialize)