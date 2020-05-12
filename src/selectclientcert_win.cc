#include "selectclientcert.h"

#include <memory>
#include <vector>
#include <algorithm>

#include <windows.h>
#include <cryptuiapi.h>

template<class THandle>
class handle_wrapper
{
private:
    THandle m_handle;

protected:
    virtual void internalRelease(THandle handle)
    {
    }

public:
    handle_wrapper(THandle handle)
    {
        m_handle = handle;
    }

    handle_wrapper(const handle_wrapper&) = delete;

    THandle get() const
    {
        return m_handle;
    }

    bool valid()
    {
        return m_handle != 0
            && m_handle != INVALID_HANDLE_VALUE;
    }

    void release()
    {
        if (this->valid())
        {
            this->internalRelease(m_handle);
            this->m_handle = reinterpret_cast<THandle>(INVALID_HANDLE_VALUE);
        }
    }

    ~handle_wrapper()
    {
        this->release();
    }
};

class store_wrapper: public handle_wrapper<HCERTSTORE>
{
public:
    store_wrapper(HCERTSTORE handle): handle_wrapper(handle) {}
    store_wrapper(const store_wrapper&) = delete;

protected:
    virtual void internalRelease(HCERTSTORE hStore) override
    {
        CertCloseStore(hStore, 0);
    }
};

class cert_context : public handle_wrapper<PCCERT_CONTEXT>
{
public:
    cert_context(PCCERT_CONTEXT pContext) : handle_wrapper(pContext) {}
    cert_context(const cert_context&) = delete;

protected:
    virtual void internalRelease(PCCERT_CONTEXT pContext) override
    {
        CertFreeCertificateContext(pContext);
    }
};

void ReportError(LPCSTR method, DWORD status, Nan::NAN_METHOD_ARGS_TYPE info)
{
    // TODO: Include the method and error code
    info.GetIsolate()->ThrowException(v8::Exception::Error(
        v8::String::NewFromUtf8(info.GetIsolate(), "A Windows API Function failed", v8::NewStringType::kNormal).ToLocalChecked()));
}

std::unique_ptr<cert_context> GetCertFromString(LPCSTR szCert)
{
    DWORD cbBinary = 0;
    BOOL result = ::CryptStringToBinary(szCert, 0, CRYPT_STRING_BASE64HEADER, nullptr, &cbBinary, nullptr, nullptr);
    if (!result)
    {
        return nullptr;
    }

    // Allocate
    auto pbBinary = std::make_unique<BYTE[]>(cbBinary);
    if (pbBinary == nullptr)
    {
        return nullptr;
    }

    // Initialize
    memset(pbBinary.get(), 0, cbBinary);

    // Actually fill out the binary
    result = ::CryptStringToBinary(szCert, 0, CRYPT_STRING_BASE64HEADER, pbBinary.get(), &cbBinary, nullptr, nullptr);
    if (!result)
    {
        return nullptr;
    }

    // Create context from binary
    PCCERT_CONTEXT tempCtx = ::CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        pbBinary.get(),
        cbBinary);

    auto ctx = std::make_unique<cert_context>(tempCtx);
    if (!ctx->valid())
    {
        return nullptr;
    }

    return std::move(ctx);
}

BOOL ResolveAndAddToStore(
    const store_wrapper &resolveUsingStore,
    const store_wrapper &targetStore,
    const std::unique_ptr<cert_context>& sourceContext)
{
    CERT_ID id;
    id.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;
    id.IssuerSerialNumber.Issuer = sourceContext->get()->pCertInfo->Issuer;
    id.IssuerSerialNumber.SerialNumber = sourceContext->get()->pCertInfo->SerialNumber;

    // Try to find the cert in the provided store
    cert_context resolvedContext = ::CertFindCertificateInStore(
        resolveUsingStore.get(),
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_CERT_ID,
        &id,
        nullptr);

    BOOL result;
    if (resolvedContext.valid())
    {
        result = ::CertAddCertificateContextToStore(targetStore.get(), resolvedContext.get(), CERT_STORE_ADD_ALWAYS, nullptr);
    }
    else
    {
        result = ::CertAddCertificateContextToStore(targetStore.get(), sourceContext->get(), CERT_STORE_ADD_ALWAYS, nullptr);
    }

    return result;
}

NAN_METHOD(SelectClientCert)
{
    auto isolate = info.GetIsolate();

    store_wrapper memStore = ::CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        NULL,
        CERT_STORE_CREATE_NEW_FLAG,
        nullptr);

    if (!memStore.valid())
    {
        ReportError("CertOpenStore", GetLastError(), info);
        return;
    }

    store_wrapper myStore = ::CertOpenSystemStore(NULL, "MY");
    if (!myStore.get())
    {
        ReportError("CertOpenSystemStore", GetLastError(), info);
        return;
    }

    auto certs = info[0].As<v8::Array>();

    auto context = isolate->GetCurrentContext();

    // Create each context from the certs passed in
    std::vector<std::unique_ptr<cert_context>> certContexts;
    for (uint32_t i = 0; i < certs->Length(); i++)
    {
        v8::String::Utf8Value strData(isolate, certs->Get(context, i).ToLocalChecked());
        auto certContext = GetCertFromString(*strData);

        certContexts.emplace_back(std::move(certContext));
    }

    // Add the certs to the memory store
    std::for_each(
        certContexts.rbegin(),
        certContexts.rend(),
        [&](const std::unique_ptr<cert_context>& pCtx) {
            if (pCtx != nullptr && pCtx->valid())
            {
                ResolveAndAddToStore(myStore, memStore, pCtx);
            }
        });

    // show the dialog
    cert_context selected = ::CryptUIDlgSelectCertificateFromStore(
        memStore.get(),
        NULL,
        nullptr,
        nullptr,
        0,
        0,
        nullptr);

    // See which one in our original list matches so the index is valid
    int index = -1;
    if (selected.valid())
    {
        auto elem = std::find_if(
            certContexts.begin(),
            certContexts.end(),
            [&](const std::unique_ptr<cert_context> & pCtx) {
                return ::CertCompareCertificate(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    pCtx->get()->pCertInfo,
                    selected.get()->pCertInfo);
            });

        if (elem != certContexts.end())
        {
            index = std::distance(certContexts.begin(), elem);
        }
    }

    info.GetReturnValue().Set(index);
}