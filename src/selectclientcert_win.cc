#include "selectclientcert.h"

void ReportError(LPCSTR method, DWORD status, Nan::NAN_METHOD_ARGS_TYPE info)
{
	// TODO: Include the method and error code
	info.GetIsolate()->ThrowException(v8::Exception::Error(
		v8::String::NewFromUtf8(info.GetIsolate(), "A Windows API Function failed")));
}

class store_wrapper
{
private:
	HCERTSTORE m_hStore;

public:
	store_wrapper(HCERTSTORE hStore)
	{
		m_hStore = hStore;
	}

	store_wrapper(const store_wrapper&) = delete;

	HCERTSTORE getHandle()
	{
		return m_hStore;
	}

	bool isValid()
	{
		return m_hStore != 0
			&& m_hStore != INVALID_HANDLE_VALUE;
	}

	~store_wrapper()
	{
		if (this->isValid())
		{
			CertCloseStore(m_hStore, 0);
		}
	}
};

NAN_METHOD(SelectClientCert)
{
	auto isolate = info.GetIsolate();

	store_wrapper memStore = ::CertOpenStore(
		CERT_STORE_PROV_MEMORY,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		NULL,
		CERT_STORE_CREATE_NEW_FLAG,
		nullptr);

	if (!memStore.isValid())
	{
		ReportError("CertOpenStore", GetLastError(), info);
		return;
	}

	info.GetReturnValue().Set(
		v8::String::NewFromUtf8(isolate, "At least it didn't fail"));
}