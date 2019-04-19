#include "selectclientcert.h"

template<class THandle>
class handle_wrapper
{
private:
	THandle m_handle;

protected:
	virtual void release(THandle handle)
	{
	}

public:
	handle_wrapper(THandle handle)
	{
		m_handle = handle;
	}

	handle_wrapper(const handle_wrapper&) = delete;

	THandle get()
	{
		return m_handle;
	}

	bool valid()
	{
		return m_handle != 0
			&& m_handle != INVALID_HANDLE_VALUE;
	}

	~handle_wrapper()
	{
		if (this->valid())
		{
			this->release(m_handle);
		}
	}
};

class store_wrapper: public handle_wrapper<HCERTSTORE>
{
public:
	store_wrapper(HCERTSTORE handle): handle_wrapper(handle) {}

protected:
	virtual void release(HCERTSTORE hStore) override
	{
		CertCloseStore(hStore, 0);
	}
};

void ReportError(LPCSTR method, DWORD status, Nan::NAN_METHOD_ARGS_TYPE info)
{
	// TODO: Include the method and error code
	info.GetIsolate()->ThrowException(v8::Exception::Error(
		v8::String::NewFromUtf8(info.GetIsolate(), "A Windows API Function failed")));
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

	info.GetReturnValue().Set(
		v8::String::NewFromUtf8(isolate, "At least it didn't fail"));
}