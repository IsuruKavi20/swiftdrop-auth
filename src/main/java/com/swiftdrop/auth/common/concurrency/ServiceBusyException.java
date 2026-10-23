package com.swiftdrop.auth.common.concurrency;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

public class ServiceBusyException extends DomainException {

    public ServiceBusyException() {
        super(ErrorCode.SERVICE_BUSY);
    }
}
