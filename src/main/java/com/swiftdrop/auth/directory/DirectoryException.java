package com.swiftdrop.auth.directory;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** A Directory API request that can't be answered (unknown user, bad paging or filter values). */
public class DirectoryException extends DomainException {

    public DirectoryException(ErrorCode code) {
        super(code);
    }
}
