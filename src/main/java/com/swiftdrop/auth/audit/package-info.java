/**
 * Identity step 9a: the audit log. Who did what to whom, and when; ids only. Other modules call
 * {@link com.swiftdrop.auth.audit.AuditLog#record} inside the transaction of the action they record.
 */
package com.swiftdrop.auth.audit;
