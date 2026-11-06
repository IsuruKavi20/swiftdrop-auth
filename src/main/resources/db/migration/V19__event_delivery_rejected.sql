-- Identity step 6d: two different kinds of "not delivered":
--   DEAD     = we gave up PUSHING after 24 h; the receiver can still collect it by polling (RFC 8936)
--   REJECTED = the receiver said the SET is wrong (HTTP 400 or setErrs): final, never sent again
ALTER TABLE event_deliveries DROP CONSTRAINT ck_event_deliveries_status;
ALTER TABLE event_deliveries ADD CONSTRAINT ck_event_deliveries_status
    CHECK (status IN ('PENDING', 'DELIVERED', 'DEAD', 'REJECTED'));
