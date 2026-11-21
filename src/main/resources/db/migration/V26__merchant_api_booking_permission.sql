-- Merchant API booking (21 Nov 2026): a permission ONLY for merchant machine tokens (client credentials, mc_ keys).
-- No role gets it, so no person's login token ever carries it: the delivery backend's booking API requires it and
-- can tell "a merchant's software" from "a person" by permission, not only by the token's sub.
INSERT INTO permissions (id, name) VALUES (17, 'merchant:api-booking');
