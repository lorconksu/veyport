-- Account IDs are immutable SSH incarnations and must never be reused, even
-- after deleting the account. Identity-less certificates require reissuance.
CREATE TABLE ssh_account_identities (user_id TEXT PRIMARY KEY NOT NULL);
INSERT INTO ssh_account_identities(user_id) SELECT id FROM users;
CREATE TRIGGER users_ssh_identity_insert BEFORE INSERT ON users BEGIN
    SELECT RAISE(ABORT, 'immutable account identity')
        WHERE EXISTS(SELECT 1 FROM ssh_account_identities WHERE user_id=NEW.id);
    INSERT INTO ssh_account_identities(user_id) VALUES(NEW.id);
END;
CREATE TRIGGER users_ssh_identity_immutable BEFORE UPDATE OF id ON users
WHEN NEW.id != OLD.id BEGIN SELECT RAISE(ABORT, 'immutable account identity'); END;
