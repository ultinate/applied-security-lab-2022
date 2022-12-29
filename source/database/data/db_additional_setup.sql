# begin with the transaction for all creations and inserts
START TRANSACTION;

-- Create the administrator table
CREATE TABLE IF NOT EXISTS administrators
(
    uid   varchar(64),
    email varchar(64) NOT NULL,
    PRIMARY KEY (uid)
);

-- Populate the table
INSERT INTO administrators (uid, email)
VALUES ('admin_ca', 'admin_ca@imovies.ch');

-- commit all updates and created tables
COMMIT;

-- Create the new user
DROP USER IF EXISTS 'webapp'@'localhost'; FLUSH PRIVILEGES;
CREATE USER 'webapp'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'password';
GRANT UPDATE, SELECT on imovies.users TO 'webapp'@'localhost';
GRANT SELECT on imovies.administrators TO 'webapp'@'localhost';
FLUSH PRIVILEGES;

DROP USER IF EXISTS 'backup'@'localhost'; FLUSH PRIVILEGES;
CREATE USER 'backup'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'password';
GRANT LOCK TABLES, SELECT on imovies.* TO 'backup'@'localhost';
FLUSH PRIVILEGES;
