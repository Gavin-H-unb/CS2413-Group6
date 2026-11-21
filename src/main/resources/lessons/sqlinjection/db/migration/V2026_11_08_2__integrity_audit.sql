-- CS2413 Group 6 - Layer 5: audit trail for tamper detection.

CREATE TABLE integrity_audit (
    id         INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    table_name VARCHAR(40),
    op         VARCHAR(10),
    row_key    VARCHAR(250),
    detail     VARCHAR(400),
    db_user    VARCHAR(128)
);

CREATE TABLE integrity_seal (
    table_name    VARCHAR(40)   NOT NULL,
    row_key       VARCHAR(250)  NOT NULL,
    sealed_values VARCHAR(2000) NOT NULL,
    seal          VARCHAR(64)   NOT NULL,
    PRIMARY KEY (table_name, row_key)
);

CREATE TRIGGER AUD_EMP_UPDATE AFTER UPDATE ON employees
  REFERENCING OLD ROW AS o NEW ROW AS n FOR EACH ROW
  INSERT INTO integrity_audit (table_name, op, row_key, detail, db_user)
  VALUES ('EMPLOYEES', 'UPDATE', o.userid,
          'salary ' || CAST(o.salary AS VARCHAR(12)) || ' -> ' || CAST(n.salary AS VARCHAR(12))
          || '; department ' || COALESCE(o.department, 'NULL')
          || ' -> ' || COALESCE(n.department, 'NULL'),
          SESSION_USER);

CREATE TRIGGER AUD_EMP_DELETE AFTER DELETE ON employees
  REFERENCING OLD ROW AS o FOR EACH ROW
  INSERT INTO integrity_audit (table_name, op, row_key, detail, db_user)
  VALUES ('EMPLOYEES', 'DELETE', o.userid, 'employee row deleted', SESSION_USER);

CREATE TRIGGER AUD_CRED_UPDATE AFTER UPDATE ON sql_challenge_users
  REFERENCING OLD ROW AS o NEW ROW AS n FOR EACH ROW
  INSERT INTO integrity_audit (table_name, op, row_key, detail, db_user)
  VALUES ('SQL_CHALLENGE_USERS', 'UPDATE', o.userid,
          CASE WHEN o.password <> n.password THEN 'password changed' ELSE 'row changed' END,
          SESSION_USER);

CREATE TRIGGER AUD_LOG_DELETE AFTER DELETE ON access_log
  REFERENCING OLD ROW AS o FOR EACH ROW
  INSERT INTO integrity_audit (table_name, op, row_key, detail, db_user)
  VALUES ('ACCESS_LOG', 'DELETE', CAST(o.id AS VARCHAR(12)), 'log entry deleted', SESSION_USER);