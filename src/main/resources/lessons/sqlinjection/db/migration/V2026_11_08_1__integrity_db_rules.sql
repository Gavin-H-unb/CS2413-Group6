ALTER TABLE employees ADD CONSTRAINT IG_EMP_SALARY_RANGE CHECK (salary BETWEEN 0 AND 250000);
ALTER TABLE employees ADD CONSTRAINT IG_EMP_TAN_FORMAT
  CHECK (REGEXP_MATCHES(auth_tan, '[A-Z0-9]{6}'));

CREATE TRIGGER IG_EMP_RAISE_CAP BEFORE UPDATE ON employees
  REFERENCING OLD ROW AS o NEW ROW AS n FOR EACH ROW
  WHEN (n.salary > o.salary * 1.10)
  SIGNAL SQLSTATE '45000'
  SET MESSAGE_TEXT = 'Integrity rule: salary raise above 10% requires approval';

CREATE TRIGGER IG_EMP_IMMUTABLE_IDS BEFORE UPDATE ON employees
  REFERENCING OLD ROW AS o NEW ROW AS n FOR EACH ROW
  WHEN (n.userid <> o.userid OR n.auth_tan <> o.auth_tan)
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Integrity rule: userid and auth_tan are immutable';

CREATE TRIGGER IG_LOG_NO_DELETE BEFORE DELETE ON access_log FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Integrity rule: access_log is append-only';

CREATE TRIGGER IG_LOG_NO_UPDATE BEFORE UPDATE ON access_log FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Integrity rule: access_log is append-only';

CREATE TRIGGER IG_CRED_NO_DIRECT_UPDATE BEFORE UPDATE ON sql_challenge_users
  REFERENCING OLD ROW AS o NEW ROW AS n FOR EACH ROW
  WHEN (n.password <> o.password OR n.userid <> o.userid)
  SIGNAL SQLSTATE '45000'
  SET MESSAGE_TEXT = 'Integrity rule: credentials can only be changed via the password-reset procedure';
