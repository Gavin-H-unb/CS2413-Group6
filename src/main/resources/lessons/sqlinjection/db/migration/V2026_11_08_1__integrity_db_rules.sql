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
