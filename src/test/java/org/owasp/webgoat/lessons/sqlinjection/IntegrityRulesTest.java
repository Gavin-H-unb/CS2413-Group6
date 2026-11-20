/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/** Runs the SQL injection lesson migrations and checks the L4 integrity rules directly in SQL. */
class IntegrityRulesTest {

  private Connection connection;

  @BeforeEach
  void createLessonTables() throws SQLException {
    var dataSource =
        new DriverManagerDataSource("jdbc:hsqldb:mem:" + UUID.randomUUID(), "sa", "");
    dataSource.setDriverClassName("org.hsqldb.jdbc.JDBCDriver");

    Flyway.configure()
        .dataSource(dataSource)
        .schemas("LESSON")
        .locations("lessons/sqlinjection/db/migration")
        .load()
        .migrate();

    connection = dataSource.getConnection();
    execute("SET SCHEMA LESSON");
  }

  @AfterEach
  void closeConnection() throws SQLException {
    connection.close();
  }

  @Test
  void salaryRaiseAboveTenPercentIsRefused() throws SQLException {
    assertRefused(
        "UPDATE employees SET salary = 99999 WHERE last_name = 'Smith'",
        "salary raise above 10% requires approval");

    assertThat(query("SELECT salary FROM employees WHERE userid = '37648'")).isEqualTo("64350");
  }

  @Test
  void normalRaiseIsAllowed() throws SQLException {
    execute("UPDATE employees SET salary = 67000 WHERE userid = '37648'");

    assertThat(query("SELECT salary FROM employees WHERE userid = '37648'")).isEqualTo("67000");
  }

  @Test
  void employeeIdsAndTansCannotChange() {
    assertRefused(
        "UPDATE employees SET userid = '11111' WHERE userid = '37648'",
        "userid and auth_tan are immutable");
    assertRefused(
        "UPDATE employees SET auth_tan = 'ZZZZZZ' WHERE userid = '37648'",
        "userid and auth_tan are immutable");
  }

  @Test
  void impossibleValuesAreRejected() {
    assertRefused(
        "INSERT INTO employees VALUES ('1', 'A', 'B', 'Sales', 999999, 'ABC123')",
        "IG_EMP_SALARY_RANGE");
    assertRefused(
        "INSERT INTO employees VALUES ('2', 'A', 'B', 'Sales', 50000, 'abc')",
        "IG_EMP_TAN_FORMAT");
  }

  @Test
  void accessLogIsAppendOnly() throws SQLException {
    execute("INSERT INTO access_log (time, action) VALUES ('t1', 'search: Smith')");

    assertRefused("DELETE FROM access_log", "access_log is append-only");
    assertRefused("UPDATE access_log SET action = 'nothing'", "access_log is append-only");
    assertThat(query("SELECT COUNT(*) FROM access_log")).isEqualTo("1");
  }

  @Test
  void challengePasswordsCannotBeOverwritten() throws SQLException {
    assertRefused(
        "UPDATE sql_challenge_users SET password = 'pwned1' WHERE userid = 'tom'",
        "credentials can only be changed via the password-reset procedure");

    assertThat(query("SELECT password FROM sql_challenge_users WHERE userid = 'tom'"))
        .isEqualTo("thisisasecretfortomonly");
  }

  @Test
  void signUpStillWorks() throws SQLException {
    execute("INSERT INTO sql_challenge_users VALUES ('newbie', 'newbie@webgoat.org', 'secret1')");

    assertThat(query("SELECT COUNT(*) FROM sql_challenge_users")).isEqualTo("5");
  }

  @Test
  void believableChangesAreNotBlocked() throws SQLException {
    // Known limitation: L4 only stops implausible changes, so moving Tobi to Sales (A5) still works.
    execute("UPDATE employees SET department = 'Sales' WHERE last_name = 'Barnett'");

    assertThat(query("SELECT department FROM employees WHERE last_name = 'Barnett'"))
        .isEqualTo("Sales");
  }

  private void execute(String sql) throws SQLException {
    try (var statement = connection.createStatement()) {
      statement.execute(sql);
    }
  }

  private String query(String sql) throws SQLException {
    try (var statement = connection.createStatement();
        var rs = statement.executeQuery(sql)) {
      assertThat(rs.next()).isTrue();
      return rs.getString(1);
    }
  }

  private void assertRefused(String sql, String message) {
    assertThatThrownBy(() -> execute(sql))
        .isInstanceOf(SQLException.class)
        .hasMessageContaining(message);
  }
}
