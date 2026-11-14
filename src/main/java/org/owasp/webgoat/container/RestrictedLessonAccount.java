/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import javax.sql.DataSource;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * CS2413 Group 6 - Layer 3: least-privilege database account.
 *
 * <p>The SQL-injection endpoints listed in {@link #RESTRICTED_PATHS} no longer talk to the
 * database as the all-powerful SA (DBA) account. They use the login {@value #USER}, which may only
 * read the lookup tables and append to the logs. Even if an attacker injects SQL, the database
 * itself refuses UPDATE, DELETE, DROP, ALTER and GRANT.
 */
public class RestrictedLessonAccount {

  private static final Logger LOG = LoggerFactory.getLogger(RestrictedLessonAccount.class);

  static final String ROLE = "WG_LESSON_APP_ROLE";
  static final String USER = "WG_LESSON_APP";

  /** Endpoints (path inside /WebGoat) whose SQL runs as the restricted account. */
  private static final Set<String> RESTRICTED_PATHS =
      Set.of(
          "/SqlInjection/attack3",
          "/SqlInjection/attack4",
          "/SqlInjection/attack5",
          "/SqlInjection/attack8",
          "/SqlInjection/attack9",
          "/SqlInjection/attack10",
          "/SqlInjectionAdvanced/register",
          "/SqlInjectionMitigations/servers");

  /** The ONLY privileges the account gets, per lesson schema. Nothing can be changed or dropped. */
  private static final List<String> GRANTS =
      List.of(
          "GRANT SELECT ON %s.EMPLOYEES TO " + ROLE,
          "GRANT SELECT, INSERT ON %s.ACCESS_LOG TO " + ROLE,
          "GRANT SELECT, INSERT ON %s.SQL_CHALLENGE_USERS TO " + ROLE,
          "GRANT SELECT ON %s.SERVERS TO " + ROLE);

  private final DataSource adminDataSource;

  // a new random password every start-up; it never leaves the program
  private final String password = HexFormat.of().formatHex(randomBytes(24));

  private volatile boolean accountReady;

  public RestrictedLessonAccount(DataSource adminDataSource) {
    this.adminDataSource = adminDataSource;
  }

  /** True when the current HTTP request is one of the restricted endpoints. */
  public static boolean appliesToCurrentRequest() {
    if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
      HttpServletRequest request = attrs.getRequest();
      return RESTRICTED_PATHS.contains(request.getServletPath());
    }
    return false;
  }

  /** Opens a connection as the restricted login (the caller still sets the user's schema). */
  public Connection open() throws SQLException {
    String schema = currentSchema();
    ensureAccount();
    if (schema != null) {
      grantMinimalPrivileges(schema);
    }
    return adminDataSource.getConnection(USER, password);
  }

  private static String currentSchema() {
    var auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null && auth.getPrincipal() instanceof WebGoatUser user) {
      return user.getUsername();
    }
    return null;
  }

  private synchronized void ensureAccount() throws SQLException {
    if (accountReady) {
      return;
    }
    try (Connection c = adminDataSource.getConnection();
        Statement s = c.createStatement()) {
      String roleQuery = "SELECT 1 FROM INFORMATION_SCHEMA.APPLICABLE_ROLES WHERE ROLE_NAME = ?";
      if (!exists(c, roleQuery, ROLE)) {
        s.execute("CREATE ROLE " + ROLE);
      }
      if (exists(c, "SELECT 1 FROM INFORMATION_SCHEMA.SYSTEM_USERS WHERE USER_NAME = ?", USER)) {
        s.execute("ALTER USER " + USER + " SET PASSWORD '" + password + "'");
      } else {
        s.execute("CREATE USER " + USER + " PASSWORD '" + password + "'");
        s.execute("GRANT " + ROLE + " TO " + USER);
      }
    }
    accountReady = true;
    LOG.info("[L3] restricted database login {} ready", USER);
  }

  /**
   * Re-applied on every use because "Reset lesson" drops and re-creates the tables (and with them
   * the grants). Repeating a GRANT is harmless.
   */
  private void grantMinimalPrivileges(String schema) {
    String quoted = "\"" + schema.replace("\"", "") + "\"";
    try (Connection c = adminDataSource.getConnection();
        Statement s = c.createStatement()) {
      for (String grant : GRANTS) {
        try {
          s.execute(String.format(grant, quoted));
        } catch (SQLException e) {
          LOG.debug("[L3] grant skipped ({}): {}", grant, e.getMessage());
        }
      }
    } catch (SQLException e) {
      LOG.warn("[L3] could not apply grants for {}: {}", schema, e.getMessage());
    }
  }

  private static boolean exists(Connection c, String sql, String arg) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(sql)) {
      ps.setString(1, arg);
      try (ResultSet rs = ps.executeQuery()) {
        return rs.next();
      }
    }
  }

  private static byte[] randomBytes(int n) {
    byte[] b = new byte[n];
    new SecureRandom().nextBytes(b);
    return b;
  }
}
