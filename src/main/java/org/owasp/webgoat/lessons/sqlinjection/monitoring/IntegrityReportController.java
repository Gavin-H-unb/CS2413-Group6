/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.monitoring;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** CS2413 Group 6 - Layer 5: tamper detection and audit reporting. */
@RestController
public class IntegrityReportController {

  /** Table, key column, and columns covered by the seal. */
  private static final List<String[]> SEALED =
      List.of(
          new String[] {
            "EMPLOYEES", "USERID", "USERID,FIRST_NAME,LAST_NAME,DEPARTMENT,SALARY,AUTH_TAN"
          },
          new String[] {"SQL_CHALLENGE_USERS", "USERID", "USERID,EMAIL,PASSWORD"});

  private final DataSource dataSource;
  private final byte[] key;

  public IntegrityReportController(DataSource dataSource) throws IOException {
    this.dataSource = dataSource;
    this.key =
        loadOrCreateKey(
            Path.of(System.getProperty("user.home"), ".webgoat-integrity", "hmac.key"));
  }

  @GetMapping(value = "/integrity/report", produces = MediaType.APPLICATION_JSON_VALUE)
  public Map<String, Object> report(@AuthenticationPrincipal WebGoatUser user) throws SQLException {
    Map<String, Object> result = new LinkedHashMap<>();
    try (Connection c = connect(user)) {
      if (count(c, "SELECT COUNT(*) FROM integrity_seal") == 0) {
        sealAll(c);
        result.put("note", "No seals yet: the current data was sealed as the clean baseline.");
      }
      List<String> findings = verify(c);
      result.put("status", findings.isEmpty() ? "INTACT" : "TAMPERED");
      result.put("findings", findings);
      result.put("accessLogPresent", tableExists(c, "ACCESS_LOG"));
      result.put(
          "auditTrail",
          rows(
              c,
              "SELECT changed_at, table_name, op, row_key, detail, db_user"
                  + " FROM integrity_audit ORDER BY id DESC"));
      result.put(
          "employees",
          rows(
              c,
              "SELECT userid, last_name, department, salary FROM employees"
                  + " ORDER BY salary DESC"));
    }
    return result;
  }

  /** Re-seal the current data as the new clean baseline after a lesson reset. */
  @PostMapping(value = "/integrity/seal", produces = MediaType.APPLICATION_JSON_VALUE)
  public Map<String, Object> reseal(@AuthenticationPrincipal WebGoatUser user)
      throws SQLException {
    try (Connection c = connect(user)) {
      return Map.of("sealedRows", sealAll(c));
    }
  }

  private int sealAll(Connection c) throws SQLException {
    try (Statement s = c.createStatement()) {
      s.execute("DELETE FROM integrity_seal");
    }
    int n = 0;
    for (String[] t : SEALED) {
      for (Map<String, String> row : read(c, t)) {
        try (PreparedStatement ps =
            c.prepareStatement(
                "INSERT INTO integrity_seal (table_name, row_key, sealed_values, seal)"
                    + " VALUES (?, ?, ?, ?)")) {
          String canonical = canonical(row);
          ps.setString(1, t[0]);
          ps.setString(2, row.get(t[1]));
          ps.setString(3, canonical);
          ps.setString(4, hmac(canonical));
          ps.executeUpdate();
          n++;
        }
      }
    }
    return n;
  }

  private List<String> verify(Connection c) throws SQLException {
    List<String> findings = new ArrayList<>();
    for (String[] t : SEALED) {
      Map<String, String[]> seals = new LinkedHashMap<>();
      try (PreparedStatement ps =
          c.prepareStatement(
              "SELECT row_key, sealed_values, seal FROM integrity_seal WHERE table_name = ?")) {
        ps.setString(1, t[0]);
        try (ResultSet rs = ps.executeQuery()) {
          while (rs.next()) {
            seals.put(rs.getString(1), new String[] {rs.getString(2), rs.getString(3)});
          }
        }
      }
      for (Map<String, String> row : read(c, t)) {
        String rowKey = row.get(t[1]);
        String[] seal = seals.remove(rowKey);
        String canonical = canonical(row);
        if (seal == null) {
          findings.add(
              t[0] + " " + rowKey + ": NEW row since the last seal (check it is legitimate)");
        } else if (!MessageDigest.isEqual(hmac(canonical).getBytes(), seal[1].getBytes())) {
          findings.add(t[0] + " " + rowKey + ": MODIFIED (" + diff(seal, canonical) + ")");
        }
      }
      for (String missing : seals.keySet()) {
        findings.add(t[0] + " " + missing + ": row was DELETED");
      }
    }
    return findings;
  }

  /** List changed columns while keeping password and TAN values out of the report. */
  private String diff(String[] seal, String currentCanonical) {
    if (!MessageDigest.isEqual(hmac(seal[0]).getBytes(), seal[1].getBytes())) {
      return "the seal record itself was forged";
    }
    Map<String, String> before = parse(seal[0]);
    Map<String, String> after = parse(currentCanonical);
    List<String> changes = new ArrayList<>();
    for (var e : before.entrySet()) {
      String now = after.get(e.getKey());
      if (!e.getValue().equals(now)) {
        boolean secret = e.getKey().equals("PASSWORD") || e.getKey().equals("AUTH_TAN");
        changes.add(
            secret
                ? e.getKey().toLowerCase() + " changed"
                : e.getKey().toLowerCase() + ": " + e.getValue() + " -> " + now);
      }
    }
    return String.join(", ", changes);
  }

  private static String canonical(Map<String, String> row) {
    StringBuilder sb = new StringBuilder();
    row.forEach((k, v) -> sb.append(k).append('=').append(v).append('\u001F'));
    return sb.toString();
  }

  private static Map<String, String> parse(String canonical) {
    Map<String, String> m = new LinkedHashMap<>();
    for (String part : canonical.split("\u001F")) {
      int eq = part.indexOf('=');
      if (eq > 0) {
        m.put(part.substring(0, eq), part.substring(eq + 1));
      }
    }
    return m;
  }

  private String hmac(String text) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return HexFormat.of().formatHex(mac.doFinal(text.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] loadOrCreateKey(Path file) throws IOException {
    if (Files.exists(file)) {
      return HexFormat.of().parseHex(Files.readString(file).trim());
    }
    byte[] k = new byte[32];
    new SecureRandom().nextBytes(k);
    Files.createDirectories(file.getParent());
    Files.writeString(file, HexFormat.of().formatHex(k));
    return k;
  }

  private Connection connect(WebGoatUser user) throws SQLException {
    Connection c = dataSource.getConnection();
    try (Statement s = c.createStatement()) {
      s.execute("SET SCHEMA \"" + user.getUsername() + "\"");
    }
    return c;
  }

  private static List<Map<String, String>> read(Connection c, String[] t) throws SQLException {
    List<Map<String, String>> out = new ArrayList<>();
    String[] cols = t[2].split(",");
    try (Statement s = c.createStatement();
        ResultSet rs = s.executeQuery("SELECT " + t[2] + " FROM " + t[0])) {
      while (rs.next()) {
        Map<String, String> row = new LinkedHashMap<>();
        for (int i = 0; i < cols.length; i++) {
          row.put(cols[i], rs.getString(i + 1));
        }
        out.add(row);
      }
    }
    return out;
  }

  private static int count(Connection c, String sql) throws SQLException {
    try (Statement s = c.createStatement();
        ResultSet rs = s.executeQuery(sql)) {
      rs.next();
      return rs.getInt(1);
    }
  }

  private static boolean tableExists(Connection c, String table) throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT 1 FROM INFORMATION_SCHEMA.TABLES"
                + " WHERE TABLE_SCHEMA = CURRENT_SCHEMA AND TABLE_NAME = ?")) {
      ps.setString(1, table);
      try (ResultSet rs = ps.executeQuery()) {
        return rs.next();
      }
    }
  }

  private static List<Map<String, Object>> rows(Connection c, String sql) throws SQLException {
    List<Map<String, Object>> out = new ArrayList<>();
    try (Statement s = c.createStatement();
        ResultSet rs = s.executeQuery(sql)) {
      ResultSetMetaData md = rs.getMetaData();
      while (rs.next()) {
        Map<String, Object> row = new LinkedHashMap<>();
        for (int i = 1; i <= md.getColumnCount(); i++) {
          row.put(md.getColumnLabel(i).toLowerCase(), String.valueOf(rs.getObject(i)));
        }
        out.add(row);
      }
    }
    return out;
  }
}
