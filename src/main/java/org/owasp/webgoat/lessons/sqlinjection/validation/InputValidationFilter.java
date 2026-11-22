/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.validation;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * CS2413 Group 6 - Layer 1: allowlist input validation.
 *
 * <p>Runs before the SQL-injection lesson endpoints and rejects any parameter that does not match
 * the narrowest format a legitimate value can have. Nothing else in WebGoat has to change: if a
 * value is valid, the request continues to the lesson exactly as before.
 */
@Component
public class InputValidationFilter extends OncePerRequestFilter {

  private static final Logger LOG = LoggerFactory.getLogger(InputValidationFilter.class);

  /** One allowlist rule: parameter name, pattern, and the message shown when it fails. */
  private record Rule(String param, Pattern pattern, String message) {}

  private static Rule rule(String param, String regex, String message) {
    return new Rule(param, Pattern.compile(regex), message);
  }

  // Surnames may contain letters, spaces, apostrophes (O'Brien), dots and hyphens.
  private static final Rule LAST_NAME =
      rule(
          "name",
          "^[\\p{L}][\\p{L} .'-]{0,19}$",
          "name must be 1-20 letters (space . ' - allowed)");
  // WebGoat TANs are exactly six upper-case letters or digits.
  private static final Rule AUTH_TAN =
      rule("auth_tan", "^[A-Z0-9]{6}$", "auth_tan must be exactly 6 characters A-Z / 0-9");
  // Searching the access log: no quotes, semicolons or comment markers.
  private static final Rule SEARCH =
      rule(
          "action_string",
          "^[\\p{L}\\p{N} _.@:/-]{0,50}$",
          "search term may only contain letters, digits, space and _ . @ : / -");

  private static final Rule USERNAME =
      rule(
          "username_reg",
          "^[A-Za-z0-9_.-]{3,30}$",
          "username must be 3-30 characters A-Z 0-9 _ . -");
  private static final Rule EMAIL =
      rule(
          "email_reg",
          "^[A-Za-z0-9._%+-]{1,20}@[A-Za-z0-9.-]{1,20}\\.[A-Za-z]{2,6}$",
          "email must be a valid e-mail address");

  /** Which rules apply to which endpoint (path inside /WebGoat). */
  private static final Map<String, List<Rule>> RULES =
      Map.of(
          "/SqlInjection/attack8", List.of(LAST_NAME, AUTH_TAN),
          "/SqlInjection/attack9", List.of(LAST_NAME, AUTH_TAN),
          "/SqlInjection/attack10", List.of(SEARCH),
          "/SqlInjectionAdvanced/register", List.of(USERNAME, EMAIL));

  /** ORDER BY needs a column NAME, which a PreparedStatement cannot bind, so only these pass. */
  private static final String SERVERS_PATH = "/SqlInjectionMitigations/servers";

  private static final Set<String> SORT_COLUMNS =
      Set.of("id", "hostname", "ip", "mac", "status", "description");

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String path = request.getServletPath();

    if (SERVERS_PATH.equals(path)) {
      String column = request.getParameter("column");
      if (column == null || !SORT_COLUMNS.contains(column.toLowerCase())) {
        LOG.warn("[L1] blocked ORDER BY value on {}", path);
        response.sendError(
            HttpServletResponse.SC_BAD_REQUEST,
            "Blocked by L1 input validation: column must be one of " + SORT_COLUMNS);
        return;
      }
    }

    List<Rule> rules = RULES.get(path);
    if (rules != null) {
      for (Rule r : rules) {
        String value = request.getParameter(r.param());
        if (value == null || !r.pattern().matcher(value).matches()) {
          LOG.warn("[L1] blocked {} on {}", r.param(), path);
          writeBlocked(response, r.message());
          return;
        }
      }
    }
    chain.doFilter(request, response);
  }

  /** Answers in the same JSON shape as a lesson, so the WebGoat page shows the message. */
  private static void writeBlocked(HttpServletResponse response, String message)
      throws IOException {
    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType("application/json;charset=UTF-8");
    response
        .getWriter()
        .write(
            "{\"lessonCompleted\":false,\"attemptWasMade\":true,"
                + "\"feedback\":\"Blocked by L1 input validation: "
                + message.replace("\"", "'")
                + "\",\"output\":null}");
  }
}
