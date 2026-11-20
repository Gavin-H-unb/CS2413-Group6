package org.owasp.webgoat.lessons.sqlinjection;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SafeErrors {
    private static final Logger LOG = LoggerFactory.getLogger(SafeErrors.class);

    private SafeErrors() {}

    public static String message(Exception e) {
        String ref = UUID.randomUUID().toString().substring(0, 8);
        LOG.warn("[L6] database error ref={}: {}", ref, e.getMessage());
        return "A database error occurred (reference " + ref + ").";
    }
}
