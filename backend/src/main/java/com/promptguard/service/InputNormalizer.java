package com.promptguard.service;

import org.springframework.stereotype.Component;

/**
 * InputNormalizer — Layer 0 Protection.
 * Standardizes text to defeat basic obfuscation (e.g., s-s-n, p.a.s.s.w.o.r.d).
 */
@Component
public class InputNormalizer {

    public String normalize(String input) {
        if (input == null) return "";
        
        // 1. Lowercase
        String text = input.toLowerCase();
        
        // 2. Remove common separator characters used for obfuscation (e.g. s-s-n -> ssn)
        // Removes: . - _ * / | \ [ ] { } ( ) + =
        text = text.replaceAll("[.\\-_*/|\\\\\\+\\=\\[\\]{}\\(\\)]", "");
        
        // 3. Remove extra whitespace and trim
        text = text.replaceAll("\\s+", " ").trim();
        
        return text;
    }
}
