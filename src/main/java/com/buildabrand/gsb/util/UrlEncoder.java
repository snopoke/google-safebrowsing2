package com.buildabrand.gsb.util;

/*
 * JBoss DNA (http://www.jboss.org/dna)
 * See the COPYRIGHT.txt file distributed with this work for information
 * regarding copyright ownership.  Some portions may be licensed
 * to Red Hat, Inc. under one or more contributor license agreements.
 * See the AUTHORS.txt file in the distribution for a full listing of 
 * individual contributors. 
 *
 * JBoss DNA is free software. Unless otherwise indicated, all code in JBoss DNA
 * is licensed to you under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * JBoss DNA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.BitSet;

/**
 * An encoder useful for converting text to be used within a URL, as defined by Section 2.3 of <a
 * href="http://www.ietf.org/rfc/rfc2396.txt">RFC 2396</a>. Note that this class does not encode a complete URL ({@link java.net.URLEncoder}
 * and {@link java.net.URLDecoder} should be used for such purposes).
 * 
 * @author Randall Hauch
 */
public class UrlEncoder  {

    /**
     * Data characters that are allowed in a URI but do not have a reserved purpose are called unreserved. These include upper and
     * lower case letters, decimal digits, and a limited set of punctuation marks and symbols.
     * 
     * <pre>
     * unreserved  = alphanum | mark
     * mark        = &quot;-&quot; | &quot;_&quot; | &quot;.&quot; | &quot;!&quot; | &quot;&tilde;&quot; | &quot;*&quot; | &quot;'&quot; | &quot;(&quot; | &quot;)&quot;
     * </pre>
     * 
     * Unreserved characters can be escaped without changing the semantics of the URI, but this should not be done unless the URI
     * is being used in a context that does not allow the unescaped character to appear.
     */
    private static final BitSet RFC2396_UNRESERVED_CHARACTERS = new BitSet(256);

    public static final char ESCAPE_CHARACTER = '%';

    static {
        RFC2396_UNRESERVED_CHARACTERS.set(33, 127);
        RFC2396_UNRESERVED_CHARACTERS.clear('%');
        RFC2396_UNRESERVED_CHARACTERS.clear('#');
    }

    private boolean slashEncoded = true;

    /**
     * {@inheritDoc}
     */
    public String encode( String text ) {
        if (text == null) return null;
        if (text.length() == 0) return text;
        final BitSet safeChars = RFC2396_UNRESERVED_CHARACTERS;
        final StringBuilder result = new StringBuilder();
        final CharacterIterator iter = new StringCharacterIterator(text);
        for (char c = iter.first(); c != CharacterIterator.DONE; c = iter.next()) {
            if (safeChars.get(c)) {
                // Safe character, so just pass through ...
                result.append(c);
            } else {
                // The character is not a safe character, and must be escaped ...
                result.append(ESCAPE_CHARACTER);
                result.append(Character.toUpperCase(Character.forDigit(c / 16, 16)));
                result.append(Character.toUpperCase(Character.forDigit(c % 16, 16)));
            }
        }
        return result.toString();
    }

    /**
     * {@inheritDoc}
     */
    public String decode( String encodedText ) {
        if (encodedText == null) return null;
        if (encodedText.length() == 0) return encodedText;
        final StringBuilder result = new StringBuilder();
        final CharacterIterator iter = new StringCharacterIterator(encodedText);
        for (char c = iter.first(); c != CharacterIterator.DONE; c = iter.next()) {
            if (c == ESCAPE_CHARACTER) {
                boolean foundEscapedCharacter = false;
                // Found the first character in a potential escape sequence, so grab the next two characters ...
                int cIdx = iter.getIndex();
                char hexChar1 = iter.next();
                char hexChar2 = hexChar1 != CharacterIterator.DONE ? iter.next() : CharacterIterator.DONE;
                if (hexChar2 != CharacterIterator.DONE) {
                    // We found two more characters, but ensure they form a valid hexadecimal number ...
                    int hexNum1 = Character.digit(hexChar1, 16);
                    int hexNum2 = Character.digit(hexChar2, 16);
                    if (hexNum1 > -1 && hexNum2 > -1) {
                        foundEscapedCharacter = true;
                        result.append((char)(hexNum1 * 16 + hexNum2));
                    }
                }
                if (!foundEscapedCharacter) {
                    // This is not escape, so we should restore the index.
                    result.append(c);
                    iter.setIndex(cIdx);
                }
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

}