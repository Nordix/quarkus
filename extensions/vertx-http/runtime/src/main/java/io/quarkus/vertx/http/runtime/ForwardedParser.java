/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

// This code was Heavily influenced from spring forward header parser
// https://github.com/spring-projects/spring-framework/blob/main/spring-web/src/main/java/org/springframework/web/util/UriComponentsBuilder.java#L849

package io.quarkus.vertx.http.runtime;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;

import io.netty.util.AsciiString;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.HostAndPort;
import io.vertx.core.net.SocketAddress;
import io.vertx.core.net.impl.SocketAddressImpl;

class ForwardedParser {
    private static final Logger log = Logger.getLogger(ForwardedParser.class);

    private static final String HTTP_SCHEME = "http";
    private static final String HTTPS_SCHEME = "https";
    private static final AsciiString FORWARDED = AsciiString.cached("Forwarded");
    private static final AsciiString X_FORWARDED_SSL = AsciiString.cached("X-Forwarded-Ssl");
    private static final AsciiString X_FORWARDED_PROTO = AsciiString.cached("X-Forwarded-Proto");
    private static final AsciiString X_FORWARDED_PORT = AsciiString.cached("X-Forwarded-Port");
    private static final AsciiString X_FORWARDED_FOR = AsciiString.cached("X-Forwarded-For");

    private static final Pattern FORWARDED_HOST_PATTERN = Pattern.compile("host=\"?([^;,\"]+)\"?");
    private static final Pattern FORWARDED_PROTO_PATTERN = Pattern.compile("proto=\"?([^;,\"]+)\"?");
    private static final Pattern FORWARDED_FOR_PATTERN = Pattern.compile("for=\"?([^;,\"]+)\"?");

    private final static int PORT_MIN_VALID_VALUE = 0;
    private final static int PORT_MAX_VALID_VALUE = 65535;

    private final HttpServerRequest delegate;
    private final ForwardingProxyOptions forwardingProxyOptions;
    private final TrustedProxyCheck trustedProxyCheck;

    private boolean calculated;
    private String host;
    private int port = -1;
    private String scheme;
    private String uri;
    private String absoluteURI;
    private SocketAddress remoteAddress;

    private HostAndPort authority;

    ForwardedParser(HttpServerRequest delegate, ForwardingProxyOptions forwardingProxyOptions,
            TrustedProxyCheck trustedProxyCheck) {
        this.delegate = delegate;
        this.forwardingProxyOptions = forwardingProxyOptions;
        this.trustedProxyCheck = trustedProxyCheck;
    }

    public String scheme() {
        if (!calculated)
            calculate();
        return scheme;
    }

    String host() {
        if (!calculated)
            calculate();
        return host;
    }

    boolean isSSL() {
        if (!calculated)
            calculate();

        return scheme.equals(HTTPS_SCHEME);
    }

    HostAndPort authority() {
        if (!calculated) {
            calculate();
        }
        return authority;
    }

    String absoluteURI() {
        if (!calculated)
            calculate();

        return absoluteURI;
    }

    SocketAddress remoteAddress() {
        if (!calculated)
            calculate();

        return remoteAddress;
    }

    String uri() {
        if (!calculated)
            calculate();

        return uri;
    }

    private void calculate() {
        calculated = true;
        remoteAddress = delegate.remoteAddress();
        scheme = delegate.scheme();
        setHostAndPort(delegate.getHeader(HttpHeaders.HOST), port);
        uri = delegate.uri();

        if (trustedProxyCheck.isProxyAllowed()) {
            String schemeFromHeader = null;
            String hostFromHeader = null;
            SocketAddress remoteAddressFromHeader = null;
            int portFromHeader = -1;

            String forwarded = delegate.getHeader(FORWARDED);
            if (forwardingProxyOptions.allowForwarded && forwarded != null) {
                Matcher matcher = FORWARDED_PROTO_PATTERN.matcher(forwarded);
                if (matcher.find()) {
                    schemeFromHeader = (matcher.group(1).trim());
                }

                matcher = FORWARDED_HOST_PATTERN.matcher(forwarded);
                if (matcher.find()) {
                    hostFromHeader = matcher.group(1).trim();
                }

                matcher = FORWARDED_FOR_PATTERN.matcher(forwarded);
                if (matcher.find()) {
                    remoteAddressFromHeader = parseFor(matcher.group(1).trim(),
                            remoteAddress != null ? remoteAddress.port() : port);
                }
            }

            if (forwardingProxyOptions.allowXForwarded) {
                String protocolHeader = delegate.getHeader(X_FORWARDED_PROTO);
                if (protocolHeader != null) {
                    String val = getFirstElement(protocolHeader);
                    // If both Forwarded proto and X-Forwarded-Proto are specified, they need to be consistent.
                    if (schemeFromHeader != null && !schemeFromHeader.equals(val)) {
                       delegate.response().setStatusCode(400).end("Mismatch protocol given in Forwarded and X-Forwarded-Proto");
                    }
                    schemeFromHeader = val;
                    port = -1;
                }

                String forwardedSsl = delegate.getHeader(X_FORWARDED_SSL);
                boolean isForwardedSslOn = forwardedSsl != null && forwardedSsl.equalsIgnoreCase("on");
                if (isForwardedSslOn) {
                    // If both Forwarded proto and X-Forwarded-Ssl are specified, they need to be consistent.
                    if (schemeFromHeader != null && !schemeFromHeader.equals(HTTPS_SCHEME)) {
                        delegate.response().setStatusCode(400).end("Mismatch protocol given in Forwarded and X-Forwarded-Ssl");
                    }
                    schemeFromHeader = HTTPS_SCHEME;
                    port = -1;
                }

                if (forwardingProxyOptions.enableForwardedHost) {
                    String hostHeader = delegate.getHeader(forwardingProxyOptions.forwardedHostHeader);
                    if (hostHeader != null) {
                        String val = getFirstElement(hostHeader);
                        // If both Forwarded host and X-Forwarded-Host are specified, they need to be consistent.
                        if (hostFromHeader != null && !hostFromHeader.equals(val)) {
                            delegate.response().setStatusCode(400).end("Mismatch host given in Forwarded and X-Forwarded-Host");
                        }
                        hostFromHeader = val;
                    }
                }

                if (forwardingProxyOptions.enableForwardedPrefix) {
                    String prefixHeader = delegate.getHeader(forwardingProxyOptions.forwardedPrefixHeader);
                    if (prefixHeader != null) {
                        uri = appendPrefixToUri(prefixHeader, uri);
                    }
                }

                String portHeader = delegate.getHeader(X_FORWARDED_PORT);
                if (portHeader != null) {
                    portFromHeader = parsePort(getFirstElement(portHeader), port);
                    // If both Forwarded port and X-Forwarded-Port are specified, they need to be consistent.
                    if (port != -1 && portFromHeader != -1 && port != portFromHeader) {
                        delegate.response().setStatusCode(400).end("Mismatch port given in Forwarded and X-Forwarded-Port");
                    }
                }

                String forHeader = delegate.getHeader(X_FORWARDED_FOR);
                if (forHeader != null) {
                    remoteAddressFromHeader = parseFor(getFirstElement(forHeader),
                            remoteAddress != null ? remoteAddress.port() : port);
                    // If both Forwarded for and X-Forwarded-For are specified, they need to be consistent.
                    if (remoteAddress != null && !remoteAddress.equals(remoteAddressFromHeader)) {
                        delegate.response().setStatusCode(400).end("Mismatch address given in Forwarded and X-Forwarded-For");
                    }
                }
            }

            if (schemeFromHeader != null) {
                scheme = schemeFromHeader;
            }
            if (hostFromHeader != null) {
                setHostAndPort(hostFromHeader, port);
            }
            if (remoteAddressFromHeader != null) {
                remoteAddress = remoteAddressFromHeader;
            }
            if (portFromHeader != -1) {
                port = portFromHeader;
            }
        }

        if (((scheme.equals(HTTP_SCHEME) && port == 80) || (scheme.equals(HTTPS_SCHEME) && port == 443))) {
            port = -1;
        }

        authority = HostAndPort.create(host, port >= 0 ? port : -1);
        host = host + (port >= 0 ? ":" + port : "");
        delegate.headers().set(HttpHeaders.HOST, host);
        absoluteURI = scheme + "://" + host + uri;
        log.debug("Recalculated absoluteURI to " + absoluteURI);
    }

    private void setHostAndPort(String hostToParse, int defaultPort) {
        if (hostToParse == null) {
            hostToParse = "";
        }
        String[] hostAndPort = parseHostAndPort(hostToParse);
        host = hostAndPort[0];
        delegate.headers().set(HttpHeaders.HOST, host);
        port = parsePort(hostAndPort[1], defaultPort);
    }

    private SocketAddress parseFor(String forToParse, int defaultPort) {
        String[] hostAndPort = parseHostAndPort(forToParse);
        String host = hostAndPort[0];
        int port = parsePort(hostAndPort[1], defaultPort);
        return new SocketAddressImpl(port, host);
    }

    private String getFirstElement(String value) {
        int index = value.indexOf(',');
        return index == -1 ? value : value.substring(0, index);
    }

    /**
     * Returns a String[] of 2 elements, with the first being the host and the second the port
     */
    private String[] parseHostAndPort(String hostToParse) {
        String[] hostAndPort = { hostToParse, "" };
        int portSeparatorIdx = hostToParse.lastIndexOf(':');
        int squareBracketIdx = hostToParse.lastIndexOf(']');
        if ((squareBracketIdx > -1 && portSeparatorIdx > squareBracketIdx)) {
            // ipv6 with port
            hostAndPort[0] = hostToParse.substring(0, portSeparatorIdx);
            hostAndPort[1] = hostToParse.substring(portSeparatorIdx + 1);
        } else {
            long numberOfColons = hostToParse.chars().filter(ch -> ch == ':').count();
            if (numberOfColons == 1 && !hostToParse.endsWith(":")) {
                // ipv4 with port
                hostAndPort[0] = hostToParse.substring(0, portSeparatorIdx);
                hostAndPort[1] = hostToParse.substring(portSeparatorIdx + 1);
            }
        }
        return hostAndPort;
    }

    private int parsePort(String portToParse, int defaultPort) {
        if (portToParse != null && portToParse.length() > 0) {
            try {
                int port = Integer.parseInt(portToParse);
                if (port < PORT_MIN_VALID_VALUE || port > PORT_MAX_VALID_VALUE) {
                    log.errorf("Failed to validate a port from \"forwarded\"-type headers, using the default port %d",
                            defaultPort);
                    return defaultPort;
                }
                return port;
            } catch (NumberFormatException ignored) {
                log.errorf("Failed to parse a port from \"forwarded\"-type headers, using the default port %d", defaultPort);
            }
        }
        return defaultPort;
    }

    private String appendPrefixToUri(String prefix, String uri) {
        String parsed = stripSlashes(prefix);
        return parsed.isEmpty() ? uri : '/' + parsed + uri;
    }

    private String stripSlashes(String uri) {
        String result;
        if (!uri.isEmpty()) {
            int beginIndex = 0;
            if (uri.startsWith("/")) {
                beginIndex = 1;
            }

            int endIndex = uri.length();
            if (uri.endsWith("/") && uri.length() > 1) {
                endIndex = uri.length() - 1;
            }
            result = uri.substring(beginIndex, endIndex);
        } else {
            result = uri;
        }

        return result;
    }

}
