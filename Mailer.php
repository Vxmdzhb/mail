<?php

declare(strict_types = 1);

namespace AstrX\Mail;

use AstrX\Config\InjectConfig;
use AstrX\Mail\Diagnostic\MailInvalidRecipientDiagnostic;
use AstrX\Mail\Diagnostic\MailSendFailedDiagnostic;
use AstrX\Result\DiagnosticLevel;
use AstrX\Result\Diagnostics;
use AstrX\Result\Result;

/**
 * Simple SMTP mailer for transactional emails (registration, password reset, etc.).
 * Connects directly to an SMTP server using PHP streams — no external library
 * required. Supports STARTTLS, SMTPS (implicit TLS), and plain connections.
 * Configuration (Mail.config.php):
 *   host         SMTP server hostname or .onion address
 *   port         SMTP port (587 = submission STARTTLS, 465 = SMTPS, 25 = plain)
 *   username     SMTP auth username (leave empty to skip AUTH)
 *   password     SMTP auth password
 *   from_address The envelope From address
 *   from_name    Display name for the From header
 *   encryption   'tls' (STARTTLS), 'ssl' (implicit TLS), or '' (plain)
 *   timeout      Connection timeout in seconds (default 30)
 * When connecting to a .onion address, set a SOCKS5 proxy:
 *   socks5_host  Tor SOCKS5 proxy host (e.g. 'tor-client')
 *   socks5_port  Tor SOCKS5 proxy port (default 9050)
 */
final class Mailer
{

    public const string ID_MAIL_ERROR = 'astrx.mail/error';
    private string $host = 'localhost';
    private int $port = 587;
    private string $username = '';
    private string $password = '';
    private string $fromAddress = '';
    private string $fromName = '';
    private string $encryption = 'tls';   // 'tls' | 'ssl' | ''
    private int $timeout = 30;
    private string $socks5Host = '';
    private int $socks5Port = 9050;
    /**
     * Verify the SMTP server's TLS certificate (STARTTLS + implicit-TLS paths).
     * Keep true for clearnet. Onion-only deployments may set it false because
     * Tor already authenticates the hidden service.
     */
    private bool $smtpVerifySsl = true;

    #[InjectConfig('host')]
    public function setHost(string $v)
    : void {
        $this->host = $v;
    }

    #[InjectConfig('port')]
    public function setPort(int $v)
    : void {
        $this->port = $v;
    }

    #[InjectConfig('username')]
    public function setUsername(string $v)
    : void {
        $this->username = $v;
    }

    #[InjectConfig('password')]
    public function setPassword(string $v)
    : void {
        $this->password = $v;
    }

    #[InjectConfig('from_address')]
    public function setFromAddress(string $v)
    : void {
        $this->fromAddress = $v;
    }

    #[InjectConfig('from_name')]
    public function setFromName(string $v)
    : void {
        $this->fromName = $v;
    }

    #[InjectConfig('encryption')]
    public function setEncryption(string $v)
    : void {
        $this->encryption = $v;
    }

    #[InjectConfig('timeout')]
    public function setTimeout(int $v)
    : void {
        $this->timeout = max(1, $v);
    }

    #[InjectConfig('socks5_host')]
    public function setSocks5Host(string $v)
    : void {
        $this->socks5Host = $v;
    }

    #[InjectConfig('socks5_port')]
    public function setSocks5Port(int $v)
    : void {
        $this->socks5Port = $v;
    }

    #[InjectConfig('smtp_verify_ssl')]
    public function setSmtpVerifySsl(bool $v)
    : void {
        $this->smtpVerifySsl = $v;
    }

    // =========================================================================

    /**
     * Send an email.
     *
     * @param string $fromAddressOverride  When non-empty, replaces the configured
     *                                     from_address for this message (webmail
     *                                     sends as the logged-in user).
     * @param string $fromNameOverride     The matching display name.
     * @param list<array{filename:string,content_type:string,data:string}> $attachments
     *        Optional attachments: the name shown to the recipient, the MIME
     *        type, and the raw bytes (encoded here).
     * @param string $toAddress  One address, or a comma-separated list; each may
     *                           carry a display name ("Ann <ann@example.org>").
     *                           $cc, $bcc and $replyTo take the same form.
     * @param string $inReplyTo  The Message-ID being answered ("<id@host>"), so
     *                           the reply joins its thread; '' for none.
     * @return Result<bool>
     */
    public function send(
        string $toAddress,
        string $toName,
        string $subject,
        string $bodyText,
        string $bodyHtml = '',
        string $fromAddressOverride = '',
        string $fromNameOverride    = '',
        string $priority            = 'normal',  // 'high', 'normal', 'low'
        bool   $readReceipt         = false,
        array  $attachments         = [],
        string $cc                  = '',
        string $bcc                 = '',
        string $replyTo             = '',
        string $inReplyTo           = '',
    )
    : Result {
        try {
            return $this->doSend(
                $toAddress,
                $toName,
                $subject,
                $bodyText,
                $bodyHtml,
                $fromAddressOverride,
                $fromNameOverride,
                $priority,
                $readReceipt,
                $attachments,
                $cc,
                $bcc,
                $replyTo,
                $inReplyTo,
            );
        } catch (\Throwable $e) {
            return $this->err($e->getMessage());
        }
    }

    // =========================================================================
    // Internal
    // =========================================================================

    /**
     * @param list<array{filename:string,content_type:string,data:string}> $attachments
     * @return Result<bool>
     */
    private function doSend(
        string $toAddress,
        string $toName,
        string $subject,
        string $bodyText,
        string $bodyHtml,
        string $fromAddressOverride = '',
        string $fromNameOverride    = '',
        string $priority            = 'normal',
        bool   $readReceipt         = false,
        array  $attachments         = [],
        string $cc                  = '',
        string $bcc                 = '',
        string $replyTo             = '',
        string $inReplyTo           = '',
    )
    : Result {
        $effectiveFromAddress = $fromAddressOverride !== '' ? $fromAddressOverride : $this->fromAddress;
        $effectiveFromName    = $fromAddressOverride !== '' ? $fromNameOverride    : $this->fromName;

        // ── SMTP header / command injection defence ─────────────────────
        // A CR/LF/NUL in any envelope address would let a caller inject extra
        // SMTP commands (RCPT TO smuggling) once written to the socket; the same
        // bytes in a display name or subject forge mail headers. Validate the
        // address SHAPE and header-safety of every operator-influenced field
        // BEFORE opening the socket — on any violation we return a Result and
        // never dial the server.
        // Address lists, display names and all ("Ann <ann@example.org>, bob@...").
        // The envelope gets the bare addresses; the headers keep the names.
        $toList      = $this->parseAddressList($toAddress);
        if (count($toList) === 1 && $toList[0]['name'] === '' && $toName !== '') {
            $toList[0]['name'] = $toName;
        }
        $ccList      = $this->parseAddressList($cc);
        $bccList     = $this->parseAddressList($bcc);
        $replyToList = $this->parseAddressList($replyTo);
        if ($toList === []) {
            return $this->invalidRecipient($toAddress);
        }
        if (!$this->validAddress($effectiveFromAddress)) {
            return $this->invalidRecipient($effectiveFromAddress);
        }
        foreach ([...$toList, ...$ccList, ...$bccList, ...$replyToList] as $entry) {
            if (!$this->validAddress($entry['address'])) {
                return $this->invalidRecipient($entry['address']);
            }
            if (!$this->headerSafe($entry['name'])) {
                return $this->invalidRecipient($entry['name']);
            }
        }
        // Only a well-formed Message-ID is passed on; anything else is dropped
        // rather than refusing the whole message.
        $inReplyTo = trim($inReplyTo);
        if (preg_match('/^<[^<>\s]+>$/', $inReplyTo) !== 1) {
            $inReplyTo = '';
        }
        foreach ([$effectiveFromName, $subject] as $headerText) {
            if (!$this->headerSafe($headerText)) {
                return $this->invalidRecipient($headerText);
            }
        }

        $sock = $this->connect();

        $this->read($sock);                         // 220 greeting

        // EHLO
        $domain = gethostname() ?: 'localhost';
        $caps = $this->ehlo($sock, $domain);

        // STARTTLS upgrade (encryption='tls')
        if ($this->encryption === 'tls') {
            if (!in_array('STARTTLS', $caps, true)) {
                return $this->err("Server does not support STARTTLS");
            }
            $this->cmd($sock, "STARTTLS");
            $this->read($sock, '220');
            // Pin the certificate to the configured host (SNI + peer_name)
            // and honour smtp_verify_ssl BEFORE upgrading the plaintext socket.
            $this->applyTlsContext($sock);
            // @-suppress: a TLS-handshake failure raises E_WARNING, which the
            // ErrorHandler would escalate to a forced HTTP 500. We already fail
            // closed on the boolean return, and send()'s try/catch converts the
            // follow-on Result::err path — a mail failure must not 500 the page.
            if (!@stream_socket_enable_crypto(
                $sock,
                true,
                STREAM_CRYPTO_METHOD_TLS_CLIENT
            )) {
                return $this->err("STARTTLS negotiation failed");
            }
            // Re-EHLO after TLS handshake
            $caps = $this->ehlo($sock, $domain);
        }

        // AUTH — prefer PLAIN, fall back to LOGIN when the server doesn't
        // advertise PLAIN. Older MS Exchange, some shared-hosting MTAs, and a
        // few legacy mail providers only support AUTH LOGIN. Both methods
        // send credentials in cleartext (base64 isn't encryption) so STARTTLS
        // or SMTPS is still required for any non-localhost connection.
        if ($this->username !== '') {
            $supportsAny = false;
            $supportsPlain = false;
            $supportsLogin = false;
            foreach ($caps as $cap) {
                if ($cap === 'AUTH PLAIN' || str_starts_with($cap, 'AUTH PLAIN ')) {
                    $supportsAny = $supportsPlain = true;
                }
                if ($cap === 'AUTH LOGIN' || str_starts_with($cap, 'AUTH LOGIN ')
                 || str_contains($cap, ' PLAIN') || str_contains($cap, ' LOGIN')) {
                    $supportsAny = true;
                    if (str_contains($cap, 'LOGIN')) { $supportsLogin = true; }
                    if (str_contains($cap, 'PLAIN')) { $supportsPlain = true; }
                }
                // Tolerate 'AUTH' alone (very old servers); assume both methods.
                if ($cap === 'AUTH') { $supportsAny = $supportsPlain = $supportsLogin = true; }
            }
            if (!$supportsAny) {
                return $this->err("Server does not support AUTH");
            }

            if ($supportsPlain) {
                $auth = base64_encode("\0" . $this->username . "\0" . $this->password);
                $this->cmd($sock, "AUTH PLAIN {$auth}");
                $this->read($sock, '235');
            } elseif ($supportsLogin) {
                // AUTH LOGIN: server prompts "Username:" then "Password:" both
                // base64-encoded, and we reply with base64 of each in turn.
                $this->cmd($sock, "AUTH LOGIN");
                $this->read($sock, '334');                            // base64('Username:')
                $this->cmd($sock, base64_encode($this->username));
                $this->read($sock, '334');                            // base64('Password:')
                $this->cmd($sock, base64_encode($this->password));
                $this->read($sock, '235');                            // auth ok
            } else {
                return $this->err("Server advertises AUTH but neither PLAIN nor LOGIN");
            }
        }

        // Envelope
        $this->cmd($sock, "MAIL FROM:<{$effectiveFromAddress}>");
        $this->read($sock, '250');

        $this->cmd($sock, "RCPT TO:<{$toList[0]['address']}>");
        $this->read($sock, '25');   // 250 or 251

        // Deliver to every other To, Cc and Bcc recipient too. Bcc addresses
        // are RCPT'd here but deliberately NOT emitted as a header below. A
        // rejected SECONDARY recipient must NOT abort delivery to the accepted
        // ones (the first To already succeeded above), so skip it and carry on.
        foreach ([...array_slice($toList, 1), ...$ccList, ...$bccList] as $rcpt) {
            $rcptAddr = $rcpt['address'];
            try {
                $this->cmd($sock, "RCPT TO:<{$rcptAddr}>");
                $this->read($sock, '25');
            } catch (\Throwable) {
                continue;
            }
        }

        $this->cmd($sock, "DATA");
        $this->read($sock, '354');

        // Build message
        $boundary = bin2hex(random_bytes(12));
        $hasAttachments = $attachments !== [];
        $headers = $this->buildHeaders(
            $this->formatAddressList($toList),
            '',
            $subject,
            $boundary,
            $bodyHtml !== '',
            $effectiveFromAddress,
            $effectiveFromName,
            $priority,
            $readReceipt,
            $hasAttachments,
            $this->formatAddressList($ccList),
            $this->formatAddressList($replyToList),
            $inReplyTo,
        );
        $body = $this->buildBody($bodyText, $bodyHtml, $boundary, $attachments);

        // Dot-stuff (RFC 5321 §4.5.2): a body line beginning with '.' gets an extra
        // leading '.', otherwise a body line of just "." would prematurely END the
        // DATA phase — letting a webmail-composed body smuggle SMTP commands.
        $stuffed = preg_replace('/(\r\n|^)\./', '$1..', $body);
        if (!is_string($stuffed)) { $stuffed = $body; }
        fwrite($sock, $headers . "\r\n" . $stuffed . "\r\n.\r\n");
        $this->read($sock, '250');

        $this->cmd($sock, "QUIT");
        fclose($sock);

        return Result::ok(true);
    }

    /** @return resource */
    private function connect()
    : mixed
    {
        $errno  = 0;
        $errstr = '';
        if ($this->socks5Host !== '') {
            $sock = $this->connectViaSocks5();
        } elseif ($this->encryption === 'ssl') {
            $ctx = stream_context_create(['ssl' => [
                'peer_name'         => $this->host,
                'verify_peer'       => $this->smtpVerifySsl,
                'verify_peer_name'  => $this->smtpVerifySsl,
                'allow_self_signed' => !$this->smtpVerifySsl,
            ]]);
            // @-suppress: an unreachable/misconfigured SMTP server raises
            // E_WARNING here, which the ErrorHandler escalates to a forced 500.
            // $errno/$errstr are captured and the false return throws below,
            // where send()'s try/catch turns it into Result::err instead.
            $sock = @stream_socket_client(
                "ssl://{$this->host}:{$this->port}",
                $errno,
                $errstr,
                $this->timeout,
                STREAM_CLIENT_CONNECT,
                $ctx
            );
        } else {
            // @-suppress: see the ssl:// branch above — a failed connect must
            // resolve to Result::err, not a forced 500.
            $sock = @stream_socket_client(
                "tcp://{$this->host}:{$this->port}",
                $errno,
                $errstr,
                $this->timeout
            );
        }

        if ($sock === false) {
            throw new \RuntimeException(
                "Cannot connect to {$this->host}:{$this->port} — $errstr ($errno)"
            );
        }

        stream_set_timeout($sock, $this->timeout);

        if ($this->encryption === 'ssl' && $this->socks5Host !== '') {
            // Wrap in TLS after the SOCKS5 tunnel is open (implicit TLS).
            // Pin peer_name + verification on the tunnelled stream first,
            // then capture the handshake result and fail closed. A failed or
            // unverified handshake must never fall through to a cleartext send;
            // the throw is converted to Result::err() by send()'s catch.
            $this->applyTlsContext($sock);
            // @-suppress: a TLS-handshake failure over the tunnel raises
            // E_WARNING (→ forced 500). We fail closed on the non-true return
            // and throw; send()'s try/catch converts that to Result::err.
            if (@stream_socket_enable_crypto(
                $sock,
                true,
                STREAM_CRYPTO_METHOD_TLS_CLIENT
            ) !== true) {
                throw new \RuntimeException(
                    "TLS handshake failed after SOCKS5 tunnel"
                );
            }
        }

        return $sock;
    }

    /**
     * Open a TCP connection via a SOCKS5 proxy.
     * Used when sending to .onion addresses or routing through Tor.
     * @return resource
     */
    private function connectViaSocks5()
    : mixed
    {
        // @-suppress: an unreachable SOCKS5 proxy raises E_WARNING (→ forced
        // 500). The false return throws below and send()'s try/catch converts
        // it to Result::err.
        $sock = @stream_socket_client(
            "tcp://{$this->socks5Host}:{$this->socks5Port}",
            $errno,
            $errstr,
            $this->timeout
        );
        if ($sock === false) {
            throw new \RuntimeException(
                "Cannot connect to SOCKS5 proxy: $errstr ($errno)"
            );
        }

        // SOCKS5 handshake: no auth
        fwrite(
            $sock,
            "\x05\x01\x00"
        );              // version=5, nmethods=1, method=noauth
        // Guard a short read: fread() may return fewer than 2 bytes, so accessing
        // $resp[1] without a length check raises an undefined-offset E_WARNING
        // (→ forced 500). Mirror ImapClient::connectViaSocks5's `strlen($resp) < 2`.
        $resp = fread($sock, 2);
        if ($resp === false || strlen($resp) < 2 || $resp[1] !== "\x00") {
            throw new \RuntimeException("SOCKS5 proxy rejected no-auth method");
        }

        // CONNECT request
        $host = $this->host;
        $port = $this->port;
        $hostLen = strlen($host);
        $req = "\x05\x01\x00"                   // VER CMD RSV
               . "\x03"                            // ATYP: domain name
               . chr($hostLen) . $host             // DST.ADDR
               . pack('n', $port);                 // DST.PORT
        fwrite($sock, $req);

        // Response: VER REP RSV ATYP BNDADDR BNDPORT
        $resp = fread($sock, 4);
        if ($resp === false || strlen($resp) < 4) {
            throw new \RuntimeException(
                "SOCKS5 proxy returned truncated response"
            );
        }
        if ($resp[1] !== "\x00") {
            $code = ord($resp[1]);
            throw new \RuntimeException(
                "SOCKS5 proxy refused connection (code {$code})"
            );
        }
        // Read the bound address (variable length) and port to drain the response
        $atyp = ord($resp[3]);
        if ($atyp === 1) {
            fread($sock, 4);
        }     // IPv4
        elseif ($atyp === 3) {
            fread($sock, max(1, ord((string)fread($sock, 1))));
        } // domain
        elseif ($atyp === 4) {
            fread($sock, 16);
        }    // IPv6
        fread($sock, 2);       // port

        return $sock;
    }

    /**
     * Send EHLO and return list of capability keywords.
     * @return list<string>
     */
    private function ehlo(mixed $sock, string $domain)
    : array {
        assert(is_resource($sock));
        $this->cmd($sock, "EHLO {$domain}");
        $caps = [];
        while (true) {
            $line = fgets($sock, 512);
            if ($line === false) {
                break;
            }
            $line = rtrim($line);
            // "250-KEYWORD" or "250 KEYWORD" — extract keyword
            if (preg_match('/^250[-\s]+(.+)$/', $line, $m)) {
                $parts = explode(' ', strtoupper(trim($m[1])));
                $caps[] = $parts[0];
            }
            // Last line has a space: "250 OK" or "250 KEYWORD"
            if (isset($line[3]) && $line[3] === ' ') {
                break;
            }
        }

        return $caps;
    }

    /** @param resource $sock */
    /** @param resource $sock */
    private function cmd(mixed $sock, string $line)
    : void {
        fwrite($sock, $line . "\r\n");
    }

    /** @param resource $sock */
    private function read(mixed $sock, string $expectedCode = '')
    : string {
        $response = '';
        while (true) {
            $line = fgets($sock, 512);
            if ($line === false) {
                break;
            }
            $response .= $line;
            // Continuation lines: "250-text" — final line has a space: "250 text"
            if (isset($line[3]) && $line[3] === ' ') {
                break;
            }
        }
        if ($expectedCode !== '' &&
            !str_starts_with($response, $expectedCode)) {
            throw new \RuntimeException(
                "Expected {$expectedCode}, got: " . rtrim($response)
            );
        }

        return $response;
    }

    /**
     * Split an address list into addresses and display names:
     *   ann@example.org, "Doe, John" <john@example.org>, Bob <bob@example.org>
     * Commas inside quotes or angle brackets do not split.
     *
     * @return list<array{address:string,name:string}>
     */
    private function parseAddressList(string $list): array
    {
        $parts = [];
        $current = '';
        $quoted = false;
        $angle = false;
        $len = strlen($list);
        for ($i = 0; $i < $len; $i++) {
            $c = $list[$i];
            if ($c === '\\' && $quoted && $i + 1 < $len) {
                $current .= $c . $list[++$i];
                continue;
            }
            if ($c === '"') { $quoted = !$quoted; }
            elseif ($c === '<' && !$quoted) { $angle = true; }
            elseif ($c === '>' && !$quoted) { $angle = false; }
            if (($c === ',' || $c === ';') && !$quoted && !$angle) {
                $parts[] = $current;
                $current = '';
                continue;
            }
            $current .= $c;
        }
        $parts[] = $current;

        $out = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '') { continue; }
            if (preg_match('/^(.*)<([^<>]*)>$/s', $part, $m)) {
                $name = trim($m[1]);
                if (strlen($name) >= 2 && $name[0] === '"' && str_ends_with($name, '"')) {
                    $name = (string) preg_replace('/\\\\(.)/s', '$1', substr($name, 1, -1));
                }
                $out[] = ['address' => trim($m[2]), 'name' => $name];
            } else {
                $out[] = ['address' => $part, 'name' => ''];
            }
        }
        return $out;
    }

    /** @param list<array{address:string,name:string}> $list */
    private function formatAddressList(array $list): string
    {
        return implode(', ', array_map(fn (array $a): string => $this->formatAddress($a['address'], $a['name']), $list));
    }

    /**
     * One address for a header. A display name that is not plain ASCII is
     * sent as an RFC 2047 encoded word, as header bytes must be ASCII.
     */
    private function formatAddress(string $address, string $name): string
    {
        if ($name === '') {
            return '<' . $address . '>';
        }
        $shown = preg_match('/[^\x20-\x7E]/', $name) === 1
            ? '=?UTF-8?B?' . base64_encode($name) . '?='
            : '"' . addcslashes($name, '"\\') . '"';
        return $shown . ' <' . $address . '>';
    }

    private function buildHeaders(
        string $toAddress,
        string $toName,
        string $subject,
        string $boundary,
        bool   $hasHtml,
        string $fromAddress  = '',
        string $fromName     = '',
        string $priority     = 'normal',
        bool   $readReceipt  = false,
        bool   $hasAttachments = false,
        string $cc           = '',
        string $replyTo      = '',
        string $inReplyTo    = '',
    )
    : string {
        if ($fromAddress === '') { $fromAddress = $this->fromAddress; }
        if ($fromName    === '') { $fromName    = $this->fromName; }
        // formatAddress() escapes the quoted display name: a " or \ would
        // otherwise break the quoted-string and could forge trailing header
        // tokens. headerSafe() already blocked CR/LF/NUL upstream.
        $from = $this->formatAddress($fromAddress, $fromName);
        // $toAddress arrives as a header-ready list (formatAddressList) unless
        // a name is given with a single bare address.
        $to = $toName !== '' ? $this->formatAddress($toAddress, $toName) : $toAddress;
        $msgId = '<' .
                 bin2hex(random_bytes(12)) .
                 '@' .
                 (gethostname() ?: 'localhost') .
                 '>';
        $date = date('r');
        $subject = '=?UTF-8?B?' . base64_encode($subject) . '?=';

        $h = "From: {$from}\r\n";
        $h .= "To: {$to}\r\n";
        if ($cc !== '') {
            $h .= "Cc: {$cc}\r\n"; // addresses already validated in doSend
        }
        if ($replyTo !== '') {
            $h .= "Reply-To: {$replyTo}\r\n";
        }
        if ($inReplyTo !== '') {
            $h .= "In-Reply-To: {$inReplyTo}\r\n";
            $h .= "References: {$inReplyTo}\r\n";
        }
        $h .= "Subject: {$subject}\r\n";
        $h .= "Date: {$date}\r\n";
        $h .= "Message-ID: {$msgId}\r\n";
        // Priority headers (X-Priority / Importance / X-MS-Exchange-Message-Class)
        if ($priority === 'high') {
            $h .= "X-Priority: 1\r\n";
            $h .= "Importance: High\r\n";
        } elseif ($priority === 'low') {
            $h .= "X-Priority: 5\r\n";
            $h .= "Importance: Low\r\n";
        }
        // Read receipt (Disposition-Notification-To)
        if ($readReceipt) {
            $h .= "Disposition-Notification-To: {$fromAddress}\r\n";
        }
        $h .= "MIME-Version: 1.0\r\n";

        // Outermost Content-Type:
        //   - With attachments → multipart/mixed (wraps an alternative block + each attachment)
        //   - HTML, no atts    → multipart/alternative (text + html)
        //   - No HTML, no atts → text/plain
        if ($hasAttachments) {
            $h .= "Content-Type: multipart/mixed; boundary=\"{$boundary}\"\r\n";
        } elseif ($hasHtml) {
            $h .= "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n";
        } else {
            $h .= "Content-Type: text/plain; charset=UTF-8\r\n";
            $h .= "Content-Transfer-Encoding: quoted-printable\r\n";
        }

        return $h;
    }

    /**
     * Build the MIME body.
     *
     * Layout:
     *   - No html, no attachments  → bare quoted-printable text
     *   - Html present, no atts    → multipart/alternative (text + html)
     *   - Attachments present      → multipart/mixed with the alt-block first,
     *                                then each attachment as a part with
     *                                base64 transfer-encoding.
     *
     * @param list<array{filename:string,content_type:string,data:string}> $attachments
     */
    private function buildBody(string $text, string $html, string $boundary, array $attachments = [])
    : string {
        // Fast path — no html, no attachments.
        if ($html === '' && $attachments === []) {
            return quoted_printable_encode($text);
        }

        // Body container — the text+html alternative block (with no attachments
        // we use this directly; with attachments it becomes a child of the
        // multipart/mixed wrapper).
        $altBoundary = $attachments === [] ? $boundary : 'alt_' . bin2hex(random_bytes(8));

        $altBody = '';
        if ($html !== '') {
            $altBody = "--{$altBoundary}\r\n" .
                       "Content-Type: text/plain; charset=UTF-8\r\n" .
                       "Content-Transfer-Encoding: quoted-printable\r\n\r\n" .
                       quoted_printable_encode($text) .
                       "\r\n" .
                       "--{$altBoundary}\r\n" .
                       "Content-Type: text/html; charset=UTF-8\r\n" .
                       "Content-Transfer-Encoding: quoted-printable\r\n\r\n" .
                       quoted_printable_encode($html) .
                       "\r\n" .
                       "--{$altBoundary}--";
        } else {
            // Attachments present but no html — single text part.
            $altBody = "--{$altBoundary}\r\n" .
                       "Content-Type: text/plain; charset=UTF-8\r\n" .
                       "Content-Transfer-Encoding: quoted-printable\r\n\r\n" .
                       quoted_printable_encode($text) .
                       "\r\n--{$altBoundary}--";
        }

        // No attachments — the alt block IS the body.
        if ($attachments === []) {
            return $altBody;
        }

        // Multipart/mixed: alt block as first part, attachments after.
        $out  = "--{$boundary}\r\n";
        $out .= "Content-Type: multipart/alternative; boundary=\"{$altBoundary}\"\r\n\r\n";
        $out .= $altBody . "\r\n";

        foreach ($attachments as $att) {
            $filename    = $att['filename'];
            $contentType = $att['content_type'];
            $data        = $att['data'];
            if ($data === '') { continue; }

            // Sanitise filename — strip path components + CRLF (header-injection
            // defence) AND escape the quote/backslash that would otherwise break out
            // of the quoted MIME parameter.
            $safeName = preg_replace('/[\r\n]/', '', basename($filename)) ?? 'attachment';
            $safeName = addcslashes($safeName, '"\\');
            // Never emit an attacker-shaped Content-Type: a CRLF or stray char there
            // could forge MIME headers/boundaries. Accept only a plain type/subtype;
            // fall back to a safe default otherwise.
            if (preg_match('#^[\w.+-]+/[\w.+-]+$#', $contentType) !== 1) {
                $contentType = 'application/octet-stream';
            }

            $out .= "--{$boundary}\r\n";
            $out .= "Content-Type: {$contentType}; name=\"{$safeName}\"\r\n";
            $out .= "Content-Transfer-Encoding: base64\r\n";
            $out .= "Content-Disposition: attachment; filename=\"{$safeName}\"\r\n\r\n";
            // RFC 2045 — base64 lines max 76 chars.
            $out .= chunk_split(base64_encode($data), 76, "\r\n");
        }

        $out .= "--{$boundary}--";
        return $out;
    }

    /**
     * True when $v carries no header/command-injection bytes (CR, LF, NUL).
     * A single one of these lets a caller break out of the intended header or
     * SMTP command and inject their own.
     */
    private function headerSafe(string $v): bool
    {
        return strpbrk($v, "\r\n\0") === false;
    }

    /**
     * True when $addr is a syntactically valid, header-safe email address.
     *
     * FILTER_VALIDATE_EMAIL is the primary shape check. It rejects single-label
     * domains, however — including the shipped default "noreply@localhost" and
     * the "localpart@localhost" addresses produced when mail_domain=localhost —
     * so a bare-label fallback keeps local/dev delivery working. The fallback is
     * still injection-safe: header-safety is enforced first and the pattern
     * forbids whitespace and every SMTP/header metacharacter.
     */
    private function validAddress(string $addr): bool
    {
        if ($addr === '' || !$this->headerSafe($addr)) {
            return false;
        }
        if (filter_var($addr, FILTER_VALIDATE_EMAIL) !== false) {
            return true;
        }
        return preg_match(
            '/^[^\s@<>,;:"\\\\]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/',
            $addr
        ) === 1;
    }

    /**
     * Apply TLS verification + SNI/peer_name to a stream before the handshake.
     * peer_name pins the certificate to the configured host (essential on the
     * STARTTLS and SOCKS5 paths, where the socket is opened as tcp:// and would
     * otherwise have no expected peer name). Verification follows
     * smtp_verify_ssl so onion-only deployments can opt out.
     *
     * @param resource $sock
     */
    private function applyTlsContext(mixed $sock): void
    {
        stream_context_set_option($sock, 'ssl', 'peer_name', $this->host);
        stream_context_set_option($sock, 'ssl', 'verify_peer', $this->smtpVerifySsl);
        stream_context_set_option($sock, 'ssl', 'verify_peer_name', $this->smtpVerifySsl);
        stream_context_set_option($sock, 'ssl', 'allow_self_signed', !$this->smtpVerifySsl);
    }

    /**
     * Expected failure: an address/name/subject failed the injection guard.
     * The offending value is carried on the diagnostic for logs only — the
     * translation renders a generic message so nothing is echoed to users.
     *
     * @return Result<never>
     */
    private function invalidRecipient(string $offending): Result
    {
        return Result::err(null, Diagnostics::of(
            new MailInvalidRecipientDiagnostic('astrx.mail/invalid_recipient', DiagnosticLevel::ERROR, $offending)
        ));
    }

    /** @return Result<never> */
    private function err(string $detail): Result
    {
        return Result::err(null, Diagnostics::of(
            new MailSendFailedDiagnostic('astrx.mail/send_failed', DiagnosticLevel::ERROR, $detail)
        ));
    }
}
