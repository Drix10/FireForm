from pydantic import BaseModel, Field, field_validator, ConfigDict
import re
import html
import logging

# Get logger for this module
logger = logging.getLogger(__name__)

# Optional bleach import for HTML sanitization
try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False

# Pre-compile regex patterns for performance
DANGEROUS_CONTENT_PATTERN = re.compile(
    r'(?i)(?:'
    r'<\s*(?:script|iframe|object|embed|form|input|meta|link|style|base|applet|body|html|head|title|svg|math|xml)\b|'
    r'javascript\s*:|'
    r'data\s*:|'
    r'vbscript\s*:|'
    r'file\s*:|'
    r'ftp\s*:|'
    r'on(?:click|error|load|mouseover|focus|blur|change|submit|keydown|keyup|keypress|resize|scroll|unload|beforeunload|hashchange|popstate|storage|message|offline|online|pagehide|pageshow|beforeprint|afterprint|dragstart|drag|dragenter|dragover|dragleave|drop|dragend|copy|cut|paste|selectstart|select|input|invalid|reset|search|abort|canplay|canplaythrough|durationchange|emptied|ended|loadeddata|loadedmetadata|loadstart|pause|play|playing|progress|ratechange|seeked|seeking|stalled|suspend|timeupdate|volumechange|waiting|animationstart|animationend|animationiteration|transitionend|wheel|contextmenu|show|toggle)\s*=|'
    r'&#\s*(?:\d{1,7}|x[0-9a-f]{1,6})\s*;|'
    r'expression\s*\(|'
    r'url\s*\(|'
    r'import\s*\(|'
    r'@import\b|'
    r'binding\s*:|'
    r'behavior\s*:|'
    r'mocha\s*:|'
    r'livescript\s*:|'
    r'eval\s*\(|'
    r'setTimeout\s*\(|'
    r'setInterval\s*\(|'
    r'Function\s*\(|'
    r'constructor\s*\(|'
    r'alert\s*\(|'
    r'confirm\s*\(|'
    r'prompt\s*\(|'
    r'document\.\w+\s*[\(\[=]|'
    r'window\.\w+\s*[\(\[=]|'
    r'location\.|'
    r'navigator\.|'
    r'history\.|'
    r'localStorage\.|'
    r'sessionStorage\.|'
    r'XMLHttpRequest\b|'
    r'fetch\s*\(|'
    r'WebSocket\b|'
    r'EventSource\b|'
    r'SharedWorker\b|'
    r'\bWorker\b|'
    r'\bServiceWorker\b|'
    r'postMessage\b|'
    r'innerHTML\b|'
    r'outerHTML\b|'
    r'insertAdjacentHTML\b|'
    r'document\.write\b|'
    r'document\.writeln\b|'
    r'createContextualFragment\b|'
    r'DOMParser\b|'
    r'Range\.createContextualFragment\b|'
    r'<\s*!\s*\[CDATA\[|'
    r'<\s*!\s*--.*?--|'
    r'<\s*\?.*?\?>'
    r')', re.DOTALL
)

# Control character pattern including Unicode control chars
CONTROL_CHARS_PATTERN = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\u2000-\u200F\u2028-\u202F\u205F-\u206F\uFEFF]')

# Pattern for detecting potential prompt injection
PROMPT_INJECTION_PATTERN = re.compile(
    r'(?i)(?:'
    r'(?:please\s+)?ignore\s+(?:all\s+)?(?:previous|above|all|the|your|system|earlier|prior)\s+(?:instructions?|prompts?|commands?|rules?|directions?)|'
    r'(?:please\s+)?forget\s+(?:all\s+)?(?:previous|above|all|the|your|system|earlier|prior)\s+(?:instructions?|prompts?|commands?|rules?|directions?)|'
    r'(?:please\s+)?disregard\s+(?:all\s+)?(?:previous|above|all|the|your|system|earlier|prior|everything)\s*(?:instructions?|prompts?|commands?|rules?|directions?|and)?|'
    r'(?:please\s+)?override\s+(?:all\s+)?(?:previous|above|all|the|your|system|earlier|prior)\s+(?:instructions?|prompts?|commands?|rules?|directions?)|'
    r'new\s+(?:instructions?|prompts?|commands?|rules?|directions?)|'
    r'(?:^|\s|["\'\[\(])(?:system|assistant|user|human|ai|bot)\s*:\s*|'
    r'(?:^|\s)(?:now\s+)?(?:you\s+(?:are|will|must|should)|act\s+as|pretend\s+to\s+be|roleplay\s+as)|'
    r'(?:^|\s)(?:from\s+now\s+on|instead\s+of|rather\s+than)(?:\s|$)|'
    r'actually\s+you\s+(?:are|will|must|should)|'
    r'in\s+reality\s+you\s+(?:are|will|must|should)|'
    r'the\s+truth\s+is|'
    r'actually\s+ignore|'
    r'but\s+ignore|'
    r'however\s+ignore|'
    r'nevertheless\s+ignore|'
    r'nonetheless\s+ignore|'
    r'still\s+ignore|'
    r'yet\s+ignore|'
    r'although\s+ignore|'
    r'though\s+ignore|'
    r'despite\s+ignore|'
    r'in\s+spite\s+of\s+ignore|'
    r'regardless\s+ignore|'
    r'irrespective\s+ignore|'
    r'notwithstanding\s+ignore|'
    r'(?:can\s+you|i\s+need\s+you\s+to)\s+(?:ignore|forget|disregard)'
    r')'
)

class FormFill(BaseModel):
    template_id: int = Field(..., gt=0, le=2147483647)
    input_text: str = Field(..., min_length=1, max_length=50000)

    @field_validator('template_id')
    @classmethod
    def validate_template_id(cls, v):
        if v is None:
            raise ValueError('Template ID cannot be null')
        if not isinstance(v, int):
            raise ValueError('Template ID must be an integer')
        return v

    @field_validator('input_text')
    @classmethod
    def validate_input_text(cls, v):
        import unicodedata
        import signal
        import threading
        import concurrent.futures
        
        if v is None:
            raise ValueError('Input text cannot be null')
        
        if not v.strip():
            raise ValueError('Input text cannot be empty')
        
        # Early length check to prevent processing attacks
        if len(v) > 50000:
            raise ValueError('Input text too long')
        
        # Store original for security comparison
        original_v = v
        original_len = len(v)
        
        # Check for dangerous content before normalization
        if DANGEROUS_CONTENT_PATTERN.search(v):
            raise ValueError('Potentially dangerous content detected')
        
        # Check for zero-width and invisible characters
        invisible_chars = ['\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF', '\u202E']
        if any(char in v for char in invisible_chars):
            raise ValueError('Invisible or zero-width characters detected')
        
        # Check for homograph attacks (non-ASCII lookalikes)
        suspicious_chars = {
            'і': 'i',  # Cyrillic і looks like Latin i
            'ο': 'o',  # Greek omicron looks like Latin o
            'О': 'O',  # Cyrillic О looks like Latin O
            'а': 'a',  # Cyrillic а looks like Latin a
            'е': 'e',  # Cyrillic е looks like Latin e
            'р': 'p',  # Cyrillic р looks like Latin p
            'с': 'c',  # Cyrillic с looks like Latin c
            'х': 'x',  # Cyrillic х looks like Latin x
        }
        
        for char in v:
            if char in suspicious_chars:
                # Check if it's mixed with Latin characters (potential homograph attack)
                # Use simpler and more reliable logic
                has_latin = any(c.isascii() and c.isalpha() for c in v)
                has_suspicious = any(c in suspicious_chars for c in v)
                if has_latin and has_suspicious:
                    raise ValueError('Potential homograph attack detected')
        
        # Check for path traversal patterns
        path_patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c', '..%2f', '..%5c']
        v_lower = v.lower()
        if any(pattern in v_lower for pattern in path_patterns):
            raise ValueError('Path traversal pattern detected')
        
        # Check for control characters and null bytes
        if any(ord(c) < 32 and c not in '\t\n\r' for c in v):
            raise ValueError('Control characters or null bytes detected')
        
        # Unicode normalization with strict expansion protection
        try:
            # Use NFC instead of NFKC to prevent compatibility attacks
            normalized = unicodedata.normalize('NFC', v)
            
            # Check for suspicious Unicode patterns before normalization
            # Detect combining character attacks (many combining chars per base char)
            combining_chars = sum(1 for c in v if unicodedata.combining(c))
            base_chars = len(v) - combining_chars
            if base_chars > 0 and combining_chars / base_chars > 0.5:  # More than 0.5 combining per base
                raise ValueError('Suspicious Unicode combining character pattern detected')
            
            # Check for Unicode expansion attacks
            if len(normalized) > original_len * 1.5:
                raise ValueError('Suspicious Unicode normalization expansion detected')
            
            # Also check for excessive compression (potential DoS)
            if len(normalized) < original_len * 0.3 and original_len > 1000:
                raise ValueError('Suspicious Unicode normalization compression detected')
            
            # Apply normalized result
            v = normalized
            
            # URL decode to catch encoded injection attempts
            import urllib.parse
            decoded = urllib.parse.unquote(v)
            
            # Check for URL decoding expansion
            if len(decoded) > len(v) * 2:
                raise ValueError('Suspicious URL decoding expansion detected')
            
            # Check for repetitive pattern attacks (but allow legitimate repetition)
            if len(v) > 1000:  # Check original input for URL patterns
                # Special check for URL encoding patterns in original input
                if '%' in v and v.count('%') > len(v) * 0.05:  # More than 5% percent signs
                    # Check for repetitive URL encoding patterns
                    url_patterns = ['%26', '%3B', '%3C', '%3E', '%22', '%27', '%2F', '%5C']
                    for pattern in url_patterns:
                        if pattern in v and v.count(pattern) > 100:
                            raise ValueError('Suspicious URL encoding pattern detected')
            
            if len(decoded) > 1000:  # Check decoded content for other patterns
                # Check for excessive repetition of short patterns in decoded content
                for pattern_len in [2, 3, 4]:  # Reduced range
                    if len(decoded) >= pattern_len * 500:  # At least 500 repetitions possible
                        pattern = decoded[:pattern_len]
                        repetitions = decoded.count(pattern)
                        # Only flag if it's more than 90% repetition AND the pattern looks suspicious
                        if repetitions > len(decoded) / (pattern_len * 1.1):  # More than 90% repetition
                            # Allow legitimate patterns - only block if pattern contains special chars
                            if not pattern.replace(' ', '').isalnum():  # Contains non-alphanumeric (except space)
                                raise ValueError(f'Suspicious repetitive pattern detected: {pattern_len}-char pattern repeated {repetitions} times')
            
            # Apply security checks on decoded content but preserve original
            if decoded != v:
                logger.debug("URL decoding applied during validation")
        # Check decoded content for dangerous patterns
        if DANGEROUS_CONTENT_PATTERN.search(decoded):
            raise ValueError('Potentially dangerous content detected after URL decoding')
            
            # Length check after all processing
            if len(v) > 45000:  # Reduced from original to account for processing
                raise ValueError('Input text too long after normalization')
                
        except ValueError:
            # Re-raise ValueError to preserve security error messages
            raise
        except Exception:
            raise ValueError('Invalid Unicode characters detected')
        
        # Controlled HTML entity decoding with timeout
        def timeout_handler(signum, frame):
            raise TimeoutError("HTML processing timeout")
        
        def process_html_unescape(text):
            return html.unescape(text)
        
        old_handler = None
        try:
            # Cross-platform timeout protection
            if hasattr(signal, 'SIGALRM'):
                # POSIX: Use signal-based timeout
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(1)
                try:
                    v = html.unescape(v)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
            else:
                # Windows: Use ThreadPoolExecutor with timeout
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                try:
                    future = executor.submit(process_html_unescape, v)
                    try:
                        v = future.result(timeout=1)
                    except concurrent.futures.TimeoutError:
                        future.cancel()  # Cancel the future
                        raise TimeoutError("HTML processing timeout")
                finally:
                    # Always shutdown the executor
                    executor.shutdown(wait=False)
                        
        except TimeoutError:
            raise ValueError('HTML processing timeout - potential attack')
        except Exception as e:
            # If unescape fails, raise validation error to prevent bypass
            logger.debug(f"HTML unescape failed: {e}")
            raise ValueError('HTML entity decoding failed')
            
        v = v.strip()
        
        # Remove control characters
        v = CONTROL_CHARS_PATTERN.sub('', v)
        
        # Use bleach with strict limits if available
        if BLEACH_AVAILABLE:
            def process_bleach_clean(text):
                return bleach.clean(text, tags=[], attributes={}, strip=True)
            
            old_handler = None
            try:
                # Cross-platform timeout protection
                if hasattr(signal, 'SIGALRM'):
                    # POSIX: Use signal-based timeout
                    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(2)  # 2-second timeout for bleach
                    try:
                        v = bleach.clean(v, tags=[], attributes={}, strip=True)
                    finally:
                        signal.alarm(0)
                        signal.signal(signal.SIGALRM, old_handler)
                else:
                    # Windows: Use ThreadPoolExecutor with timeout
                    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                    try:
                        future = executor.submit(process_bleach_clean, v)
                        try:
                            v = future.result(timeout=2)
                        except concurrent.futures.TimeoutError:
                            future.cancel()  # Cancel the future
                            raise TimeoutError("Content sanitization timeout")
                    finally:
                        # Always shutdown the executor
                        executor.shutdown(wait=False)
                            
            except TimeoutError:
                raise ValueError('Content sanitization timeout - potential attack')
            except (KeyboardInterrupt, SystemExit, MemoryError):
                # Re-raise fatal exceptions
                raise
            except Exception as e:
                # Log other bleach failures and continue without it
                logger.error(f"bleach.clean failed: {str(e)}", exc_info=True)
                pass
        
        # Final dangerous content check after processing
        if DANGEROUS_CONTENT_PATTERN.search(v):
            raise ValueError('Potentially dangerous content detected after processing')
        
        # Check for prompt injection attempts
        if PROMPT_INJECTION_PATTERN.search(v):
            raise ValueError('Potential prompt injection detected')
        
        # Final validation
        if len(v) == 0:
            raise ValueError('Input text cannot be empty after processing')
        
        # Additional length check for processed content
        if len(v) > 45000:  # Leave buffer for processing
            raise ValueError('Input text too long after processing')
        
        return v


class FormFillResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    template_id: int
    input_text: str
    output_pdf_path: str