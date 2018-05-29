#!/usr/bin/env python

"""
特定功能的 flawfinder
直接输出 hitlist 至 csv 文件
"""

# 全局变量
import csv
import hashlib
import re

import os
import string

import sys

import time

c_files = [] # 已提取的待检测的所有 c 文件
csv_content = [] # csv 内容列表
find_cwe_pattern = re.compile(r'\(CWE-[^)]*\)')
hitlist = []
count = 0

def print_multi_line(text):
    # Print text as multiple indented lines.
    width = 78
    prefix = " "
    starting_position = len(prefix) + 1
    #
    print(prefix, end='')
    position = starting_position
    #
    for w in text.split():
        if len(w) + position >= width:
            print()
            print(prefix, end='')
            position = starting_position
        print(' ', end='')
        print(w, end='')
        position = position + len(w) + 1


class Hit(object):
    """
    Each instance of Hit is a warning of some kind in a source code file.
    See the rulesets, which define the conditions for triggering a hit.
    Hit is initialized with a tuple containing the following:
      hook: function to call when function name found.
      level: (default) warning level, 0-5. 0=no problem, 5=very risky.
      warning: warning (text saying what's the problem)
      suggestion: suggestion (text suggesting what to do instead)
      category: One of "buffer" (buffer overflow), "race" (race condition),
                "tmpfile" (temporary file creation), "format" (format string).
                Use "" if you don't have a better category.
      url: URL fragment reference.
      other:  A dictionary with other settings.

    Other settings usually set:

      name: function name
      parameter: the function parameters (0th parameter null)
      input: set to 1 if the function inputs from external sources.
      start: start position (index) of the function name (in text)
      end:  end position of the function name (in text)
      filename: name of file
      line: line number in file
      column: column in line in file
      context_text: text surrounding hit
    """

    # Set default values:
    source_position = 2  # By default, the second parameter is the source.
    format_position = 1  # By default, the first parameter is the format.
    input = 0  # By default, this doesn't read input.
    note = ""  # No additional notes.
    filename = ""  # Empty string is filename.
    extract_lookahead = 0  # Normally don't extract lookahead.
    args = None

    def __init__(self, data):
        hook, level, warning, suggestion, category, url, other = data
        self.hook, self.level = hook, level
        self.warning, self.suggestion = warning, suggestion
        self.category, self.url = category, url
        # These will be set later, but I set them here so that
        # analysis tools like PyChecker will know about them.
        self.column = 0
        self.line = 0
        self.name = ""
        self.context_text = ""
        for key in other:
            setattr(self, key, other[key])

    def __getitem__(self, X):  # Define this so this works: "%(line)" % hit
        return getattr(self, X)

    # return CWEs
    def cwes(self):
        result = find_cwe_pattern.search(self.warning)
        return result.group()[1:-1] if result else ''

    def fingerprint(self):
        """Return fingerprint of stripped context."""
        m = hashlib.sha256()
        m.update(self.context_text.strip().encode('utf-8'))
        return m.hexdigest()

    # Show as CSV format
    def show_csv(self):
        if self.level > 0:
            csv_content.append([
                self.filename, self.line, self.column, self.level, self.category,
                self.name, self.warning, self.suggestion, self.note,
                self.cwes(), self.context_text, self.fingerprint()
            ])



    def show(self):
        self.show_csv()
        return
        sys.stdout.write(self.filename)
        print(":%(line)s:" % self, end='')
        print("  [%(level)s]" % self, end=' ')
        print("(%(category)s)" % self, end=' ')
        print(("%(name)s:" % self), end='')
        main_text = "%(warning)s. " % self
        main_text = main_text + self.note
        print()
        print_multi_line(main_text)
        print()
        return


def c_valid_match(text, position):
    # Determine if this is a valid match, or a false positive.
    # If false positive controls aren't on, always declare it's a match:
    i = position
    while i < len(text):
        c = text[i]
        if c == '(':
            return 1
        elif c in string.whitespace:
            i = i + 1
        else:
            if c in "=+-":
                # This is very unlikely to be a function use. If c is '=',
                # the name is followed by an assignment or is-equal operation.
                # Since the names of library functions are really unlikely to be
                # followed by an assignment statement or 'is-equal' test,
                # while this IS common for variable names, let's declare it invalid.
                # It's possible that this is a variable function pointer, pointing
                # to the real library function, but that's really improbable.
                # If c is "+" or "-", we have a + or - operation.
                # In theory "-" could be used for a function pointer difference
                # computation, but this is extremely improbable.
                # More likely: this is a variable in a computation, so drop it.
                return 0
            return 1
    return 0  # Never found anything other than "(" and whitespace.



# These patterns match gettext() and _() for internationalization.
# This is compiled here, to avoid constant recomputation.
# FIXME: assumes simple function call if it ends with ")",
# so will get confused by patterns like  gettext("hi") + function("bye")
# In practice, this doesn't seem to be a problem; gettext() is usually
# wrapped around the entire parameter.
# The ?s makes it posible to match multi-line strings.
gettext_pattern = re.compile(r'(?s)^\s*' + 'gettext' + r'\s*\((.*)\)\s*$')
undersc_pattern = re.compile(r'(?s)^\s*' + '_(T(EXT)?)?' + r'\s*\((.*)\)\s*$')


def strip_i18n(text):
    """Strip any internationalization function calls surrounding 'text'.

    In particular, strip away calls to gettext() and _().
    """
    match = gettext_pattern.search(text)
    if match:
        return match.group(1).strip()
    match = undersc_pattern.search(text)
    if match:
        return match.group(3).strip()
    return text


p_trailingbackslashes = re.compile(r'(\s|\\(\n|\r))*$')

p_c_singleton_string = re.compile(r'^\s*L?"([^\\]|\\[^0-6]|\\[0-6]+)?"\s*$')


def c_singleton_string(text):
    "Returns true if text is a C string with 0 or 1 character."
    return 1 if p_c_singleton_string.search(text) else 0

# This string defines a C constant.
p_c_constant_string = re.compile(r'^\s*L?"([^\\]|\\[^0-6]|\\[0-6]+)*"$')


def c_constant_string(text):
    "Returns true if text is a constant C string."
    return 1 if p_c_constant_string.search(text) else 0

# Precompile patterns for speed.


def c_buffer(hit):
    source_position = hit.source_position
    if source_position <= len(hit.parameters) - 1:
        source = hit.parameters[source_position]
        if c_singleton_string(source):
            hit.level = 1
            hit.note = "Risk is low because the source is a constant character."
        elif c_constant_string(strip_i18n(source)):
            hit.level = max(hit.level - 2, 1)
            hit.note = "Risk is low because the source is a constant string."
    add_warning(hit)


p_dangerous_strncat = re.compile(r'^\s*sizeof\s*(\(\s*)?[A-Za-z_$0-9]+' +
                                 r'\s*(\)\s*)?(-\s*1\s*)?$')
# This is a heuristic: constants in C are usually given in all
# upper case letters.  Yes, this need not be true, but it's true often
# enough that it's worth using as a heuristic.
# We check because strncat better not be passed a constant as the length!
p_looks_like_constant = re.compile(r'^\s*[A-Z][A-Z_$0-9]+\s*(-\s*1\s*)?$')


def c_strncat(hit):
    if len(hit.parameters) > 3:
        # A common mistake is to think that when calling strncat(dest,src,len),
        # that "len" means the ENTIRE length of the destination.
        # This isn't true,
        # it must be the length of the characters TO BE ADDED at most.
        # Which is one reason that strlcat is better than strncat.
        # We'll detect a common case of this error; if the length parameter
        # is of the form "sizeof(dest)", we have this error.
        # Actually, sizeof(dest) is okay if the dest's first character
        # is always \0,
        # but in that case the programmer should use strncpy, NOT strncat.
        # The following heuristic will certainly miss some dangerous cases, but
        # it at least catches the most obvious situation.
        # This particular heuristic is overzealous; it detects ANY sizeof,
        # instead of only the sizeof(dest) (where dest is given in
        # hit.parameters[1]).
        # However, there aren't many other likely candidates for sizeof; some
        # people use it to capture just the length of the source, but this is
        # just as dangerous, since then it absolutely does NOT take care of
        # the destination maximum length in general.
        # It also detects if a constant is given as a length, if the
        # constant follows common C naming rules.
        length_text = hit.parameters[3]
        if p_dangerous_strncat.search(
                length_text) or p_looks_like_constant.search(length_text):
            hit.level = 5
            hit.note = (
                "Risk is high; the length parameter appears to be a constant, "
                + "instead of computing the number of characters left.")
            add_warning(hit)
            return
    c_buffer(hit)


def c_printf(hit):
    format_position = hit.format_position
    if format_position <= len(hit.parameters) - 1:
        # Assume that translators are trusted to not insert "evil" formats:
        source = strip_i18n(hit.parameters[format_position])
        if c_constant_string(source):
            # Parameter is constant, so there's no risk of
            # format string problems.
            # At one time we warned that very old systems sometimes incorrectly
            # allow buffer overflows on snprintf/vsnprintf, but those systems
            # are now very old, and snprintf is an important potential tool for
            # countering buffer overflows.
            # We'll pass it on, just in case it's needed, but at level 0 risk.
            hit.level = 0
            hit.note = "Constant format string, so not considered risky."
    add_warning(hit)


p_dangerous_sprintf_format = re.compile(r'%-?([0-9]+|\*)?s')


# sprintf has both buffer and format vulnerabilities.
def c_sprintf(hit):
    source_position = hit.source_position
    if hit.parameters is None:
        # Serious parameter problem, e.g., none, or a string constant that
        # never finishes.
        hit.warning = "format string parameter problem"
        hit.suggestion = "Check if required parameters present and quotes close."
        hit.level = 4
        hit.category = "format"
        hit.url = ""
    elif source_position <= len(hit.parameters) - 1:
        source = hit.parameters[source_position]
        if c_singleton_string(source):
            hit.level = 1
            hit.note = "Risk is low because the source is a constant character."
        else:
            source = strip_i18n(source)
            if c_constant_string(source):
                if not p_dangerous_sprintf_format.search(source):
                    hit.level = max(hit.level - 2, 1)
                    hit.note = "Risk is low because the source has a constant maximum length."
                # otherwise, warn of potential buffer overflow (the default)
            else:
                # Ho ho - a nonconstant format string - we have a different
                # problem.
                hit.warning = "Potential format string problem (CWE-134)"
                hit.suggestion = "Make format string constant"
                hit.level = 4
                hit.category = "format"
                hit.url = ""
    add_warning(hit)


p_dangerous_scanf_format = re.compile(r'%s')
p_low_risk_scanf_format = re.compile(r'%[0-9]+s')


def c_scanf(hit):
    format_position = hit.format_position
    if format_position <= len(hit.parameters) - 1:
        # Assume that translators are trusted to not insert "evil" formats;
        # it's not clear that translators will be messing with INPUT formats,
        # but it's possible so we'll account for it.
        source = strip_i18n(hit.parameters[format_position])
        if c_constant_string(source):
            if p_dangerous_scanf_format.search(source):
                pass  # Accept default.
            elif p_low_risk_scanf_format.search(source):
                # This is often okay, but sometimes extremely serious.
                hit.level = 1
                hit.warning = ("It's unclear if the %s limit in the " +
                               "format string is small enough (CWE-120)")
                hit.suggestion = ("Check that the limit is sufficiently " +
                                  "small, or use a different input function")
            else:
                # No risky scanf request.
                # We'll pass it on, just in case it's needed, but at level 0
                # risk.
                hit.level = 0
                hit.note = "No risky scanf format detected."
        else:
            # Format isn't a constant.
            hit.note = ("If the scanf format is influenceable " +
                        "by an attacker, it's exploitable.")
    add_warning(hit)


p_dangerous_multi_byte = re.compile(r'^\s*sizeof\s*(\(\s*)?[A-Za-z_$0-9]+' +
                                    r'\s*(\)\s*)?(-\s*1\s*)?$')
p_safe_multi_byte = re.compile(
    r'^\s*sizeof\s*(\(\s*)?[A-Za-z_$0-9]+\s*(\)\s*)?' +
    r'/\s*sizeof\s*\(\s*?[A-Za-z_$0-9]+\s*' + r'\[\s*0\s*\]\)\s*(-\s*1\s*)?$')


def c_multi_byte_to_wide_char(hit):
    # Unfortunately, this doesn't detect bad calls when it's a #define or
    # constant set by a sizeof(), but trying to do so would create
    # FAR too many false positives.
    if len(hit.parameters) - 1 >= 6:
        num_chars_to_copy = hit.parameters[6]
        if p_dangerous_multi_byte.search(num_chars_to_copy):
            hit.level = 5
            hit.note = (
                "Risk is high, it appears that the size is given as bytes, but the "
                + "function requires size as characters.")
        elif p_safe_multi_byte.search(num_chars_to_copy):
            # This isn't really risk-free, since it might not be the destination,
            # or the destination might be a character array (if it's a char pointer,
            # the pattern is actually quite dangerous, but programmers
            # are unlikely to make that error).
            hit.level = 1
            hit.note = "Risk is very low, the length appears to be in characters not bytes."
    add_warning(hit)


p_null_text = re.compile(r'^ *(NULL|0|0x0) *$')


def c_hit_if_null(hit):
    null_position = hit.check_for_null
    if null_position <= len(hit.parameters) - 1:
        null_text = hit.parameters[null_position]
        if p_null_text.search(null_text):
            add_warning(hit)
        else:
            return
    add_warning(hit)  # If insufficient # of parameters.


p_static_array = re.compile(r'^[A-Za-z_]+\s+[A-Za-z0-9_$,\s\*()]+\[[^]]')


def c_static_array(hit):
    # This is cheating, but it does the job for most real code.
    # In some cases it will match something that it shouldn't.
    # We don't match ALL arrays, just those of certain types (e.g., char).
    # In theory, any array can overflow, but in practice it seems that
    # certain types are far more prone to problems, so we just report those.
    if p_static_array.search(hit.lookahead):
        add_warning(hit)  # Found a static array, warn about it.


def cpp_unsafe_stl(hit):
    # Use one of the overloaded classes from the STL in C++14 and higher
    # instead of the <C++14 versions of theses functions that did not
    # if the second iterator could overflow
    if len(hit.parameters) <= 4:
        add_warning(hit)

def normal(hit):
    add_warning(hit)


c_ruleset = {
    "strcpy":
    (c_buffer, 4,
     "Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
     "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused)",
     "buffer", "", {}),
    "strcpyA|strcpyW|StrCpy|StrCpyA|lstrcpyA|lstrcpyW|_tccpy|_mbccpy|_ftcscpy|_mbsncpy|StrCpyN|StrCpyNA|StrCpyNW|StrNCpy|strcpynA|StrNCpyA|StrNCpyW|lstrcpynA|lstrcpynW":
    # We need more info on these functions; I got their names from the
    # Microsoft "banned" list.  For now, just use "normal" to process them
    # instead of "c_buffer".
    (normal, 4,
     "Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
     "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused)",
     "buffer", "", {}),
    "lstrcpy|wcscpy|_tcscpy|_mbscpy":
    (c_buffer, 4,
     "Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
     "Consider using a function version that stops copying at the end of the buffer",
     "buffer", "", {}),
    "memcpy|CopyMemory|bcopy":
    (normal, 2,  # I've found this to have a lower risk in practice.
     "Does not check for buffer overflows when copying to destination (CWE-120)",
     "Make sure destination can always hold the source data",
     "buffer", "", {}),
    "strcat":
    (c_buffer, 4,
     "Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
     "Consider using strcat_s, strncat, strlcat, or snprintf (warning: strncat is easily misused)",
     "buffer", "", {}),
    "lstrcat|wcscat|_tcscat|_mbscat":
    (c_buffer, 4,
     "Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
     "",
     "buffer", "", {}),
    # TODO: Do more analysis.  Added because they're in MS banned list.
    "StrCat|StrCatA|StrcatW|lstrcatA|lstrcatW|strCatBuff|StrCatBuffA|StrCatBuffW|StrCatChainW|_tccat|_mbccat|_ftcsat|StrCatN|StrCatNA|StrCatNW|StrNCat|StrNCatA|StrNCatW|lstrncat|lstrcatnA|lstrcatnW":
    (normal, 4,
     "Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
     "",
     "buffer", "", {}),
    "strncpy":
    (c_buffer,
     1,  # Low risk level, because this is often used correctly when FIXING security
     # problems, and raising it to a higher risk level would cause many false
     # positives.
     "Easily used incorrectly; doesn't always \\0-terminate or " +
     "check for invalid pointers [MS-banned] (CWE-120)",
     "",
     "buffer", "", {}),
    "lstrcpyn|wcsncpy|_tcsncpy|_mbsnbcpy":
    (c_buffer,
     1,  # Low risk level, because this is often used correctly when FIXING security
     # problems, and raising it to a higher risk levle would cause many false
     # positives.
     "Easily used incorrectly; doesn't always \\0-terminate or " +
     "check for invalid pointers [MS-banned] (CWE-120)",
     "",
     "buffer", "", {}),
    "strncat":
    (c_strncat,
     1,  # Low risk level, because this is often used correctly when
     # FIXING security problems, and raising it to a
     # higher risk level would cause many false positives.
     "Easily used incorrectly (e.g., incorrectly computing the correct maximum size to add) [MS-banned] (CWE-120)",
     "Consider strcat_s, strlcat, snprintf, or automatically resizing strings",
     "buffer", "", {}),
    "lstrcatn|wcsncat|_tcsncat|_mbsnbcat":
    (c_strncat,
     1,  # Low risk level, because this is often used correctly when FIXING security
     # problems, and raising it to a higher risk level would cause many false
     # positives.
     "Easily used incorrectly (e.g., incorrectly computing the correct maximum size to add) [MS-banned] (CWE-120)",
     "Consider strcat_s, strlcat, or automatically resizing strings",
     "buffer", "", {}),
    "strccpy|strcadd":
    (normal, 1,
     "Subject to buffer overflow if buffer is not as big as claimed (CWE-120)",
     "Ensure that destination buffer is sufficiently large",
     "buffer", "", {}),
    "char|TCHAR|wchar_t":  # This isn't really a function call, but it works.
    (c_static_array, 2,
     "Statically-sized arrays can be improperly restricted, " +
     "leading to potential overflows or other issues (CWE-119/CWE-120)",
     "Perform bounds checking, use functions that limit length, " +
     "or ensure that the size is larger than the maximum possible length",
     "buffer", "", {'extract_lookahead': 1}),

    "gets|_getts":
    (normal, 5, "Does not check for buffer overflows (CWE-120/CWE-20)",
     "Use fgets() instead", "buffer", "", {'input': 1}),

    # The "sprintf" hook will raise "format" issues instead if appropriate:
    "sprintf|vsprintf|swprintf|vswprintf|_stprintf|_vstprintf":
    (c_sprintf, 4,
     "Does not check for buffer overflows (CWE-120)",
     "Use sprintf_s, snprintf, or vsnprintf",
     "buffer", "", {}),

    "printf|vprintf|vwprintf|vfwprintf|_vtprintf|wprintf":
    (c_printf, 4,
     "If format strings can be influenced by an attacker, they can be exploited (CWE-134)",
     "Use a constant for the format specification",
     "format", "", {}),

    "fprintf|vfprintf|_ftprintf|_vftprintf|fwprintf|fvwprintf":
    (c_printf, 4,
     "If format strings can be influenced by an attacker, they can be exploited (CWE-134)",
     "Use a constant for the format specification",
     "format", "", {'format_position': 2}),

    # The "syslog" hook will raise "format" issues.
    "syslog":
    (c_printf, 4,
     "If syslog's format strings can be influenced by an attacker, " +
     "they can be exploited (CWE-134)",
     "Use a constant format string for syslog",
     "format", "", {'format_position': 2}),

    "snprintf|vsnprintf|_snprintf|_sntprintf|_vsntprintf":
    (c_printf, 4,
     "If format strings can be influenced by an attacker, they can be " +
     "exploited, and note that sprintf variations do not always \\0-terminate (CWE-134)",
     "Use a constant for the format specification",
     "format", "", {'format_position': 3}),

    "scanf|vscanf|wscanf|_tscanf|vwscanf":
    (c_scanf, 4,
     "The scanf() family's %s operation, without a limit specification, " +
     "permits buffer overflows (CWE-120/CWE-20)",
     "Specify a limit to %s, or use a different input function",
     "buffer", "", {'input': 1}),

    "fscanf|sscanf|vsscanf|vfscanf|_ftscanf|fwscanf|vfwscanf|vswscanf":
    (c_scanf, 4,
     "The scanf() family's %s operation, without a limit specification, "
     "permits buffer overflows (CWE-120/CWE-20)",
     "Specify a limit to %s, or use a different input function",
     "buffer", "", {'input': 1, 'format_position': 2}),

    "strlen|wcslen|_tcslen|_mbslen":
    (normal,
     # Often this isn't really a risk, and even when it is, at worst it
     # often causes a program crash (and nothing worse).
     1,
     "Does not handle strings that are not \\0-terminated; " +
     "if given one it may perform an over-read (it could cause a crash " +
     "if unprotected) (CWE-126)",
     "",
     "buffer", "", {}),

    "MultiByteToWideChar":  # Windows
    (c_multi_byte_to_wide_char,
     2,  # Only the default - this will be changed in many cases.
     "Requires maximum length in CHARACTERS, not bytes (CWE-120)",
     "",
     "buffer", "", {}),

    "streadd|strecpy":
    (normal, 4,
     "This function does not protect against buffer overflows (CWE-120)",
     "Ensure the destination has 4 times the size of the source, to leave room for expansion",
     "buffer", "dangers-c", {}),

    "strtrns":
    (normal, 3,
     "This function does not protect against buffer overflows (CWE-120)",
     "Ensure that destination is at least as long as the source",
     "buffer", "dangers-c", {}),

    "realpath":
    (normal, 3,
     "This function does not protect against buffer overflows, " +
     "and some implementations can overflow internally (CWE-120/CWE-785)",
     "Ensure that the destination buffer is at least of size MAXPATHLEN, and" +
     "to protect against implementation problems, the input argument " +
     "should also be checked to ensure it is no larger than MAXPATHLEN",
     "buffer", "dangers-c", {}),

    "getopt|getopt_long":
    (normal, 3,
     "Some older implementations do not protect against internal buffer overflows (CWE-120/CWE-20)",
     "Check implementation on installation, or limit the size of all string inputs",
     "buffer", "dangers-c", {'input': 1}),

    "getwd":
    (normal, 3,
     "This does not protect against buffer overflows "
     "by itself, so use with caution (CWE-120/CWE-20)",
     "Use getcwd instead",
     "buffer", "dangers-c", {'input': 1}),

    # fread not included here; in practice I think it's rare to mistake it.
    "getchar|fgetc|getc|read|_gettc":
    (normal, 1,
     "Check buffer boundaries if used in a loop including recursive loops (CWE-120/CWE-20)",
     "",
     "buffer", "dangers-c", {'input': 1}),

    "access":        # ???: TODO: analyze TOCTOU more carefully.
    (normal, 4,
     "This usually indicates a security flaw.  If an " +
     "attacker can change anything along the path between the " +
     "call to access() and the file's actual use (e.g., by moving " +
     "files), the attacker can exploit the race condition (CWE-362/CWE-367!)",
     "Set up the correct permissions (e.g., using setuid()) and " +
     "try to open the file directly",
     "race",
     "avoid-race#atomic-filesystem", {}),
    "chown":
    (normal, 5,
     "This accepts filename arguments; if an attacker " +
     "can move those files, a race condition results. (CWE-362)",
     "Use fchown( ) instead",
     "race", "", {}),
    "chgrp":
    (normal, 5,
     "This accepts filename arguments; if an attacker " +
     "can move those files, a race condition results. (CWE-362)",
     "Use fchgrp( ) instead",
     "race", "", {}),
    "chmod":
    (normal, 5,
     "This accepts filename arguments; if an attacker " +
     "can move those files, a race condition results. (CWE-362)",
     "Use fchmod( ) instead",
     "race", "", {}),
    "vfork":
    (normal, 2,
     "On some old systems, vfork() permits race conditions, and it's " +
     "very difficult to use correctly (CWE-362)",
     "Use fork() instead",
     "race", "", {}),
    "readlink":
    (normal, 5,
     "This accepts filename arguments; if an attacker " +
     "can move those files or change the link content, " +
     "a race condition results.  " +
     "Also, it does not terminate with ASCII NUL. (CWE-362/CWE-20)",
     # This is often just a bad idea, and it's hard to suggest a
     # simple alternative:
     "Reconsider approach",
     "race", "", {'input': 1}),

    "tmpfile":
    (normal, 2,
     "Function tmpfile() has a security flaw on some systems (e.g., older System V systems) (CWE-377)",
     "",
     "tmpfile", "", {}),
    "tmpnam|tempnam":
    (normal, 3,
     "Temporary file race condition (CWE-377)",
     "",
     "tmpfile", "avoid-race", {}),

    # TODO: Detect GNOME approach to mktemp and ignore it.
    "mktemp":
    (normal, 4,
     "Temporary file race condition (CWE-377)",
     "",
     "tmpfile", "avoid-race", {}),

    "mkstemp":
    (normal, 2,
     "Potential for temporary file vulnerability in some circumstances.  Some older Unix-like systems create temp files with permission to write by all by default, so be sure to set the umask to override this. Also, some older Unix systems might fail to use O_EXCL when opening the file, so make sure that O_EXCL is used by the library (CWE-377)",
     "",
     "tmpfile", "avoid-race", {}),

    "fopen|open":
    (normal, 2,
     "Check when opening files - can an attacker redirect it (via symlinks), force the opening of special file type (e.g., device files), move things around to create a race condition, control its ancestors, or change its contents? (CWE-362)",
     "",
     "misc", "", {}),

    "umask":
    (normal, 1,
     "Ensure that umask is given most restrictive possible setting (e.g., 066 or 077) (CWE-732)",
     "",
     "access", "", {}),

    # Windows.  TODO: Detect correct usage approaches and ignore it.
    "GetTempFileName":
    (normal, 3,
     "Temporary file race condition in certain cases " +
     "(e.g., if run as SYSTEM in many versions of Windows) (CWE-377)",
     "",
     "tmpfile", "avoid-race", {}),

    # TODO: Need to detect varying levels of danger.
    "execl|execlp|execle|execv|execvp|system|popen|WinExec|ShellExecute":
    (normal, 4,
     "This causes a new program to execute and is difficult to use safely (CWE-78)",
     "try using a library call that implements the same functionality " +
     "if available",
     "shell", "", {}),

    # TODO: Be more specific.  The biggest problem involves "first" param NULL,
    # second param with embedded space. Windows.
    "CreateProcessAsUser|CreateProcessWithLogon":
    (normal, 3,
     "This causes a new process to execute and is difficult to use safely (CWE-78)",
     "Especially watch out for embedded spaces",
     "shell", "", {}),

    # TODO: Be more specific.  The biggest problem involves "first" param NULL,
    # second param with embedded space. Windows.
    "CreateProcess":
    (c_hit_if_null, 3,
     "This causes a new process to execute and is difficult to use safely (CWE-78)",
     "Specify the application path in the first argument, NOT as part of the second, " +
     "or embedded spaces could allow an attacker to force a different program to run",
     "shell", "", {'check_for_null': 1}),

    "atoi|atol|_wtoi|_wtoi64":
    (normal, 2,
     "Unless checked, the resulting number can exceed the expected range " +
     "(CWE-190)",
     "If source untrusted, check both minimum and maximum, even if the" +
     " input had no minus sign (large numbers can roll over into negative" +
     " number; consider saving to an unsigned value if that is intended)",
     "integer", "dangers-c", {}),

    # Random values.  Don't trigger on "initstate", it's too common a term.
    "drand48|erand48|jrand48|lcong48|lrand48|mrand48|nrand48|random|seed48|setstate|srand|strfry|srandom|g_rand_boolean|g_rand_int|g_rand_int_range|g_rand_double|g_rand_double_range|g_random_boolean|g_random_int|g_random_int_range|g_random_double|g_random_double_range":
    (normal, 3,
     "This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327)",
     "Use a more secure technique for acquiring random values",
     "random", "", {}),

    "crypt|crypt_r":
    (normal, 4,
     "The crypt functions use a poor one-way hashing algorithm; " +
     "since they only accept passwords of 8 characters or fewer " +
     "and only a two-byte salt, they are excessively vulnerable to " +
     "dictionary attacks given today's faster computing equipment (CWE-327)",
     "Use a different algorithm, such as SHA-256, with a larger, " +
     "non-repeating salt",
     "crypto", "", {}),

    # OpenSSL EVP calls to use DES.
    "EVP_des_ecb|EVP_des_cbc|EVP_des_cfb|EVP_des_ofb|EVP_desx_cbc":
    (normal, 4,
     "DES only supports a 56-bit keysize, which is too small given today's computers (CWE-327)",
     "Use a different patent-free encryption algorithm with a larger keysize, " +
     "such as 3DES or AES",
     "crypto", "", {}),

    # Other OpenSSL EVP calls to use small keys.
    "EVP_rc4_40|EVP_rc2_40_cbc|EVP_rc2_64_cbc":
    (normal, 4,
     "These keysizes are too small given today's computers (CWE-327)",
     "Use a different patent-free encryption algorithm with a larger keysize, " +
     "such as 3DES or AES",
     "crypto", "", {}),

    "chroot":
    (normal, 3,
     "chroot can be very helpful, but is hard to use correctly (CWE-250/CWE-22)",
     "Make sure the program immediately chdir(\"/\")," +
     " closes file descriptors," +
     " and drops root privileges, and that all necessary files" +
     " (and no more!) are in the new root",
     "misc", "", {}),

    "getenv|curl_getenv":
    (normal, 3, "Environment variables are untrustable input if they can be" +
     " set by an attacker.  They can have any content and" +
     " length, and the same variable can be set more than once (CWE-807/CWE-20)",
     "Check environment variables carefully before using them",
     "buffer", "", {'input': 1}),

    "g_get_home_dir":
    (normal, 3, "This function is synonymous with 'getenv(\"HOME\")';" +
     "it returns untrustable input if the environment can be" +
     "set by an attacker.  It can have any content and length, " +
     "and the same variable can be set more than once (CWE-807/CWE-20)",
     "Check environment variables carefully before using them",
     "buffer", "", {'input': 1}),

    "g_get_tmp_dir":
    (normal, 3, "This function is synonymous with 'getenv(\"TMP\")';" +
     "it returns untrustable input if the environment can be" +
     "set by an attacker.  It can have any content and length, " +
     "and the same variable can be set more than once (CWE-807/CWE-20)",
     "Check environment variables carefully before using them",
     "buffer", "", {'input': 1}),


    # These are Windows-unique:

    # TODO: Should have lower risk if the program checks return value.
    "RpcImpersonateClient|ImpersonateLoggedOnUser|CoImpersonateClient|" +
    "ImpersonateNamedPipeClient|ImpersonateDdeClientWindow|ImpersonateSecurityContext|" +
    "SetThreadToken":
    (normal, 4, "If this call fails, the program could fail to drop heightened privileges (CWE-250)",
     "Make sure the return value is checked, and do not continue if a failure is reported",
     "access", "", {}),

    "InitializeCriticalSection":
    (normal, 3, "Exceptions can be thrown in low-memory situations",
     "Use InitializeCriticalSectionAndSpinCount instead",
     "misc", "", {}),

    "EnterCriticalSection":
    (normal, 3, "On some versions of Windows, exceptions can be thrown in low-memory situations",
     "Use InitializeCriticalSectionAndSpinCount instead",
     "misc", "", {}),

    "LoadLibrary|LoadLibraryEx":
    (normal, 3, "Ensure that the full path to the library is specified, or current directory may be used (CWE-829/CWE-20)",
     "Use registry entry or GetWindowsDirectory to find library path, if you aren't already",
     "misc", "", {'input': 1}),

    "SetSecurityDescriptorDacl":
    (c_hit_if_null, 5,
     "Never create NULL ACLs; an attacker can set it to Everyone (Deny All Access), " +
     "which would even forbid administrator access (CWE-732)",
     "",
     "misc", "", {'check_for_null': 3}),

    "AddAccessAllowedAce":
    (normal, 3,
     "This doesn't set the inheritance bits in the access control entry (ACE) header (CWE-732)",
     "Make sure that you set inheritance by hand if you wish it to inherit",
     "misc", "", {}),

    "getlogin":
    (normal, 4,
     "It's often easy to fool getlogin.  Sometimes it does not work at all, because some program messed up the utmp file.  Often, it gives only the first 8 characters of the login name. The user currently logged in on the controlling tty of our program need not be the user who started it.  Avoid getlogin() for security-related purposes (CWE-807)",
     "Use getpwuid(geteuid()) and extract the desired information instead",
     "misc", "", {}),

    "cuserid":
    (normal, 4,
     "Exactly what cuserid() does is poorly defined (e.g., some systems use the effective uid, like Linux, while others like System V use the real uid). Thus, you can't trust what it does. It's certainly not portable (The cuserid function was included in the 1988 version of POSIX, but removed from the 1990 version).  Also, if passed a non-null parameter, there's a risk of a buffer overflow if the passed-in buffer is not at least L_cuserid characters long (CWE-120)",
     "Use getpwuid(geteuid()) and extract the desired information instead",
     "misc", "", {}),

    "getpw":
    (normal, 4,
     "This function is dangerous; it may overflow the provided buffer. It extracts data from a 'protected' area, but most systems have many commands to let users modify the protected area, and it's not always clear what their limits are.  Best to avoid using this function altogether (CWE-676/CWE-120)",
     "Use getpwuid() instead",
     "buffer", "", {}),

    "getpass":
    (normal, 4,
     "This function is obsolete and not portable. It was in SUSv2 but removed by POSIX.2.  What it does exactly varies considerably between systems, particularly in where its prompt is displayed and where it gets its data (e.g., /dev/tty, stdin, stderr, etc.). In addition, some implementations overflow buffers. (CWE-676/CWE-120/CWE-20)",
     "Make the specific calls to do exactly what you want.  If you continue to use it, or write your own, be sure to zero the password as soon as possible to avoid leaving the cleartext password visible in the process' address space",
     "misc", "", {'input': 1}),

    "gsignal|ssignal":
    (normal, 2,
     "These functions are considered obsolete on most systems, and very non-poertable (Linux-based systems handle them radically different, basically if gsignal/ssignal were the same as raise/signal respectively, while System V considers them a separate set and obsolete) (CWE-676)",
     "Switch to raise/signal, or some other signalling approach",
     "obsolete", "", {}),

    "memalign":
    (normal, 1,
     "On some systems (though not Linux-based systems) an attempt to free() results from memalign() may fail. This may, on a few systems, be exploitable.  Also note that memalign() may not check that the boundary parameter is correct (CWE-676)",
     "Use posix_memalign instead (defined in POSIX's 1003.1d).  Don't switch to valloc(); it is marked as obsolete in BSD 4.3, as legacy in SUSv2, and is no longer defined in SUSv3.  In some cases, malloc()'s alignment may be sufficient",
     "free", "", {}),

    "ulimit":
    (normal, 1,
     "This C routine is considered obsolete (as opposed to the shell command by the same name, which is NOT obsolete) (CWE-676)",
     "Use getrlimit(2), setrlimit(2), and sysconf(3) instead",
     "obsolete", "", {}),

    "usleep":
    (normal, 1,
     "This C routine is considered obsolete (as opposed to the shell command by the same name).   The interaction of this function with SIGALRM and other timer functions such as sleep(), alarm(), setitimer(), and nanosleep() is unspecified (CWE-676)",
     "Use nanosleep(2) or setitimer(2) instead",
     "obsolete", "", {}),

    # Input functions, useful for -I
    "recv|recvfrom|recvmsg|fread|readv":
    (normal, 0, "Function accepts input from outside program (CWE-20)",
     "Make sure input data is filtered, especially if an attacker could manipulate it",
     "input", "", {'input': 1}),

    # Unsafe STL functions that don't check the second iterator
    "equal|mismatch|is_permutation":
    (cpp_unsafe_stl,
     # Like strlen, this is mostly a risk to availability; at worst it
     # often causes a program crash.
     1,
     "Function does not check the second iterator for over-read conditions (CWE-126)",
     "This function is often discouraged by most C++ coding standards in favor of its safer alternatives provided since C++14. Consider using a form of this function that checks the second iterator before potentially overflowing it",
     "buffer", "", {}),

    # TODO: detect C++'s:   cin >> charbuf, where charbuf is a char array; the problem
    #       is that flawfinder doesn't have type information, and ">>" is safe with
    #       many other types.
    # ("send" and friends aren't todo, because they send out.. not input.)
    # TODO: cwd("..") in user's space - TOCTOU vulnerability
    # TODO: There are many more rules to add, esp. for TOCTOU.
}



def find_column(text, position):
    "Find column number inside line."
    newline = text.rfind("\n", 0, position)
    if newline == -1:
        return position + 1
    return position - newline


def get_context(text, position):
    "Get surrounding text line starting from text[position]"
    linestart = text.rfind("\n", 0, position + 1) + 1
    lineend = text.find("\n", position, len(text))
    if lineend == -1:
        lineend = len(text)
    return text[linestart:lineend]


p_trailingbackslashes = re.compile(r'(\s|\\(\n|\r))*$')
def internal_warn(message):
    print(message)

def extract_c_parameters(text, pos=0):
    "Return a list of the given C function's parameters, starting at text[pos]"
    # '(a,b)' produces ['', 'a', 'b']
    i = pos
    # Skip whitespace and find the "("; if there isn't one, return []:
    while i < len(text):
        if text[i] == '(':
            break
        elif text[i] in string.whitespace:
            i = i + 1
        else:
            return []
    else:  # Never found a reasonable ending.
        return []
    i = i + 1
    parameters = [""]  # Insert 0th entry, so 1st parameter is parameter[1].
    currentstart = i
    parenlevel = 1
    instring = 0  # 1=in double-quote, 2=in single-quote
    incomment = 0
    while i < len(text):
        c = text[i]
        if instring:
            if c == '"' and instring == 1:
                instring = 0
            elif c == "'" and instring == 2:
                instring = 0
                # if \, skip next character too.  The C/C++ rules for
                # \ are actually more complex, supporting \ooo octal and
                # \xhh hexadecimal (which can be shortened),
                # but we don't need to
                # parse that deeply, we just need to know we'll stay
                # in string mode:
            elif c == '\\':
                i = i + 1
        elif incomment:
            if c == '*' and text[i:i + 2] == '*/':
                incomment = 0
                i = i + 1
        else:
            if c == '"':
                instring = 1
            elif c == "'":
                instring = 2
            elif c == '/' and text[i:i + 2] == '/*':
                incomment = 1
                i = i + 1
            elif c == '/' and text[i:i + 2] == '//':
                while i < len(text) and text[i] != "\n":
                    i = i + 1
            elif c == '\\' and text[i:i + 2] == '\\"':
                i = i + 1  # Handle exposed '\"'
            elif c == '(':
                parenlevel = parenlevel + 1
            elif c == ',' and (parenlevel == 1):
                parameters.append(
                    p_trailingbackslashes.sub('', text[currentstart:i]).strip())
                currentstart = i + 1
            elif c == ')':
                parenlevel = parenlevel - 1
                if parenlevel <= 0:
                    parameters.append(
                        p_trailingbackslashes.sub(
                            '', text[currentstart:i]).strip())
                    # Re-enable these for debugging:
                    # print " EXTRACT_C_PARAMETERS: ", text[pos:pos+80]
                    # print " RESULTS: ", parameters
                    return parameters
            elif c == ';':
                internal_warn(
                    "Parsing failed to find end of parameter list; "
                    "semicolon terminated it in %s" % text[pos:pos + 200])
                return parameters
        i = i + 1
    internal_warn("Parsing failed to find end of parameter list in %s" %
                  text[pos:pos + 200])


def error(message):
    sys.stderr.write("Error: %s\n" % message)


def add_warning(hit):
    global hitlist

    if hit.level > 0:
        hitlist.append(hit)
        hit.show()


def print_warning(message):
    sys.stderr.write("Warning: ")
    sys.stderr.write(message)
    sys.stderr.write("\n")
    sys.stderr.flush()

c_extensions = {
    '.c': 1,
    '.h': 1,
    '.ec': 1,
    '.ecp': 1,  # Informix embedded C.
    '.pgc': 1,  # Postgres embedded C.
    '.C': 1,
    '.cpp': 1,
    '.CPP': 1,
    '.cxx': 1,
    '.cc': 1,  # C++
    '.CC': 1,
    '.c++': 1,  # C++.
    '.pcc': 1,  # Oracle C++
    '.hpp': 1,
    '.H': 1,  # .h - usually C++.
}

def preprocess_files_c(files):
    """
    预处理待检测目录或文件，返回 c 文件列表
    :param files: 待检测目录或文件，参数输入
    :return: c_files 所有待检测 c 文件
    """
    global num_links_skipped,c_files,num_dotdirs_skipped
    for f in files:
        if os.path.islink(f):
            print_warning("Skipping symbolic link " + f)

        elif os.path.isdir(f):
            # At one time flawfinder used os.path.walk, but that Python
            # built-in doesn't give us enough control over symbolic links.
            # So, we'll walk the filesystem hierarchy ourselves:
            if  os.path.islink(f):
                print_warning("Skipping symbolic link directory " + f)
                return
            base_filename = os.path.basename(f)

            for dir_entry in os.listdir(f):
                preprocess_files_c([os.path.join(f,dir_entry)])
            # Now we will FIRST check if the file appears to be a C/C++ file, and
            # THEN check if it's a regular file or symlink.  This is more complicated,
            # but I do it this way so that there won't be a lot of pointless
            # warnings about skipping files we wouldn't have used anyway.
        dotposition = f.rfind(".")
        if dotposition > 1:
            extension = f[dotposition:]
            if extension in c_extensions:
                # Its name appears to be a C/C++ source code file.
                if os.path.islink(f):
                    print_warning("Skipping symbolic link file " + f)
                elif not os.path.isfile(f):
                    # Skip anything not a normal file.  This is so that
                    # device files, etc. won't cause trouble.
                    print_warning("Skipping non-regular file " + h(f))
                else:
                    # We want to know the difference only with files found in the
                    # patch.
                    c_files.append(f)
        elif not os.path.exists(f):
            if f.startswith("\342\210\222"):
                print_warning(
                    "Skipping non-existent filename starting with UTF-8 long dash "
                    + f)
            else:
                print_warning("Skipping non-existent file " + f)
        else:
            print_warning("Skipping non-regular file " + f)


p_whitespace = re.compile(r'[ \t\v\f]+')
p_include = re.compile(r'#\s*include\s+(<.*?>|".*?")')
p_c_word = re.compile(r'[A-Za-z_][A-Za-z_0-9$]*')
p_digits = re.compile(r'[0-9]')
max_lookahead = 500  # Lookahead limit for c_static_array.

def process_c_file(f):
    global  count
    filename = f
    linenumber = 1
    incomment = 0
    instring = 0
    linebegin = 1
    if os.path.islink(f):
        print("BUG! Somehow got a symlink in process_c_file!")
        return
    try:
        my_input = open(f, "r")
    except BaseException:
        print("Error: failed to open", f)
        sys.exit(1)

    # Read ENTIRE file into memory.  Use readlines() to convert \n if necessary.
    # This turns out to be very fast in Python, even on large files, and it
    # eliminates lots of range checking later, making the result faster.
    # We're examining source files, and today, it would be EXTREMELY bad practice
    # to create source files larger than main memory space.
    # Better to load it all in, and get the increased speed and reduced
    # development time that results.

    #print("Examining", f)
    sys.stdout.flush()

    text = "".join(my_input.readlines())

    i = 0
    while i < len(text):
        # This is a trivial tokenizer that just tries to find "words", which
        # match [A-Za-z_][A-Za-z0-9_]*.  It skips comments & strings.
        # It also skips "#include <...>", which must be handled specially
        # because "<" and ">" aren't usually delimiters.
        # It doesn't bother to tokenize anything else, since it's not used.
        # The following is a state machine with 3 states: incomment, instring,
        # and "normal", and a separate state "linebegin" if at BOL.

        # Skip any whitespace
        m = p_whitespace.match(text, i)
        if m:
            i = m.end(0)
        if i >= len(text):
            c = "\n"  # Last line with no newline, we're done
        else:
            c = text[i]
        if linebegin:  # If at beginning of line, see if #include is there.
            linebegin = 0
            if c == "#":
                codeinline = 1  # A directive, count as code.
            m = p_include.match(text, i)
            if m:  # Found #include, skip it.  Otherwise: #include <stdio.h>
                i = m.end(0)
                continue
        if c == "\n":
            linenumber = linenumber + 1
            linebegin = 1
            i = i + 1
            continue
        i = i + 1  # From here on, text[i] points to next character.
        if i < len(text):
            nextc = text[i]
        else:
            nextc = ''
        if incomment:
            if c == '*' and nextc == '/':
                i = i + 1
                incomment = 0
        elif instring:
            if c == '\\' and (nextc != "\n"):
                i = i + 1
            elif c == '"' and instring == 1:
                instring = 0
            elif c == "'" and instring == 2:
                instring = 0
        else:
            if c == '/' and nextc == '*':
                i = i + 1
                incomment = 1
            elif c == '/' and nextc == '/':  # "//" comments - skip to EOL.
                while i < len(text) and text[i] != "\n":
                    i = i + 1
            elif c == '"':
                instring = 1
            elif c == "'":
                instring = 2
            else:
                m = p_c_word.match(text, i - 1)
                if m:  # Do we have a word?
                    startpos = i - 1
                    endpos = m.end(0)
                    i = endpos
                    word = text[startpos:endpos]
                    # print "Word is:", text[startpos:endpos]
                    if (word in c_ruleset) and c_valid_match(text, endpos):

                        # FOUND A MATCH, setup & call hook.
                        # print "HIT: #%s#\n" % word
                        # Don't use the tuple assignment form, e.g., a,b=c,d
                        # because Python (least 2.2.2) does that slower
                        # (presumably because it creates & destroys temporary tuples)
                        hit = Hit(c_ruleset[word])
                        hit.name = word
                        hit.start = startpos
                        hit.end = endpos
                        hit.line = linenumber
                        hit.column = find_column(text, startpos)
                        hit.filename = filename
                        hit.context_text = get_context(text, startpos)
                        hit.parameters = extract_c_parameters(text, endpos)
                        if hit.extract_lookahead:
                            hit.lookahead = text[startpos:
                                                 startpos + max_lookahead]
                        hit.hook(hit)
                        count = count + 1
                elif p_digits.match(c):
                    while i < len(text) and p_digits.match(
                            text[i]):  # Process a number.
                        i = i + 1
                # else some other character, which we ignore.
                # End of loop through text. Wrap up.
    if incomment:
        error("File ended while in comment.")
    if instring:
        error("File ended while in string.")


def expand_ruleset(ruleset):
    # Rulesets can have compressed sets of rules
    # (multiple function names separated by "|".
    # Expand the given ruleset.
    # Note that this "for" loop modifies the ruleset while it's iterating,
    # so we *must* convert the keys into a list before iterating.
    for rule in list(ruleset.keys()):
        if "|" in rule: # We found a rule to expand.
            for newrule in rule.split("|"):
                if newrule in ruleset:
                    print("Error: Rule %s, when expanded, overlaps %s" % (
                        rule, newrule))
                    sys.exit(1)
                ruleset[newrule] = ruleset[rule]
            del ruleset[rule]
    # To print out the set of keys in the expanded ruleset, run:
    #   print `ruleset.keys()`


def initialize_ruleset():
    expand_ruleset(c_ruleset)


def main_process():
    for f in c_files:
        process_c_file(f)


def save_result():
    with open('result_temp.csv','w',newline='') as f:
        writer = csv.writer(f)
        for content in csv_content:
            writer.writerow(content)


if __name__ == '__main__':

    #start = time.time()
    initialize_ruleset()
    files = []
    args = sys.argv[1:]
    if(args is None or len(args) == 0):
        print("No Input Files")
    for arg in args:
        files.append(arg)
    initialize_ruleset()
    preprocess_files_c(files)
    main_process()
    save_result()
    #print(time.time() - start)

