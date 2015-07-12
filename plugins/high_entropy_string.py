# -*- coding:utf-8 -*-

import bandit
from bandit.core.test_properties import *

import pdb
import ast
import logging
import re

import zxcvbn

#things to look for
#- large absolute entropy
#- high per-character entropy with minimum absolute
#- assignment targets containing 'key' 'secret' 'pass' 'password'

# string patterns to ignore
#- words with spaces
#- CONSTANT_LOOKING_THINGS
#- http://urls

ENTROPY_PATTERNS_TO_DISCOUNT = [
        re.compile(r'\s+'),  # secrets don't contain whitespace
        re.compile(r'([A-Z]+_)+[A-Z]+'),  # secrets don't look like constants
        re.compile(r'^[a-z]+://'), # secrets don't look like URIs
        re.compile(r'\{\d{0,2}\}'), # secrets don't look like format strings
        re.compile(r'^AKIA'), # secrets don't look like AWS key IDs
        ]
SECRET_VAR_HINTS = [
        'key',
        'secret',
        'pass',
        'password',
        'token'
        ]
SAFE_SECRET_SOURCES = [
        'os.environ.get',
        'str_env'
        ]

def is_assignment_target_secret(context):
    statement = context.statement['node']
    parts = []
    if isinstance(statement, ast.Assign):
        for t in statement.targets:
            if isinstance(t, ast.Name):
                parts = t.id.lower().split('_')
            elif isinstance(t, ast.Subscript):
                if isinstance(t.value, ast.Attribute):
                    parts += t.value.attr.lower().split('_')
                elif isinstance(t.value, ast.Name):
                    parts += t.value.id.lower().split('_')
                if isinstance(t.slice.value, ast.Str):
                    parts += t.slice.value.s.lower().split('_')

            if any([p in SECRET_VAR_HINTS for p in parts]):
                return True
    return False

def assignment_target_pretty(context):
    targets = context.statement['node'].targets
    if len(targets) == 1:
        return _assignment_target_pretty(targets[0])
    else:
        return str([_assignment_target_pretty(t) for t in targets])

def _assignment_target_pretty(target):
    pretty = ''
    if isinstance(target, ast.Name):
        pretty = target.id
    elif isinstance(target, ast.Subscript):
        #pdb.set_trace()
        if isinstance(target.value, ast.Attribute):
            pretty = target.value.attr
        elif isinstance(target.value, ast.Name):
            pretty = target.value.id
        if isinstance(target.slice.value, ast.Str):
            pretty += '[{}]'.format(target.slice.value.s)

    return pretty

@checks('Str')
#@checks('Assign')
def safe_secret_assignment(context):
    is_assignment = False
    is_target_likely_secret = False
    is_safe_secret_source = False
    is_hardcoded_string = False
    discounted_entropy_string = False
    entropy = 0
    entropy_per_char = 0

    if not context.string_val:
        return

    statement = context.statement['node']
    if isinstance(statement, ast.Assign):
        is_assignment = True
        is_target_likely_secret = is_assignment_target_secret(context)
        if is_target_likely_secret:
            if isinstance(statement.value, ast.Call):
                f = statement.value.func
                func_name_parts = []
                while True:
                    if isinstance(f, ast.Attribute):
                        func_name_parts.insert(0, f.attr)
                        f = f.value
                    elif isinstance(f, ast.Name):
                        func_name_parts.insert(0, f.id)
                        source_name = '.'.join(func_name_parts)
                        if source_name in SAFE_SECRET_SOURCES:
                            is_safe_secret_source = True
                        break
                    elif isinstance(f, ast.Str):
                        is_hardcoded_string = True
                        logging.warning("!!STRING!! %s" % str(func_name_parts))

                        string = context.string_val
                        discounted_entropy_string = any((pattern.search(string) for pattern in ENTROPY_PATTERNS_TO_DISCOUNT))
                        entropy = zxcvbn.password_strength(string)['entropy']
                        entropy_per_char = entropy/float(len(string))
                        break
                    else:
                        logging.warning("Don't know what to do with type {}".format(type(f.value)))
                        break
            elif isinstance(statement.value, ast.Str):
                string = statement.value.s
                discounted_entropy_string = any((pattern.search(string) for pattern in ENTROPY_PATTERNS_TO_DISCOUNT))
                entropy = zxcvbn.password_strength(string)['entropy']
                entropy_per_char = entropy/float(len(string))
                is_hardcoded_string = True
    else: # not assignment -- let's just look at the string itself
        string = context.string_val
        discounted_entropy_string = any((pattern.search(string) for pattern in ENTROPY_PATTERNS_TO_DISCOUNT))
        entropy = zxcvbn.password_strength(string)['entropy']
        entropy_per_char = entropy/float(len(string))

    # scoring
    confidence = 0
    if is_assignment:
        if is_target_likely_secret:
            if not is_hardcoded_string and not is_safe_secret_source:
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.LOW,
                    text="Unknown secret source assigned to '(%s)'" % assignment_target_pretty(context)
                )
            elif is_hardcoded_string and not discounted_entropy_string:
                confidence += 2
    if (entropy > 80 or (entropy > 40 and entropy_per_char > 3)) and not discounted_entropy_string:
        confidence += 1
    if entropy >= 120 and not discounted_entropy_string:
        confidence += 1

    debug = {
        'discounted_entropy_string': discounted_entropy_string,
        'entropy': entropy,
        'entropy_per_char': entropy_per_char,
        'is_target_likely_secret': is_target_likely_secret,
        'is_assignment': is_assignment,
        'is_hardcoded_string': is_hardcoded_string,
        'is_safe_secret_source': is_safe_secret_source,
        }
    #print(debug)

    if confidence >= 1:
        if confidence == 1:
            confidence = bandit.LOW
        elif confidence == 2:
            confidence = bandit.MEDIUM
        else:
            confidence = bandit.HIGH

        if is_assignment:
            return bandit.Issue(
                severity=confidence,
                confidence=confidence,
                text="Possible hardcoded secret assigned to '%s'" % assignment_target_pretty(context)
                )
        else:
            return bandit.Issue(
                severity=confidence,
                confidence=confidence,
                text="Possible hardcoded secret '%s...%s'" % (string[:4], string[-4:])
                )
