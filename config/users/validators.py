import re

from rest_framework.exceptions import ValidationError


def number_validator(password):
    regex = re.compile('[0-9]')
    if regex.search(password):
        raise ValidationError(
                "password must include number",
                code="password_must_include_number"
                )

def letter_validator(password):
    regex = re.compile('[a-zA-Z]')
    if regex.search(password):
        raise ValidationError(
                "password must include letter",
                code="password_must_include_letter"
                )

def special_char_validator(password):
    regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    if regex.search(password):
        raise ValidationError(
                "password must include special char",
                code="password_must_include_special_char"
                )