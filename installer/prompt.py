import sys
from colored import fg, bg, attr
import re

def get_input(prompt, specified_value=None, expected_answers=None, expected_type=int):
    if expected_answers is None:
        expected_answers = []
    response = None
    if specified_value:
        # Value specified, validating user provided input
        if expected_answers:
            if specified_value not in expected_answers:
                print(f"{fg('red')}{specified_value} 是无效的。请选择这些内容：{expected_answers}{attr('reset')}")
                sys.exit(1)
        return specified_value

    else:
        # Value not specified, prompt user
        while isinstance(response, expected_type) is False:
            if sys.version_info[0] >= 3:
                if expected_answers:
                    question = input(f"{fg('misty_rose_3')} >> {prompt} {expected_answers}{attr('reset')}: ")
                else:
                    question = input(f"{fg('misty_rose_3')} >> {prompt}{attr('reset')}: ")
            else:
                # Python 2
                if expected_answers:
                    question = raw_input(f"{fg('misty_rose_3')} >> {prompt} {expected_answers}{attr('reset')}: ")
                else:
                    question = raw_input(f"{fg('misty_rose_3')} >> {prompt}{attr('reset')}: ")

            try:
                response = expected_type(question.rstrip().lstrip())
            except ValueError:
                print(f"Sorry, expected answer is something from {expected_answers}")


            if expected_answers:
                if response not in expected_answers:
                    print(f"{fg('red')}{response} 是无效的。请选择这些内容：{expected_answers}{attr('reset')}")
                    response = None

    return response