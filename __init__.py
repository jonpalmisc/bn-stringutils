import json
import re

from binaryninja import *

# Settings keys & options
S_ROOT = "stringutils"
S_ASK_POST_ANALYSIS = f"{S_ROOT}.ask_post_analysis"
S_NAME_LIMIT = f"{S_ROOT}.name_limit"
S_NAME_STYLE = f"{S_ROOT}.name_style"
S_NAME_STYLE_SNAKE_CASE = "snake_case"
S_NAME_STYLE_PASCAL_CASE = "PascalCase"

Settings().register_group(S_ROOT, "String Utilities Plugin")

Settings().register_setting(
    S_ASK_POST_ANALYSIS,
    json.dumps(
        {
            "title": "Post-analysis prompt",
            "description": "Ask to auto-name all strings after analysis completes.",
            "default": False,
            "type": "boolean",
        }
    ),
)

Settings().register_setting(
    S_NAME_LIMIT,
    json.dumps(
        {
            "title": "Maximum name length",
            "description": "The maximum name length for auto-named strings.",
            "default": 20,
            "type": "number",
        }
    ),
)

Settings().register_setting(
    S_NAME_STYLE,
    json.dumps(
        {
            "title": "Naming convention",
            "description": "The naming convention to use for auto-named strings.",
            "default": S_NAME_STYLE_PASCAL_CASE,
            "type": "string",
            "enum": [S_NAME_STYLE_SNAKE_CASE, S_NAME_STYLE_PASCAL_CASE],
        }
    ),
)

# Simplify a string into snake_case form.
def name_sanitize_snake_case(s):
    cleaned = re.sub(r"[^A-Za-z0-9 ]+", "", s)
    cleaned = cleaned.strip().replace(" ", "_").lower()

    return name_truncate(cleaned)


# Simplify a string into PascalCase form.
def name_sanitize_pascal_case(s):
    cleaned = re.sub(r"[^A-Za-z0-9 ]+", "", s)
    cleaned = "".join(c for c in cleaned.strip().title() if not c.isspace())

    return name_truncate(cleaned)


# Truncate a string to the length of the user's preference.
def name_truncate(s):
    max_len = Settings().get_integer(S_NAME_LIMIT)
    return s[:max_len]


# Automatically defines a named symbol for a given string.
def auto_define_string(bv, s):
    if Settings().get_string(S_NAME_STYLE) == S_NAME_STYLE_SNAKE_CASE:
        auto_name = "s_" + name_sanitize_snake_case(s.value)
    else:
        auto_name = "s" + name_sanitize_pascal_case(s.value)

    symbol = Symbol(SymbolType.DataSymbol, s.start, auto_name)
    bv.define_user_symbol(symbol)


# UI action to automatically name the string under the cursor.
def auto_name_selected_string(bv, address):
    selected_string = bv.get_string_at(address)

    if selected_string == None:
        show_message_box(
            "String Utilities",
            "No string selected!",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    auto_define_string(bv, selected_string)


# UI action to automatically name all strings in the database.
def auto_name_all_strings(bv, address):
    print("Automatically naming all known strings...")

    for s in bv.strings:
        auto_define_string(bv, s)

    print("Done!")


# Ask the user if they would like to automatically name all identified strings.
def ask_name_all_strings(bv):
    choice = show_message_box(
        "String Utilities",
        "Analysis is complete. Would you like to auto-name identified strings?",
        MessageBoxButtonSet.YesNoButtonSet,
        MessageBoxIcon.QuestionIcon,
    )

    if choice == MessageBoxButtonResult.YesButton:
        auto_name_all_strings(bv, 0)


# Callback to trigger ask_name_all_strings() after analysis completes if requested.
def analysis_complete_callback(event):
    mainthread.execute_on_main_thread(lambda: ask_name_all_strings(event.view))


# Callback to set up another callback. That's what's up.
def view_finalized_callback(bv):
    if Settings().get_bool(S_ASK_POST_ANALYSIS):
        AnalysisCompletionEvent(bv, analysis_complete_callback)


BinaryViewType.add_binaryview_finalized_event(view_finalized_callback)


PluginCommand.register_for_address(
    "Auto-name selected string",
    "Automatically name the selected string",
    auto_name_selected_string,
)

PluginCommand.register_for_address(
    "Auto-name all strings",
    "Automatically name all the strings in the database",
    auto_name_all_strings,
)
