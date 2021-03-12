import re

from binaryninja import *

LEN_LIMIT = 20


def name_sanitize(s):
    return (
        re.sub(r"[^A-Za-z0-9 ]+", "", s).strip().replace(" ", "_").lower()[:LEN_LIMIT]
    )


def auto_define_string(bv, s):
    auto_name = "str_" + name_sanitize(s.value)

    symbol = Symbol(SymbolType.DataSymbol, s.start, auto_name)
    bv.define_auto_symbol(symbol)


def auto_name_selected_string(bv, address):
    selected_string = bv.get_string_at(address)

    if selected_string == None:
        show_message_box("Error", "Selected object is not a string.", 0, 0)
        return

    auto_define_string(bv, selected_string)


def auto_name_all_strings(bv, address):
    for s in bv.strings:
        auto_define_string(bv, s)


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
