import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_name

PLUGIN_HOTKEY = 'Shift-T'
COMMENT       = 'IDA-names automatically renames pseudocode windows with the current function name.'
WANTED_NAME   = 'IDA-names'

def set_window_title(view, newtitle):
    '''
    Recursively iterate qt widgets and change widget title if title matches top widget title.
    '''
    widget   = ida_kernwin.PluginForm.TWidgetToPyQtWidget(view)
    oldtitle = ida_kernwin.get_widget_title(view)

    def set_title_recursive(widget, oldtitle, newtitle):
        if widget is not None:
            curtitle = ida_kernwin.get_widget_title(ida_kernwin.PluginForm.QtWidgetToTWidget(widget))
            if curtitle == oldtitle:
                widget.setWindowTitle(newtitle)
            set_title_recursive(widget.parentWidget(), oldtitle, newtitle)
    set_title_recursive(widget, oldtitle, newtitle)

class hex_hook(ida_hexrays.Hexrays_Hooks):
    def __init__(self, *args):
        super().__init__(*args)

    def refresh_pseudocode(self, vu: ida_hexrays.vdui_t):
        self._set_window_title_to_function_name(vu)
        return 0

    def switch_pseudocode(self, vu: ida_hexrays.vdui_t):
        self._set_window_title_to_function_name(vu)
        return 0

    @staticmethod
    def _set_window_title_to_function_name(vu: ida_hexrays.vdui_t) -> None:
        function_name = ida_funcs.get_func_name(vu.cfunc.entry_ea)
        set_window_title(vu.ct, hex_hook._demangle_name(function_name))

    @staticmethod
    def _demangle_name(name: str) -> str:
        demangled_name = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
        if not demangled_name:
            # IDA's demangler returns an empty string for non-mangled names
            return name

        # Avoid excessively long names by removing the arguments
        return demangled_name.split('(')[0]


def rename_window_cb():
    view = ida_kernwin.get_current_widget()
    if view is not None:
        title    = ida_kernwin.get_widget_title(view)
        newtitle = ida_kernwin.ask_str(title, 0, "New window title")
        if newtitle is not None and newtitle != "":
            set_window_title(view, newtitle)

class ida_names(ida_idaapi.plugin_t):
    def __init__(self):
        self.flags       = ida_idaapi.PLUGIN_KEEP
        self.comment     = COMMENT
        self.help        = COMMENT
        self.wanted_name = WANTED_NAME
        self.hotkey      = None

    def init(self):
        self.hexrays_hook = hex_hook()
        self.hexrays_hook.hook()
        # Add hotkey
        self.hotkey = ida_kernwin.add_hotkey(PLUGIN_HOTKEY, rename_window_cb)
        if self.hotkey is None:
            ida_kernwin.msg(f'Failed to register {PLUGIN_HOTKEY} hotkey')
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _):
        s = ida_kernwin.ask_yn(1, 'Enable auto renaming of pseudocode windows?\n')
        if s == 1:
            self.hexrays_hook.hook()
        elif s == 0:
            self.hexrays_hook.unhook()

    def term(self):
        self.hexrays_hook.unhook()
        if self.hotkey is not None:
            ida_kernwin.del_hotkey(self.hotkey)

def PLUGIN_ENTRY():
    return ida_names()
