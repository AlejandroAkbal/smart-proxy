import sys
import types


def install_proxy_stack_stubs(mitmproxy_module):
    """Install the import-time mitmproxy surface used by smart_proxy tests."""
    ctx = types.ModuleType("mitmproxy.ctx")
    ctx.options = types.SimpleNamespace(proxyauth=None)
    mitmproxy_module.ctx = ctx
    sys.modules["mitmproxy.ctx"] = ctx

    proxy = types.ModuleType("mitmproxy.proxy")
    commands = types.ModuleType("mitmproxy.proxy.commands")
    events = types.ModuleType("mitmproxy.proxy.events")
    layer = types.ModuleType("mitmproxy.proxy.layer")
    mode_specs = types.ModuleType("mitmproxy.proxy.mode_specs")
    layers = types.ModuleType("mitmproxy.proxy.layers")
    modes = types.ModuleType("mitmproxy.proxy.layers.modes")

    class Layer:
        def __init__(self, context):
            self.context = context

    class NextLayer:
        pass

    class Start:
        pass

    class CloseConnection:
        def __init__(self, connection):
            self.connection = connection

    class Socks5Mode:
        pass

    class Socks5AuthData:
        pass

    layer.Layer = Layer
    layer.NextLayer = NextLayer
    events.Start = Start
    commands.CloseConnection = CloseConnection
    mode_specs.Socks5Mode = Socks5Mode
    modes.Socks5AuthData = Socks5AuthData
    layers.modes = modes
    proxy.commands = commands
    proxy.events = events
    proxy.layer = layer
    proxy.mode_specs = mode_specs
    mitmproxy_module.proxy = proxy

    sys.modules["mitmproxy.proxy"] = proxy
    sys.modules["mitmproxy.proxy.commands"] = commands
    sys.modules["mitmproxy.proxy.events"] = events
    sys.modules["mitmproxy.proxy.layer"] = layer
    sys.modules["mitmproxy.proxy.mode_specs"] = mode_specs
    sys.modules["mitmproxy.proxy.layers"] = layers
    sys.modules["mitmproxy.proxy.layers.modes"] = modes
