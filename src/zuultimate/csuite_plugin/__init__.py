"""C-Suite integration plugin -- exposes Zuultimate AI security as C-Suite tools."""

try:
    from zuultimate.csuite_plugin.plugin import ZuultimateSecurityPlugin
    __all__ = ["ZuultimateSecurityPlugin"]
except ImportError:
    __all__ = []
