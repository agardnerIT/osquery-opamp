"""OpAMP agent for osquery, delivered as an osquery extension.

The extension is a normal osquery extension: it registers with the daemon over
the Thrift API in ``osquery/extensions/thrift/osquery.thrift`` and uses
documented registry calls, so nothing in osquery's core is modified.

Push mode (default) merges remote configuration into the daemon's live config
through ``config/update``. Pull mode (``--config_plugin=opamp``) is also
supported, answering ``genConfig`` from the last configuration received.
"""

__version__ = "0.1.0"
