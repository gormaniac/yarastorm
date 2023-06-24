"""Library code for the yarastorm service."""


import json
import os
import sys

import synapse.common as s_common
from synapse.tools.genpkg import tryLoadPkgProto
import yaml


class StormPkg:
    """A Python representation of a Storm package, proto and definition.

    This class must be subclassed. Subclasses must set the following class
    properties according to their ``Properties`` docs below::

        pkg_name
        pkg_ver
        synapse_minversion

    By default, this subclasses expect a Storm package proto to be stored in a
    ``pkgproto`` directory that is within the same directory as the ``__init__.py``
    of the module the object is defined within. This can be changed. But, if
    it isn't, this means you must setup your package proto files to be built with
    your Python module.

    This object is ready to use on init - access the ``pkgdef`` prop for
    the full Storm package definition loaded from the definied package proto.

    It takes the following steps on start up:

        - Resolves the path of the package proto based on ``proto_name`` and
        ``proto_dir``.
        - Updates the proto's Yaml file with any of the required passed in
        arguments, if they are different from what was passed into the class.
        This behavior ensures that the Python references to the package's
        identifying information is accurate.
        - Loads the package proto using ``synapse.tools.genpkg.tryLoadPkgProto``.
        - Converts the returned object to a ``dict`` using ``json.dumps`` and
        ``json.loads``.
            - This is necessary because ``tryLoadPkgProto`` returns a "tuplified"
            object (the return of ``synapse.common.tuplify``). Which can return
            immutable objects that ``synapse.cortex.Cortex.addStormPkg`` expects
            to be mutable. So a ``StormSvc._storm_svc_pkgs`` works best when it
            is set to a ``dict``.
        - Sets the loaded package definition's ``build`` key to a ``dict`` containing
        the time using ``synapse.common.now``.
        - Sets the package definition ``dict`` to the ``pkdef`` property.

    Use the ``dict()`` method to get the ``pkdef`` property. The ``pkdef``
    property is also this object's ``__repr__``.

    Parameters
    ----------
    proto_name : str | None, optional
        The name of the package's proto Yaml file, without the extension,
        if it is different from ``pkg_name``. A value of ``None`` means
        ``pkg_name`` is used. By default None.
    proto_dir : str | None, optional
        The fully resolved directory that the package proto is in. A value
        of ``None`` tells ``StormPkg``. By default None.
    
    Properties
    ----------
    pkgdef : dict
        The loaded Storm package definition.
    pkg_name : str
        The name of the Storm package this object will represent.
    pkg_ver : str | tuple
        The version of the Storm package. Can either be a semantic version str
        or a Synapse version tuple.
    synapse_minversion : tuple
        The minimum Synapse version the Storm package works with.
    name : str
        A pointer to ``pkg_name``.
    verstr : str
        The normalized semantic version str based on ``pkg_ver``.
    vertup : str
        The normalized Synapse version tuple based on ``pkg_ver``.
    proto_dir : str
        The directory that the Storm package's proto is in. This is
        the ``proto_dir`` argument if it is passed. Otherwise, the dir
        is resolved by looking at the ``self.__class__.__module__`` name
        at init, finding the object this resolves to in ``sys.modules``,
        and reading the module's ``__file__``. Then joining this file's
        dir name with the value ``pkgproto``.
    proto_name : str
        The name of the Storm package's proto Yaml file (without extension).
        This is the ``proto_name`` argument if passed.
        Otherwise, it is ``self.name``.
    """

    pkg_name: str = None
    pkg_ver: str | tuple = None
    synapse_minversion: tuple = None

    def __init__(
        self,
        proto_name: str | None = None,
        proto_dir: str | None = None,
    ) -> None:

        if (
            self.pkg_name is None
            or self.pkg_ver is None
            or self.synapse_minversion is None
        ):
            raise ValueError("Subclasses must set the required class properties.")

        self.name = self.pkg_name
        self.verstr, self.vertup = normver(self.pkg_ver)

        if proto_dir:
            self.proto_dir = proto_dir
        else:
            self.proto_dir = os.path.abspath(
                os.path.join(
                    os.path.dirname(sys.modules[self.__class__.__module__].__file__),
                    "pkgproto",
                )
            )

        self.proto = os.path.join(
            self.proto_dir, f"{proto_name if proto_name else self.name}.yaml"
        )

        self._update_proto()

        self.pkgdef = self._load_proto()
        """A Python dict containing the full Storm package definition."""

    def __repr__(self):
        return self.pkgdef

    def _load_proto(self) -> dict:
        """Load the package proto and convert it to a package definition."""

        pkgdef = json.loads(
            json.dumps(tryLoadPkgProto(self.proto, readonly=True), sort_keys=True)
        )

        pkgdef["build"] = {"time": s_common.now()}

        return pkgdef

    def _update_proto(self) -> None:
        """Update the proto Yaml file to use the constants defined by this class."""

        with open(self.proto, "r") as rfd:
            proto_yaml = yaml.safe_load(rfd)

        if proto_yaml.get("name") != self.name:
            proto_yaml["name"] = self.name

        if proto_yaml.get("version") != self.verstr:
            proto_yaml["version"] = self.verstr

        if list(proto_yaml.get("synapse_minversion")) != list(self.synapse_minversion):
            proto_yaml["synapse_minversion"] = list(self.synapse_minversion)

        with open(self.proto, "wb") as wfd:
            yaml.safe_dump(proto_yaml, wfd, encoding="utf-8")


def normver(ver: str | tuple) -> tuple[str, tuple]:
    """Take either a version str "x.x.x" or tuple (x, x, x) and return both."""

    if isinstance(ver, str):
        verstr = ver
        vertup = tuple(ver.split("."))
    elif isinstance(ver, tuple):
        vertup = ver
        verstr = ".".join(ver)
    else:
        raise TypeError("Can only use a str or tuple as a Storm pkg version")

    return (verstr, vertup)
