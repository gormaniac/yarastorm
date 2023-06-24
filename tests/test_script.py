import yarastorm.lib
x = yarastorm.lib.StormPkg()
class X(yarastorm.lib.StormPkg):
    """yo"""

class Y(yarastorm.lib.StormPkg):
    """yo"""

x = X()

path = "/Users/gormo/projects/yarastorm/src/yarastorm/pkgproto"

x = X(proto_dir=path, proto_name='gormo.yara')
x.asdict()

y = Y(proto_dir=path, proto_name='gormo.pkg')
y.asdict()
