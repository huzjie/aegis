import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：启动 aegis HTTP 控制平面（Ctrl-C 退出）。"""
from aegis.api import Aegis
from aegis.gateway.server import serve

if __name__ == "__main__":
    print("启动控制平面: http://127.0.0.1:8700")
    print("  GET  /health         健康检查")
    print("  GET  /v1/signatures  特征库")
    print("  POST /v1/compile     编译策略")
    print("  POST /v1/scan        扫描快照")
    print("  POST /v1/gen         自然语言生成")
    serve(port=8700, engine=Aegis())
