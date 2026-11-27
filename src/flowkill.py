# Per-flow termination. There is deliberately NO app-wide block primitive here.
from . import winapi

def terminate_client_flow(client_port, proxy_port):
    row = winapi.flow_of_client_port(client_port, proxy_port)
    if not row:
        return False
    return winapi.kill_flow(row)

def terminate_row(row):
    return winapi.kill_flow(row)
