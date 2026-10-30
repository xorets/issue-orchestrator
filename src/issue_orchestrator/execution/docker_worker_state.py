"""Authenticate daemon worker identity, liveness and selected network state."""
import ipaddress

from ..domain.original_delivery import DockerCustody
from .docker_engine import DockerEngine


def require_never_started_exec(provider: dict, container_id: str, exec_id: str,
                               user: str, command: list[str]) -> None:
    """Require the exact pre-start Docker exec observation; never infer it from absence."""
    process = provider.get('ProcessConfig')
    if (type(process) is not dict or provider.get('ID') != exec_id or provider.get('ContainerID') != container_id or
            provider.get('Running') is not False or type(provider.get('Pid')) is not int or
            provider['Pid'] != 0 or provider.get('ExitCode', False) is not None or
            not command or process.get('entrypoint') != command[0] or
            process.get('arguments') != command[1:] or process.get('user') != user or
            process.get('privileged') is not False or process.get('tty') is not False):
        raise ValueError('Docker provider never-started state is unknown')


def require_worker_identity(actual: dict, container_id: str, launch_digest: str) -> None:
    if (actual.get("Id") != container_id or
            actual.get("Config", {}).get("Labels", {}).get("io.builder.launch") != launch_digest):
        raise ValueError("Docker worker custody changed")


def require_first_model_liveness(actual: dict, provider: dict, custody: DockerCustody) -> None:
    """Strict daemon facts for the selected provider, before any model receipt."""
    state = actual.get("State", {})
    if (state.get("Running") is not True or state.get("Paused") is not False or state.get("Restarting") is not False or
            state.get("OOMKilled") is not False or state.get("Error") != "" or
            type(actual.get("RestartCount")) is not int or actual["RestartCount"] != 0 or
            provider.get("ID") != custody.provider_exec_id or provider.get("ContainerID") != custody.container_id or
            provider.get("Running") is not True or provider.get("ExitCode") is not None or
            type(state.get("Pid")) is not int or state["Pid"] <= 0 or
            type(provider.get("Pid")) is not int or provider["Pid"] <= 0):
        raise ValueError("Docker first-model exact worker/provider is not live")


def require_prestart_liveness(actual: dict) -> None:
    state = actual.get('State', {})
    if (state.get('Running') is not True or state.get('Paused') is not False or
            state.get('Restarting') is not False or state.get('OOMKilled') is not False or
            state.get('Error') != '' or type(state.get('Pid')) is not int or state['Pid'] <= 0 or
            type(actual.get('RestartCount')) is not int or actual['RestartCount'] != 0):
        raise ValueError('Docker pre-start worker is not live')


def require_bridge_endpoint(endpoint: dict, packet: dict, address: str) -> None:
    network = packet["network"]
    if (endpoint.get("NetworkID") != packet["network_id"] or endpoint.get("IPAddress") != address or
            endpoint.get("IPPrefixLen") != ipaddress.IPv4Network(network["subnet"]).prefixlen or
            endpoint.get("Gateway") != network["gateway"] or endpoint.get("GlobalIPv6Address") or
            endpoint.get("GlobalIPv6PrefixLen") or endpoint.get("IPv6Gateway")):
        raise ValueError("Docker bridge endpoint differs from selected IPv4 membership")
    ipam = endpoint.get("IPAMConfig") or {}
    if ipam.get("IPv6Address") or ipam.get("LinkLocalIPs"):
        raise ValueError("Docker bridge endpoint has unadmitted additional addresses")


def require_selected_bridge(engine: DockerEngine, packet: dict, controller: dict) -> None:
    if "network" not in packet:
        return
    network = packet["network"]
    actual = engine.request("GET", "/networks/" + packet["network_id"])
    if (actual.get("Id") != packet["network_id"] or actual.get("Driver") != "bridge" or
            actual.get("Scope") != "local" or actual.get("Internal") is not False or
            actual.get("EnableIPv6") is not False or
            actual.get("IPAM", {}).get("Driver") != "default" or
            actual.get("IPAM", {}).get("Config") != [{"Subnet": network["subnet"], "Gateway": network["gateway"]}] or
            actual.get("Options", {}).get("com.docker.network.bridge.name") != network["bridge_name"] or
            actual.get("Options", {}).get("com.docker.network.bridge.enable_icc") != "true"):
        raise ValueError("Docker bridge properties differ from sealed network")
    endpoints = controller.get("NetworkSettings", {}).get("Networks", {})
    selected = [value for value in endpoints.values() if value.get("NetworkID") == packet["network_id"]]
    if len(selected) != 1:
        raise ValueError("Docker controller is not attached to selected bridge")
    require_bridge_endpoint(selected[0], packet, network["controller_ipv4"])


def worker_network_endpoint(actual: dict, packet: dict) -> dict:
    network = packet["network"]
    host = actual.get("HostConfig", {})
    settings = actual.get("NetworkSettings", {})
    endpoints = settings.get("Networks", {})
    if (host.get("Dns") != network["dns"] or host.get("DnsOptions") or host.get("DnsSearch") or
            host.get("Sysctls") != {"net.ipv6.conf.all.disable_ipv6": "1"} or len(endpoints) != 1 or
            settings.get("LinkLocalIPv6Address") or settings.get("LinkLocalIPv6PrefixLen")):
        raise ValueError("Docker worker DNS, IPv6 or network membership differs from sealed intent")
    return next(iter(endpoints.values()))


def require_worker_network(actual: dict, packet: dict) -> None:
    if 'network' in packet:
        require_bridge_endpoint(worker_network_endpoint(actual, packet), packet, packet['network']['worker_ipv4'])


def require_stopped_parent_state(actual: dict) -> None:
    state = actual.get('State', {})
    if (state.get('Running') is not False or type(state.get('Pid')) is not int or state['Pid'] != 0 or
            state.get('Paused') is not False or state.get('Restarting') is not False or state.get('OOMKilled') is not False or
            state.get('Error') != '' or type(actual.get('RestartCount')) is not int or actual['RestartCount'] != 0):
        raise ValueError('Docker review parent implementation is not successfully stopped')


def require_stopped_worker_network(actual: dict, packet: dict) -> None:
    """Static bridge intent survives normal removal of dead endpoint addresses."""
    require_stopped_parent_state(actual)
    if 'network' not in packet:
        return
    endpoint = worker_network_endpoint(actual, packet)
    ipam = endpoint.get('IPAMConfig') or {}
    if (endpoint.get('NetworkID') != packet['network_id'] or ipam.get('IPv4Address') != packet['network']['worker_ipv4'] or
            ipam.get('IPv6Address') or ipam.get('LinkLocalIPs')):
        raise ValueError('Docker stopped parent static endpoint differs from sealed intent')
    if endpoint.get('IPAddress') == packet['network']['worker_ipv4']:
        require_bridge_endpoint(endpoint, packet, packet['network']['worker_ipv4'])
        return
    if (any(endpoint.get(key) != '' for key in ('IPAddress','Gateway','MacAddress','EndpointID','GlobalIPv6Address','IPv6Gateway')) or
            any(type(endpoint.get(key)) is not int or endpoint.get(key) != 0 for key in ('IPPrefixLen','GlobalIPv6PrefixLen'))):
        raise ValueError('Docker stopped parent operational endpoint is not lifecycle-cleared')


def validate_created_worker(engine, packet: dict, container_id: str, launch_digest: str, *, stopped_parent: bool = False) -> dict:
    actual = engine.request("GET", f"/containers/{container_id}/json")
    host = actual.get("HostConfig", {})
    config = actual.get("Config", {})
    limits = packet["limits"]
    require_worker_identity(actual, container_id, launch_digest)
    if stopped_parent:
        require_stopped_parent_state(actual)
    if (actual.get("Image") != packet["image_id"] or
            actual.get("Name") != "/" + packet["container_name"] or
            config.get("User") != packet["user"] or
            config.get("Volumes") or host.get("ReadonlyRootfs") is not True or host.get("Privileged") is not False or
            host.get("CapAdd") or set(host.get("CapDrop") or []) != {"ALL"} or
            set(host.get("SecurityOpt") or []) != {"no-new-privileges:true"} or
            host.get("PidMode") or host.get("IpcMode") not in {"private", ""} or
            host.get("NetworkMode") != packet["network_id"] or host.get("Devices") or host.get("DeviceRequests") or
            host.get("PortBindings") or host.get("PublishAllPorts") or host.get("ExtraHosts") or
            host.get("LogConfig", {}).get("Type") != "none" or host.get("RestartPolicy", {}).get("Name") != "no" or
            host.get("Memory") != limits["memory_bytes"] or host.get("MemorySwap") != limits["swap_bytes"] or
            host.get("NanoCpus") != limits["cpu_nano"] or host.get("PidsLimit") != limits["pids"] or
            host.get("Tmpfs") != packet.get("tmpfs")):
        raise ValueError("Docker created result differs from admitted security/resource intent")
    expected = {(item["source"], item["target"], item["read_only"]) for item in packet["mounts"]}
    observed = {(item.get("Source"), item.get("Destination"), not item.get("RW")) for item in actual.get("Mounts", []) if item.get("Type") == "bind"}
    if expected != observed or any(item.get("Type") not in {"bind", "tmpfs"} for item in actual.get("Mounts", [])):
        raise ValueError("Docker created mounts differ from admitted mounts")
    if any(item.get("Destination") not in packet["tmpfs"] for item in actual.get("Mounts", []) if item.get("Type") == "tmpfs"):
        raise ValueError("Docker created an unbounded temporary mount")
    if stopped_parent:
        require_stopped_worker_network(actual, packet)
    else:
        require_worker_network(actual, packet)
    if "network" in packet:
        controller = engine.request("GET", f"/containers/{packet['controller_container_id']}/json")
        if controller.get("Id") != packet["controller_container_id"] or controller.get("State", {}).get("Running") is not True:
            raise ValueError("Docker controller identity is unavailable")
        require_selected_bridge(engine, packet, controller)
    return actual


def verify_stopped_parent(engine, packet: dict, custody: DockerCustody) -> None:
    if engine.request('GET', '/info').get('ID') != custody.daemon_id:
        raise ValueError('Docker review parent daemon changed')
    validate_created_worker(engine, packet, custody.container_id, custody.launch_sha256, stopped_parent=True)
    provider = engine.request('GET', '/exec/' + custody.provider_exec_id + '/json')
    if (provider.get('ID') != custody.provider_exec_id or provider.get('ContainerID') != custody.container_id or
            provider.get('Running') is not False or type(provider.get('ExitCode')) is not int or provider['ExitCode'] != 0):
        raise ValueError('Docker review parent implementation is not successfully stopped')
