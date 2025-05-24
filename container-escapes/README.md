# Container Escape PoC

This PoC explores and demonstrates container escapes in different environments.

## Environments

### Docker

Vanilla Docker and Docker Compose files live in `./docker`. There is a `Makefile` for
simplifying build and deployment.

```sh
make build
make run-default    # Run as root
make run-user       # Run as regular user
make run-privileged # Run privileged container as root
```

## Escape Types

### Mount Escape

- **Prerequisites**:
  - Container running as root
  - Privileged container or `cap_sys_admin` Linux capability
  - Host filesystem mounted (even read-only)
- **Impact**:
  - Direct access to host filesystem
  - Can modify host files
  - Can access host secrets
- **Mitigation**:
  - Don't run containers as root
  - Don't use privileged mode
  - Mount only necessary volumes
  - Use read-only mounts where possible

### Capability-based Escapes

- **Prerequisites**:
  - Container running as root
  - Dangerous capabilities like:
    - `cap_dac_override` (bypass file permissions)
    - `cap_net_raw` (raw network access)
    - `cap_sys_chroot` (change root directory)
    - `cap_mknod` (create device nodes)
  - Note: Shared namespaces (PID, NET, IPC) can amplify the impact of these capabilities
- **Impact**:
  - Can mount new filesystems
  - Can create device nodes
  - Can modify network settings
  - Can bypass file permissions
  - With shared namespaces: can see and interact with host processes
- **Mitigation**:
  - Drop unnecessary capabilities
  - Use principle of least privilege
  - Run as non-root user
  - Use separate namespaces for each container

### Shared Namespace Escapes

#### PID Namespace Escape

- **Prerequisites**:
  - Container running as root
  - Shared PID namespace with host (`--pid=host`)
- **Impact**:
  - Can see and interact with host processes
  - Can send signals to host processes
  - Can access host process memory
  - Can use host process capabilities
- **Mitigation**:
  - Use separate PID namespace
  - Don't share PID namespace with host
  - Run as non-root user

#### Network Namespace Escape

- **Prerequisites**:
  - Container running as root
  - Shared network namespace with host (`--network=host`)
- **Impact**:
  - Can see and interact with host network interfaces
  - Can sniff host network traffic
  - Can modify host network settings
  - Can bypass network isolation
- **Mitigation**:
  - Use separate network namespace
  - Don't share network namespace with host
  - Use network policies
  - Run as non-root user

#### IPC Namespace Escape

- **Prerequisites**:
  - Container running as root
  - Shared IPC namespace with host (`--ipc=host`)
- **Impact**:
  - Can access host shared memory
  - Can interact with host semaphores
  - Can communicate with host processes via IPC
  - Can potentially access sensitive data
- **Mitigation**:
  - Use separate IPC namespace
  - Don't share IPC namespace with host
  - Run as non-root user

#### UTS Namespace Escape

- **Prerequisites**:
  - Container running as root
  - Shared UTS namespace with host (`--uts=host`)
- **Impact**:
  - Can modify host hostname
  - Can affect hostname-dependent services
  - Can potentially confuse monitoring tools
- **Mitigation**:
  - Use separate UTS namespace
  - Don't share UTS namespace with host
  - Run as non-root user

### Docker Socket Access

- **Prerequisites**:
  - Container running as root
  - Docker socket mounted (`/var/run/docker.sock`)
- **Impact**:
  - Can create new containers
  - Can access host Docker daemon
  - Can mount host filesystem
- **Mitigation**:
  - Don't mount Docker socket
  - Use Docker API with proper authentication
  - Run as non-root user

### Cgroup Escapes

- **Prerequisites**:
  - Container running as root
  - Access to `/sys/fs/cgroup`
  - Vulnerable cgroup configuration
- **Impact**:
  - Can modify cgroup settings
  - Can affect host resource allocation
  - Can potentially escape container
- **Mitigation**:
  - Restrict cgroup access
  - Use cgroup v2
  - Run as non-root user

### Kernel Exploits

- **Prerequisites**:
  - Container running as root
  - Vulnerable kernel version
  - Access to `/proc` and `/sys`
  - Note: Shared namespaces can provide additional attack surface
- **Impact**:
  - Full host system compromise
  - Can bypass container isolation
  - Can access host resources
- **Mitigation**:
  - Keep kernel updated
  - Use container-specific kernels
  - Restrict access to `/proc` and `/sys`
  - Run as non-root user
  - Use separate namespaces

## General Mitigation Strategies

1. **Principle of Least Privilege**:

   - Run containers as non-root users
   - Drop unnecessary capabilities
   - Mount only required volumes
   - Use read-only mounts where possible
   - Use separate namespaces for each container

2. **Container Hardening**:

   - Keep container images updated
   - Use minimal base images
   - Remove unnecessary tools
   - Implement security profiles (AppArmor/SELinux)

3. **Host Protection**:

   - Keep host kernel updated
   - Use container-specific kernels
   - Implement network policies
   - Monitor container behavior

4. **Runtime Security**:
   - Use container runtime security tools
   - Implement runtime policies
   - Monitor for suspicious activity
   - Regular security audits
