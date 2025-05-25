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

## Host OS Considerations

### Docker Desktop for Mac

When running on macOS using Docker Desktop, some escape techniques may not work as expected because:

- Containers run in a lightweight VM (hyperkit) rather than directly on the host
- Host filesystem access is mediated through a special filesystem layer (osxfs/gRPC-FUSE)
- The actual host is macOS, not Linux
- Some Linux-specific escape vectors are not applicable

Specifically affected escape types:

- **Mount Escapes**: Limited by Docker's macOS filesystem integration
- **Kernel Exploits**: Target the VM's kernel, not the macOS host
- **Device Node Escapes**: Limited by VM isolation
- **Shared Namespace Escapes**: Namespace isolation is VM-level

For testing Linux container escapes, it's recommended to use:

- A native Linux host
- A Linux VM
- A cloud-based Linux environment

## Escape Types

### Mount Escape

- **What is it?**
  - Exploits the ability to remount host filesystem volumes
  - Can occur when container has access to host filesystem, even in read-only mode
  - Often combined with privileged mode or specific capabilities
- **Prerequisites**:
  - Container running as root
  - Privileged container or `cap_sys_admin` Linux capability
  - Host filesystem mounted (even read-only)
- **Impact**:
  - Direct access to host filesystem
  - Can modify host files and configurations
  - Can access host secrets and credentials
  - Can modify host system binaries
  - Can persist access by modifying host files
  - Can access sensitive data from other containers
- **Mitigation**:
  - Don't run containers as root
  - Don't use privileged mode
  - Mount only necessary volumes
  - Use read-only mounts where possible
  - Implement volume access controls
  - Use SELinux/AppArmor to restrict mount operations

### Capability-based Escapes

- **What is it?**
  - Exploits Linux capabilities granted to containers
  - Capabilities are granular permissions that can be granted to processes
  - Some capabilities can be used to break out of container isolation
- **Prerequisites**:
  - Container running as root
  - Dangerous capabilities like:
    - `cap_dac_override` (bypass file permissions)
    - `cap_net_raw` (raw network access)
    - `cap_sys_chroot` (change root directory)
    - `cap_mknod` (create device nodes)
    - `cap_sys_admin` (mount filesystems)
    - `cap_sys_ptrace` (debug other processes)
- **Impact**:
  - Can mount new filesystems
  - Can create device nodes
  - Can modify network settings
  - Can bypass file permissions
  - Can debug host processes
  - Can modify kernel parameters
  - Can access hardware devices
- **Mitigation**:
  - Drop unnecessary capabilities
  - Use principle of least privilege
  - Run as non-root user
  - Implement capability bounding sets
  - Use security profiles to restrict capabilities

### Shared Namespace Escapes

#### PID Namespace Escape

- **What is it?**
  - Exploits shared process namespace between container and host
  - PID namespace normally isolates process trees
  - When shared, container can see and interact with host processes
- **Prerequisites**:
  - Container running as root
  - Shared PID namespace with host (`--pid=host`)
- **Impact**:
  - Can see and interact with host processes
  - Can send signals to host processes
  - Can access host process memory
  - Can use host process capabilities
  - Can debug host processes
  - Can potentially inject code into host processes
  - Can access sensitive information from host processes
- **Mitigation**:
  - Use separate PID namespace
  - Don't share PID namespace with host
  - Run as non-root user
  - Implement process isolation policies

#### Network Namespace Escape

- **What is it?**
  - Exploits shared network namespace between container and host
  - Network namespace normally isolates network interfaces
  - When shared, container has full access to host network stack
- **Prerequisites**:
  - Container running as root
  - Shared network namespace with host (`--network=host`)
- **Impact**:
  - Can see and interact with host network interfaces
  - Can sniff host network traffic
  - Can modify host network settings
  - Can bypass network isolation
  - Can access host network services
  - Can perform network-based attacks
  - Can bypass network security controls
- **Mitigation**:
  - Use separate network namespace
  - Don't share network namespace with host
  - Use network policies
  - Run as non-root user
  - Implement network isolation

#### IPC Namespace Escape

- **What is it?**
  - Exploits shared IPC (Inter-Process Communication) namespace
  - IPC namespace normally isolates shared memory, semaphores, and message queues
  - When shared, container can communicate with host processes
- **Prerequisites**:
  - Container running as root
  - Shared IPC namespace with host (`--ipc=host`)
- **Impact**:
  - Can access host shared memory
  - Can interact with host semaphores
  - Can communicate with host processes via IPC
  - Can potentially access sensitive data
  - Can interfere with host process communication
  - Can potentially cause host process crashes
- **Mitigation**:
  - Use separate IPC namespace
  - Don't share IPC namespace with host
  - Run as non-root user
  - Implement IPC isolation policies

#### UTS (Unix Time-sharing System) Namespace Escape

- **What is it?**
  - Exploits shared UTS namespace between container and host
  - UTS namespace isolates two system identifiers:
    - Hostname (`uname -n` or `hostname`)
    - NIS (Network Information Service) domain name (`domainname`)
  - These identifiers are used by various system services and applications
- **Prerequisites**:
  - Container running as root
  - Shared UTS namespace with host (`--uts=host`)
- **Impact**:
  - Can modify host's hostname
  - Can change host's NIS domain name
  - Can affect services that rely on hostname (e.g., mail servers, web servers)
  - Can confuse monitoring and logging systems
  - Can potentially trigger hostname-based security mechanisms
- **Mitigation**:
  - Use separate UTS namespace
  - Don't share UTS namespace with host
  - Run as non-root user
  - Configure services to not rely on hostname for security decisions

### Docker Socket Access

- **What is it?**
  - Exploits access to Docker daemon socket
  - Docker socket (`/var/run/docker.sock`) provides API access to Docker daemon
  - When mounted in container, allows container to control Docker daemon
- **Prerequisites**:
  - Container running as root
  - Docker socket mounted (`/var/run/docker.sock`)
- **Impact**:
  - Can create new containers
  - Can access host Docker daemon
  - Can mount host filesystem
  - Can create privileged containers
  - Can access other containers
  - Can modify Docker daemon settings
  - Can potentially access host resources through new containers
- **Mitigation**:
  - Don't mount Docker socket
  - Use Docker API with proper authentication
  - Run as non-root user
  - Implement Docker daemon access controls
  - Use Docker API tokens with limited permissions

### Cgroup Escapes

- **What is it?**
  - Exploits vulnerabilities in cgroup (control group) implementation
  - Cgroups are used to limit and monitor resource usage
  - Some cgroup configurations can be exploited to escape container
- **Prerequisites**:
  - Container running as root
  - Access to `/sys/fs/cgroup`
  - Vulnerable cgroup configuration
- **Impact**:
  - Can modify cgroup settings
  - Can affect host resource allocation
  - Can potentially escape container
  - Can cause host resource exhaustion
  - Can bypass resource limits
  - Can potentially access host resources
- **Mitigation**:
  - Restrict cgroup access
  - Use cgroup v2
  - Run as non-root user
  - Implement cgroup access controls
  - Keep cgroup implementation updated

### Kernel Exploits

- **What is it?**
  - Exploits vulnerabilities in the Linux kernel
  - Kernel is shared between container and host
  - Successful exploit can bypass container isolation
- **Prerequisites**:
  - Container running as root
  - Vulnerable kernel version
  - Access to `/proc` and `/sys`
- **Impact**:
  - Full host system compromise
  - Can bypass container isolation
  - Can access host resources
  - Can modify kernel parameters
  - Can install kernel modules
  - Can potentially persist access
- **Mitigation**:
  - Keep kernel updated
  - Use container-specific kernels
  - Restrict access to `/proc` and `/sys`
  - Run as non-root user
  - Implement kernel hardening
  - Use security modules (SELinux/AppArmor)

## General Mitigation Strategies

1. **Principle of Least Privilege**:

   - Run containers as non-root users
   - Drop unnecessary capabilities
   - Mount only required volumes
   - Use read-only mounts where possible
   - Use separate namespaces for each container
   - Implement strict access controls

2. **Container Hardening**:

   - Keep container images updated
   - Use minimal base images
   - Remove unnecessary tools
   - Implement security profiles (AppArmor/SELinux)
   - Scan images for vulnerabilities
   - Use signed images

3. **Host Protection**:

   - Keep host kernel updated
   - Use container-specific kernels
   - Implement network policies
   - Monitor container behavior
   - Use host-based security tools
   - Implement host hardening

4. **Runtime Security**:
   - Use container runtime security tools
   - Implement runtime policies
   - Monitor for suspicious activity
   - Regular security audits
   - Implement logging and alerting
   - Use runtime security profiles
