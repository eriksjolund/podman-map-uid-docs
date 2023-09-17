# podman-map-uid-docs

Documenation of how to map UIDs and GIDs with Podman

## Trace which UIDs and GIDs are used in a container with EBPF

The [documentation](https://hub.docker.com/_/nginx) for the
container image _docker.io/library/nginx_ mentions that the container
drops privileges for the worker processes to a user with UID 101 and GID 101. 

Conclusions that can be made from that information:

* The container needs to start running as root so that it has enough permissions to drop permissions. (`--user 0:0`)
* To let the nginx worker processes create files on the host that are owned by the regular user on the host, add `--userns keep-id:uid=101,gid=101`. 

When using container images that drop privileges but where no detailed documentaion is available,
use these debugging techniques to find out information about the container image:

* Let the bind-mounted directory have permissive permissions (`chmod 777 dir`). After the container has run check which file permissions a newly create file has. See example in [Podman troubleshooting tip](https://github.com/containers/podman/blob/main/troubleshooting.md#34-container-creates-a-file-that-is-not-owned-by-the-users-regular-uid).
* Trace the use of UIDs and GIDs with the Linux kernel feature [EBPF](https://ebpf.io).

### Example: trace open system calls in an Nginx container with Inspector Gadget

Inspector Gadget (https://www.inspektor-gadget.io) is an eBPF tool and systems inspection framework.

The container image _ghcr.io/inspektor-gadget/ig_ needs to be run with `sudo podman run --privileged ...` 
The container process has full access to the host which means that you need to trust that the container
does not do anything harmful to your system. For security reasons you might want to perform this example
in a Linux VM, for example [Fedora CoreOS](https://fedoraproject.org/coreos/download/?stream=stable) that has Podman pre-installed.

1. Open two bash terminals in the VM.
2. In terminal 1 run
   ```
   sudo podman run -d --rm --name nginxtest -p 127.0.0.1:8080:80 docker.io/library/nginx
   ```
3. In terminal 1 run
   ```
   sudo systemctl start podman.socket
   ```
4. In terminal 1 set the shell variable `dir` to the container directory for which open system calls should be traced
   ```
   dir=/usr/share/nginx/html
   ```
   (The shell variable name `dir` was arbitrarily chosen. The variable is used to make this tutorial easier to understand)
5. In terminal 1 start the Inspector Gadget container
   ```
   sudo podman run \
     -ti \
     --rm \
     --privileged \
     -v /run:/run \
     -v /:/host \
     -v /sys/kernel/debug:/sys/kernel/debug \
     -v /sys/kernel/tracing:/sys/kernel/tracing \
     -v /sys/fs/bpf:/sys/fs/bpf \
     -v /run/podman/podman.sock:/run/podman/podman.sock \
     ghcr.io/inspektor-gadget/ig \
       trace open \
         --containername nginxtest \
         --filter "fullPath:~$dir/.*" \
         --runtimes podman \
         --full-path \
         --output columns=uid,gid,fullPath
   ```
   An error message is printed in terminal 1
   ```
   ERRO[0000] cgroup enricher: failed to get cgroup paths on container 675597c2e3fc24ab3d20a1203212de58c09ab148b609b2bc32264e636235689d: cgroup path not found in /proc/PID/cgroup
   ```
   (TODO: investigate why the error message is shown)
6. In terminal 2 run
   ```
   curl 127.0.0.1:8080
   ```
   The following text is printed to terminal 1
   ```
   UID        GID        FULLPATH                                                                                                                                                                                
   101        101        /usr/share/nginx/html/index.html
   ```


__Side node 1__: In this example a regular expression was specified with `--filter` to filter out only `open()` system calls for paths beginning with _/usr/share/nginx/html_


The `--help` option provides information about how to specify a regular expression with the `--filter` option:

```
$ podman run --rm ghcr.io/inspektor-gadget/ig trace open --help | grep -A1 regular
                                   columnName:~value      - matches, if the content of columnName matches the regular expression 'value'
                                                            see [https://github.com/google/re2/wiki/Syntax] for more information on the syntax
```

For more details about the regular expression syntax, see https://github.com/google/re2/wiki/Syntax

__Side node 2__: To see only which UID/GID that are used, replace the end of the command

```
--output columns=uid,gid,fullPath 
```
with
```
--output columns=uid,gid | sort -u
```
