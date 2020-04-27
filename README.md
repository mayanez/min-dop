Minimal Data-Oriented Programming (DOP) Vulnerable Server + Exploits
-------------------------------------------------------------

![GitHub](https://img.shields.io/github/license/mayanez/min-dop)
![GitHub last commit](https://img.shields.io/github/last-commit/mayanez/min-dop)
![Twitter Follow](https://img.shields.io/twitter/follow/miguelaarroyo12?style=social)

## Description

This code is used to demonstrate [Data-Oriented Programming (DOP)](https://huhong-nus.github.io/advanced-DOP/) attacks first described by [Hu et al](https://huhong-nus.github.io/advanced-DOP/papers/dop.pdf).

This example code provides a vulnerable server program with:
* Memory WRITE safety violation vulnerability
* Memory READ safety violation vulnerability
* Turing-complete DOP gadgets

It's primary purpose is to serve as an education tool for DOP.

## Docker Container

The project includes a Docker environment that contains all the dependencies necessary.
Please refer to the `Dockerfile` for the appropriate packages.

The simplest way to use this project is with the provided container.

### Setup

Launching the docker container can be done as follows.

```
$ cd min-dop
$ export REPO_PATH=$(pwd)
$ docker-compose up
```
The `REPO_PATH` env varaible is necessary in order to mount the current repository in the container.

From another terminal you will want to run the following commands in order to use the container:

```
$ docker exec -it min-dop-runner /bin/bash
```

You may run the above command as many times as you need in different terminals in order to open multiple sessions into the container.
For instance, you may want to use two for this project: (a) one for the server and (b) one for the exploit.

## Build

### Vulnerable Server

To build the `vuln_srv`:
```
$ make
```

## Run

Please use the Docker container as described above.

### Vulnerable Server

The main server executable is `vuln_srv`. It can be launched with the following command.

```
$ ./vuln_srv 1111
```

The server takes commands in the following format:
```
[TYPE][SIZE]
    uint32_t TYPE
    uint32_t SIZE
```
For details on the supported values for `TYPE` refer to `vuln_srv.c`.

##### Python Interface
To ease interfacing with the `vuln_srv` from the Python code which is used for exploit a `vuln_srv.py`
is provided.

### Exploits
The exploits are contained in `exploit.py` which provides an interface to DOP gadgets for simplicity.

A `exploit_runner.py` is provided to launch the appropriate exploits.

```
$ python ./exploit_runner.py --help
```

The preferred method for running the exploits is using the `--gdb` flag. This launches the program inside of GDB's Python environment. This makes it so that it can compute the offsets of relevant variables automatically so the exploits work reliably if you'd like to modify the code. 

## Code Coverage

For debugging purposes, this project supports reporting of code coverage metrics.
Two tools are used:
* `gcov` (included with `GCC`)
* `gcovr` http://gcovr.com/

To build the `vuln_srv` with code coverage metrics run:

```
$ make -DCODE_COVERAGE=1
```

To generate an HTML report for example consider the following command:

```
$ gcovr -r . --html --html-details -o coverage.html
```

## Vulnerabilities

### Out-of-bounds Read Vulnerability
```
//
// This function wrongly uses the signed version of `type` and has an integer
// underflow vulnerability.
// Vulnerable to an out-of-bounds read memory safety bug.
//
int checkForInvalidTypes(int type, int clientfd) {
{
  ...
  if (type <= 2) {
    err_no = LUT_ERROR_CODES[type];
  ...
}
```

#### Arbitrary memory read
To exploit the memory read vulnerability, we supply a negative value to the
`TYPE` option. Notice that the content of the memory address (controllable
offset from `LUT_ERROR_CODES`) is returned as the error code.

This is a powerful primitive, since we can now reveal the secret at `SECRET` at
offset `-9`. That's not all. If ASLR is enabled, we will need to know the base
of the program to figure out addresses using offset. We can reveal the base
address of the program by reveal the global variable `g_srv.p_g_a` which points
to `&g_a`.

### Out-of-bounds Write Vulnerability
```
//
// This function assumes that input buffer (`buf`) is RECV_MAX_LEN long.
// Vulnerable to an out-of-bounds write memory safety bug.
//
int readInData(int clientfd, char *buf)
{
  ...
  recv_len = recv(clientfd, buffer, RECV_MAX_LEN, 0);
  ...
  memcpy(buf, buffer, recv_len);
  ...
}
```

#### Arbitrary memory write
We can exploit the memory write vulnerability by supplying a request of length longer than 8 bytes. This allows us to control all the local stack variables `p_srv`, `p_size`, `p_type` and `connect_limit`.

## Exploits

### Privilege escalation
We use the above arbitrary memory read and write vulnerabilities together to perform an illegal privilege escalation.

We stitch the DOP gadgets to perform the following DOP "implicit" program.
```
int *base = &g_a
((g_struct_t *)(base - offset_v_2))->v_2 = *(&buf[4])
```

### Secret Leak / Exfiltrate
We stitch the DOP gadgets to perform the following DOP "implicit" program.
```
int *base = &g_a
*(&g_a) = **((g_struct_t *)(base + rel_addr_SECRET - offset_pp_b)->pp_b)
print(g_a)
```

### Gadget Chains
It is likely that many real-world scenarios require a significant amount of DOP
gadgets to perform useful work. There are two options we implement to simulate
the increased memory footprint of real-world attacks.

##### Links
This option performs a load, increment, store loop as shown in the following:
```
*(&g_scratch_buf[i]) = **(g_pp_g_a);
*(&g_scratch_buf[i]) += 1;
**(g_pp_g_a) = *(&g_scratch_buf[i]);
```
This creates essentially creates links between memory addresses and instructions that would not appear under normal execution.

##### Ops
This option performs an increment on a single memory address as follows:
```
*(&g_a) += 1
```

## Contributions

This started mainly an educational exercise for myself. Any contributions are welcome to improve the documentation, code, or add additional features. Please open up an `issue` or `pull-request`. 
