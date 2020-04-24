Minimal Data-Oriented Programming Vulnerable Server + Exploits
-------------------------------------------------------------

## Description
This example code is to demonstrate a vulnerable server program with:
* Memory WRITE safety violation vulnerability
* Memory READ safety violation vulnerability
* Turing-complete DOP gadgets

## Prerequisites

* Python 3+
* pip
* GDB with Python support

#### Python Dependencies
```
pip install docopt
```

## Build

To disable/enable ASLR:
```
# disable
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# enable
$ echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

To build the `vuln_srv`:
```
$ make
```

To build with code coverage metrics run:
```
make -DCODE_COVERAGE=1
```

## Run

### vuln_srv
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

### vuln_srv_runner.py

```
$ python runner.py --help
```

### exploit_runner.py

### Code Coverage

To process code coverage analysis two tools are used:
* `gcov` (included with `GCC`)
* `gcovr` http://gcovr.com/

To generate an HTML report for example consider the following command:
```
gcovr -r . --html --html-details -o coverage.html
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

We will try offset `-1`. This will give us the memory content of global variable `TYPE_MAX`.
```
$ echo 'ffffffff00000000' | xxd -r -p | nc -v 127.0.0.1 1111
```

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

On the client, we will send the exploit request as follows:
```
$ echo --------AAAABBBBCCCCDDDD | nc -v 127.0.0.1 1111
```

On the server, this will crash the program because the memory addresses we supplied in the exploit request cannot be dereferenced. Notice that the value of all the stack variables have been overwritten by our values.

## Exploits

### Privilege escalation
We use the above arbitrary memory read and write vulnerability together to perform an illegal privilege escalation.

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
