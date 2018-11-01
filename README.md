# SHHHH, THIS PROJECT HASN'T OFFICIALLY LAUNCHED YET AND THIS REPO IS SUPER SECRET!!!

# Step Certificates

An online certificate authority and related tools for secure automated
certificate management, so you can use TLS everywhere.

For more information and docs see [the step website](https://smallstep.com/cli/)
and the [blog post](https://smallstep.com/blog/zero-trust-swiss-army-knife.html)
announcing step.

### Table of Contents

- [Installing](#installing)
- [Documentation](#documentation)
- [Examples](#examples)
- [Getting Started](#getting-started)
- [Versioning](#versioning)
- [LICENSE](./LICENSE)
- [CHANGELOG](./CHANGELOG.md)

## Installing

Smallstep Certificates is a module of the Step CLI toolchain.
Installation instructions for the [Step CLI](#https://github.com/smallstep/cli)
can be found [here](#https://github.com/smallstep/cli/README.md#installing).

## Documentation

Documentation can be found in three places:

1. On the command line with `step ca help xxx` where `xxx` is the subcommand you are interested in. Ex: `step help crypto jwk`

2. On the web at https://smallstep.com/docs/cli

3. In your browser with `step ca help --http :8080` and visiting http://localhost:8080

## Getting Started

The first step in deploying an automated and integrated certificate solution
is to generate a root of trust.

** Why Step Online CA and what are provisioners **

### PKI

** what is a PKI **

** What are we creating **

```
step ca init
```

** What files were created**

** run the CA! **

```
step ca --ca-config ./.step/ca.json
```

## Examples

### Request A Certificate From the CLI

** Create a new certificate from the command line **

```
step ca certificate --ca-url 127.0.0.1
```

** inspect the certificate **
```
step certificate inspect
```

### Renew A Certificate From the CLI

```
step ca renew  ...
```

```
step certificate inspect
```

### Add A Provisioner

```
step ca provisioner add ...
```

```
step ca certificate --ca-url ...
```

### How to use the Golang client


## License

This project is licensed under the MIT License - see the
[LICENSE](./LICENSE) file for details
>>>>>>> Stashed changes
