# NAME

gopass-ssh-add - Use "gopass" as storage for ssh keys

# SYNOPSIS

gopass-ssh-add

```
[--help|-h]
[--quiet|-q|--silent]
[--store]=[value]
[--version|-v]
[--yes|-y]
```

# DESCRIPTION

This command allows you to generate ssh keys, save it to gopass store and add it to ssh-agent.

**Usage**:

```
gopass-ssh-add [GLOBAL OPTIONS] command [COMMAND OPTIONS] [ARGUMENTS...]
```

# GLOBAL OPTIONS

**--help, -h**: show help

**--quiet, -q, --silent**: do not write logs to stdout

**--store**="": first part of path to find the secret (default: ssh-keys)

**--version, -v**: print the version

**--yes, -y**: answer yes to all confirmations


# COMMANDS

## agent

manage ssh-agent

### add

add ssh-key to ssh-agent

    Add ssh-key to agent forever:
    `gopass-ssh-add --store=ssh-keys agent add path/to/ssh/key`
    
    Add ssh-key to agent for 5 minutes:
    `gopass-ssh-add --store=ssh-keys agent add --time=300 path/to/ssh/key`

**--lifetime, --time, -t**="": set a maximum lifetime when adding identities to an agent. (default: 0)

### delete, remove, del, rm

delete ssh-key from ssh-agent

>`gopass-ssh-add --store=ssh-keys agent delete path/to/ssh/key`

### list, ls

show keys list in ssh-agent

>`gopass-ssh-add --store=ssh-keys agent list`

### clear

delete all keys from ssh agent

>`gopass-ssh-add --store=ssh-keys agent clear`

## secret

manage ssh-key secrets in gopass

### delete, remove, del, rm

delete secret from gopass storage

>`gopass-ssh-add --store=ssh-keys secret delete path/to/ssh/key`

### generate, keygen, gen, ssh-keygen

generate password, run ssh-keygen save it to gopass storage

>`gopass-ssh-add --store=ssh-keys secret generate path/to/ssh/key`

**--bits, --bit, -b**="": Ssh key bits (default: 4096)

**--comment, -C**="": Ssh key comment

**--length, -l**="": Password length (default: 32)

**--symbols, -s**: Add symbols to password

**--type, -t**="": Ssh key type (default: ed25519)

### password, pass, passwd

manage ssh-key password

#### show

show ssh-key password

    `gopass-ssh-add --store=ssh-keys secret password show path/to/ssh/key/secret` # show ssh-key password
    
    `gopass-ssh-add --store=ssh-keys secret password show -c path/to/ssh/key/secret` # copy ssh-key password to clipboard

**--clipboard, --clip, --copy, -c**: Copy content to clipboard

#### delete, remove, del, rm

delete ssh-key password

>`gopass-ssh-add --store=ssh-keys secret password delete path/to/ssh/key/secret`

#### generate, gen, random, rand

generate ssh-key password

>`gopass-ssh-add --store=ssh-keys secret password generate -l=32 -s path/to/ssh/key/secret`

**--length, -l**="": Password length (default: 32)

**--symbols, -s**: Add symbols to password

#### insert, import

insert ssh-key password from stdin

>`echo "some-password" | gopass-ssh-add --store=ssh-keys secret password insert path/to/ssh/key/secret`

### key, ssh-key

manage ssh-key in secret

#### delete, remove, del, rm

delete ssh-key (private and public) from secret

>`gopass-ssh-add --store=ssh-keys secret key delete path/to/ssh/key/secret`

#### private

manage private ssh-key section

##### insert, import

insert private ssh-key from stdin

>`cat ./private/ssh-key/path | gopass-ssh-add --store=ssh-keys secret key private insert path/to/ssh/key/secret`

##### show

show private ssh-key

>`gopass-ssh-add --store=ssh-keys secret key private show path/to/ssh/key/secret`

**--clipboard, --clip, --copy, -c**: Copy content to clipboard

##### delete, remove, del, rm

delete private ssh-key

>`gopass-ssh-add --store=ssh-keys secret key private delete path/to/ssh/key/secret`

#### public

manage public ssh-key section

##### insert, import

insert public ssh-key from stdin

>`cat ./public/ssh-key/path | gopass-ssh-add --store=ssh-keys secret key public insert path/to/ssh/key/secret`

##### show

show public ssh-key

>`gopass-ssh-add --store=ssh-keys secret key public show path/to/ssh/key/secret`

**--clipboard, --clip, --copy, -c**: Copy content to clipboard

##### delete, remove, del, rm

delete public ssh-key

>`gopass-ssh-add --store=ssh-keys secret key public delete path/to/ssh/key/secret`

## version


## help, h

Shows a list of commands or help for one command
