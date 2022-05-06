# Basic Server

This example shows a fairly simple form of authorization using Biscuits. Let's start by creating a "policy" that we load into the server on startup.

## Setup

Create a folder called `assets` in this example directory. That's where the server will look for all the authorization info.

```
$ mkdir -p assets
```

Create a file `assets/policy.txt` with the following contents:

```prolog
admin("alice");
admin("bob");
allow if user($username), admin($username);
```

This policy starts with two *facts*. We can read this as "`alice` and `bob` are both `admin`s."

The last line is what the Biscuit standard actually calls a *policy*. It's an action to be taken if all the contained patterns match.

By default, with no token, this policy will not "match" because there are no `user` facts found to match that pattern. Note also that because the `$username` variable is the same identifier in both the `user` and `admin` pieces of the policy's pattern, they must be the same value for the policy to match.

That is, `user("alice"), admin("bob")` would not succeed. There must be a pattern `user("alice"), admin("alice")` for the policy to match.

So, in order to make it past an endpoint protected by this authorization policy, the bearer token (the "biscuit") must contain the complementary piece of the pattern: in this case, the fact containing the username.

Finally, we'll need to create a private/public key pair. The private key will be used to create biscuits, and the public key will be given to the user to verify the biscuits. Note that the server is configured only with public information, which is a pretty cool property of biscuits.

Install the Rust `biscuit-cli` app using the [offical instructions][install], and then execute the following commands.

```
$ biscuit keypair --only-private-key > assets/private.key
$ biscuit keypair --only-public-key --from-private-key-file assets/private.key > assets/public.key
```

## Usage

Start the example server with:

```
cargo run --example basic_server
```

We're going to use `curl` to test authorization. There are two endpoints in this server: `/` and `/admin/:name`. The example binds to `127.0.0.1:3000`, so try the following two requests:

```
$ curl 127.0.0.1:3000/
Hello, world!
```

If that succeeds, the server is at least running. Now let's try the endpoint requiring authentication.

```
$ curl 127.0.0.1:3000/admin/alice
other error: couldn't find biscuit header
```

So we're missing a header value that's apparently supposed to contain a Biscuit.

A quick note, however, before we solve this: by default, this library emits a more generic "authorization failed" error instead of "couldn't find biscuit header". It's best to give attackers as little information as possible. This example enables the `ErrorMode::Verbose` setting for the purpose of debugging and explanation, but in production it's probably preferable to use `ErrorMode::Secure` (the default).

Anyway, let's make some biscuits. The `biscuit generate` subcommand is what creates fresh biscuits.

```
$ biscuit generate --private-key-file assets/private.key - > assets/alice.bc
```

When prompted for input, simply write:

```prolog
user("alice");
```

The `-` right before the redirect instructs the `biscuit` command to read from stdin instead of opening an editor to write the "authority block". Omit the hyphen if you want to use your editor. Or you can provide the name of a file instead of a hyphen from which to read the Datalog. Or you can leave the hyphen and pipe `echo 'user("alice");` into stdin. Lots of choices.

In this generated biscuit, we've provided the *fact* (more precisely, an *authority* fact, since it's in the [authority block][intro]) that the user is "alice".

The server expects this biscuit in a header called `X-Biscuit-Auth`, so let's create a small file for convenience called `alice.header` with the contents of the biscuit we just generated, prefixed by the header name:

```
x-biscuit-auth: En4KFW...Xdq2k=
```

Note that the end of your biscuit is likely different than the one presented here.

Now let's try another request! We can use curl's `-H` argument to provide headers. (Remember to also use `-v` to debug unexpected errors when using curl.)

```
$ curl 127.0.0.1:3000/admin/alice -H @assets/alice.header
Hello, admin alice!
```

Success!

If we go through the same process with the user "bob" instead of "alice", we get the message "Hello, admin bob!".

However, let's do it for Carol and see that it fails. It *should* fail, since "carol" was not one of the admins we defined in the set of facts we loaded into the authorizer at program start. Because there is no `admin("carol")` fact, the policy

```prolog
allow if user("carol"), admin("carol");
```

should never match.

So, running all the commands for Carol, we get:

```
$ echo 'user("carol");' | biscuit generate --private-key-file assets/private.key - > assets/carol.bc

$ echo -n 'x-biscuit-auth: ' | cat - assets/carol.bc > assets/carol.header

$ curl 127.0.0.1:3000/admin/carol -H @assets/carol.header
verification failure: authorization failed
```

As expected, we can't authorize her biscuit because the policy never matches.

---

You may have already noticed that there's no actual connection between the name in the path and the user authenticating. Alice can `GET /admin/bob` and Bob can `GET /admin/alice`. 

This isn't ideal. In order to solve it, we'll need to figure out how to add facts to the authorizer that depend on properties of the request, such as path parameters. We'll explore this in the example (TODO).

[install]: https://www.biscuitsec.org/docs/Usage/cli/
[intro]: https://www.biscuitsec.org/docs/getting-started/introduction/