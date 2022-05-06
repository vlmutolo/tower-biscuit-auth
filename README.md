# `tower-biscuit-auth`

**Tower** is an ecosystem of Rust libraries built to provide and enable reusable abstractions for request-reply-based services. From their [GitHub][tower]:

> Tower aims to make it as easy as possible to build robust networking clients and servers. It is protocol agnostic, but is designed around a request / response pattern. If your protocol is entirely stream based, Tower may not be a good fit.

**Biscuit** is a new set of standards centered around authorization. More specifically, Biscuit is:

- A language to describe authorization patterns (Datalog-based).
- A binary format for asymmetrically-signed bearer tokens (also allowing attenuation).
- Implementations of those standards.


So Tower is all about providing abstractions over service architectuers, and Biscuits are a new pattern for scalable, flexible authorization for services.

This library is about exploring ways to expose Biscuit authorization as reusable Tower abstractions. We currently have a *very crude* first draft of an authorization layer where the downstream user provides ways to extract facts from the request type, and the layer blocks bad requests by being a [`tower::filter::Filter`][filter].

Contributions are welcome, including suggestions for a complete redesign.

[tower]: https://github.com/tower-rs/tower
[filter]: https://docs.rs/tower/0.4.12/tower/filter/struct.Filter.html