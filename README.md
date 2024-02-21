# Instructions

Follow the steps in the [isosceles article][isosceles] to download and build `libwebp` and `bad.webp`.
Copy `bad.webp` into this directory.

After that, apply `libwebp.patch` with `git apply libwebp.patch`.

Build `simple_api_fuzzer` (inside `libwebp`):

```posix-shell
$ make -f makefile.unix clean
$ make -f makefile.unix
$ make -f makefile.unix src/mux/libwebpmux.a
$ cd tests/fuzzer
$ make -f makefile.unix
```

Note that this will build libwebp without any fuzzing instrumentation.

Build `tracer` with `make tracer`.


Run `python3 ./capture_snapshot.py` to create a memory snapshot just before fuzzing starts.


Run `python3 ./triton_solve.py` to launch the symbolic execution on the memory snapshot.

[isosceles]: https://blog.isosceles.com/the-webp-0day/