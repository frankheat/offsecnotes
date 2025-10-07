---
title: "Analyze native libraries"
weight: 3
---

## Imports

```sh
rabin2 -i libyouwant.so

nth vaddr      bind   type     lib name
―――――――――――――――――――――――――――――――――――
3   0x0059a650 GLOBAL FUNC     AAssetManager_fromJava
4   0x0059abe0 GLOBAL FUNC     execve
5   ---------- GLOBAL OBJ      _ZNSt6__ndk15ctypeIcE2idE
[...]
```

---

## Exports

```sh
rabin2 -E libyouwant.so

nth paddr      vaddr      bind     type size lib name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
210 0x000ae1f0 0x000ae1f0 GLOBAL   FUNC  200 r_bin_java_print_exceptions_attr_summary
211 0x000afc90 0x000afc90 GLOBAL   FUNC  135 r_bin_java_get_args
212 0x000b18e0 0x000b18e0 GLOBAL   FUNC   35 r_bin_java_get_item_desc_from_bin_cp_list
[...]
```

---

## Symbols

```sh
rabin2 -s libyouwant.so

nth paddr      vaddr      bind     type size lib name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
110 0x000150a0 0x000150a0 GLOBAL FUNC 56 _obstack_allocated_p
111 0x0001f600 0x0021f600 GLOBAL  OBJ  8 program_name
112 0x0001f620 0x0021f620 GLOBAL  OBJ  8 stderr
[...]
```

---

## List libraries

```sh
rabin2 -l libyouwant.so

libc++_shared.so
liblog.so
libz.so
[...]
```

---

## Show strings

```sh
rabin2 -z libyouwant.so

nth    paddr      vaddr      len  size section type    string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0      0x0140e3db 0x0140e3db 4    5    .rodata ascii   JjD/
1      0x0140e412 0x0140e412 7    8    .rodata ascii   \r\f\v\n\t\b\a
2      0x0140e431 0x0140e431 28   29   .rodata ascii   !!!!!!!!(!!!!!\b!!!!!!!!!!!!!
[...]

# Force minimum and maximum number of chars per string
rabin2 -z -N 5:8 libyouwant.so

nth    paddr      vaddr      len size section type    string
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0      0x0140e431 0x0140e431 8   8    .rodata ascii   !!!!!!!!
1      0x0140e439 0x0140e439 7   7    .rodata ascii   (!!!!!\b
2      0x0140e440 0x0140e440 8   8    .rodata ascii   !!!!!!!!
[...]
```
