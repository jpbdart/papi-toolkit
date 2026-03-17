## STRATUM Annotations

PAPI supports `__attribute__((annotate(...)))` annotations using the `stratum:` prefix.
These annotations let you communicate information to the analyzer that it cannot infer
from source alone — most importantly, the taint behaviour of library functions whose
source is not available to PAPI.

Annotations work on both **function definitions** (in your own source) and
**forward declarations** (for library functions). When PAPI encounters a forward
declaration that carries a `stratum:` annotation, it injects a synthetic function
summary so the interprocedural propagator treats that function as a known validator.

### `stratum:validates(N, LEVEL)`

Declares that, upon return from the annotated function, parameter `N` (0-based) has
been elevated to at least `LEVEL`. This tells PAPI's taint solver not to require a
parse point at call sites that pass already-validated data through this function.

`LEVEL` must be one of: `RAW`, `SYNTACTIC`, `SEMANTIC`, `CONTEXTUAL`, `CLEAN`.

The annotation may be placed on the **parameter declaration** (recommended; the
index is inferred from position) or on the **function declaration** (the explicit
index in the annotation string is used).

**Example — annotating a parameter directly:**

```c
// Library header (no source available to PAPI)
void sanitize_port(
    __attribute__((annotate("stratum:validates(0,SEMANTIC)")))
    const char *raw_port,
    int *out_port);
```

**Example — annotating the function declaration:**

```c
__attribute__((annotate("stratum:validates(1,CONTEXTUAL)")))
void escape_for_sql(const char *input, char *out_buf, size_t out_len);
```

After seeing either form, PAPI treats the named parameter as `SEMANTIC` (or
`CONTEXTUAL`) at every call site, propagating that level through pass-through
relationships to downstream functions.

### `stratum:suppress(REASON)`

Suppresses a parse-point finding at the annotated parameter. The parameter is still
emitted in the YAML output with `suppressed: true` and the reason string, so the
decision is auditable without cluttering the actionable findings list.

The annotation is placed on the **parameter declaration**. The reason string is
free-form text — use it to record why validation is not required here (e.g.
`OUT_PARAM`, `INTERNAL_ONLY`, `VALIDATED_BY_CALLER`).

```c
// buf is an output parameter; PAPI would otherwise flag it as a parse point
// because the callee writes into it via pointer. The suppress annotation
// records our intent that this is not an input needing validation.
void fill_buffer(
    __attribute__((annotate("stratum:suppress(OUT_PARAM)")))
    char *buf,
    size_t len);
```

In the YAML output, suppressed entries appear as:

```yaml
- id: p001
  file: "plugin_public.c"
  line: 247
  variable: "buf"
  actual_layer: RAW
  required_layer: CONTEXTUAL
  suppressed: true
  suppress_reason: "OUT_PARAM"
  parameter_index: 0
  suggested_parsers: []
```

### Annotation placement rules

| Scenario | Recommended placement |
|----------|-----------------------|
| Your own function, validates a parameter | On the `ParmVarDecl` |
| Your own function, suppress a finding | On the `ParmVarDecl`, or on the function declaration to suppress all params |
| Library function (no source) | On the `extern` forward declaration, on the `ParmVarDecl` |
| Multiple validated parameters | One annotation per parameter, each on its own `ParmVarDecl` |
| Init/teardown function (suppress all params) | On the function declaration itself, before `{` |

> `ParmVarDecl` is Clang's AST node for a function parameter declaration. It is a subclass of `VarDecl`, which is itself a subclass of `DeclaratorDecl` and ultimately `Decl`.

> When Clang parses a function like:

>  `void foo(int x, const char *name);`

> it creates a `FunctionDecl` for `foo`, and for each parameter it creates a `ParmVarDecl`, one for `x` and one for `name`. The `ParmVarDecl` carries the parameter's name, type, index position, and any attributes attached to it, including `__attribute__((annotate(...)))`.

> In `StratumAnnotation.cpp`, the code iterates `func->getNumParams()`, fetches each `ParmVarDecl` via `func->getParamDecl(i)`, then walks its `attrs()` looking for `AnnotateAttr` instances. That is how a per-parameter annotation like:

>  `void foo(__attribute__((annotate("stratum:validates(0,SEMANTIC)"))) const char *input);`

> gets picked up and associated with parameter index `i` rather than with the function as a whole.

#### STRATUM suppress
When `stratum:suppress` is placed on the **function declaration** (after the parameter list, before `{`), it applies to all parameters. This is the natural form for init and teardown functions where no parameter represents untrusted input:

```c
void config__init(struct mosquitto__config *config)
    __attribute__((annotate("stratum:suppress(INIT_OUT_PARAM)")))
{
    memset(config, 0, sizeof(struct mosquitto__config));
    /* ... */
}
```

#### STRATUM validate
When a `stratum:validates` annotation is placed on a parameter declaration, the parameter index in the annotation string is ignored; PAPI uses the parameter's actual position in the signature. This means you can always write `stratum:validates(0,LEVEL)` on any parameter and the correct index will be used.

