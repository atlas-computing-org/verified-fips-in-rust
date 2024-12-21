# Setup

## Aeneas Base Library

1. In the `lean` folder at the root of this repo, clone the Aeneas project. We need the project for the `Base` library.

    ```
    cd lean
    git clone https://github.com/AeneasVerif/aeneas.git
    ```

2. Edit the `lean-toolchain` file to have the same contents as the `aeneas/backends/lean/lean-toolchain` file.

3. Edit the `lakefile.lean` file to have the following dependency

    ```
    require base from "../../aeneas/backends/lean"
    ```

    Because the Aeneas `Base` package already exports `mathlib4`, you will need to comment out any `require mathlib` lines in your `lakefile.lean` file.

4. In this folder, run `lake update` to build the dependencies.

