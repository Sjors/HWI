#! /usr/bin/env bash

while [[ $# -gt 0 ]]; do
    case $1 in
        --trezor-1)
        build_trezor_1=1
        shift
        ;;
        --trezor-t)
        build_trezor_t=1
        shift
        ;;
        --coldcard)
        build_coldcard=1
        shift
        ;;
        --coldcard-edge)
        build_coldcard_edge=1
        shift
        ;;
        --bitbox01)
        build_bitbox01=1
        shift
        ;;
        --ledger)
        build_ledger=1
        shift
        ;;
        --ledger-legacy)
        build_ledger=1
        shift
        ;;
        --keepkey)
        build_keepkey=1
        shift
        ;;
        --jade)
        build_jade=1
        shift
        ;;
        --bitbox02)
        build_bitbox02=1
        shift
        ;;
        --bitcoind)
        build_bitcoind=1
        shift
        ;;
        --all)
        build_trezor_1=1
        build_trezor_t=1
        build_coldcard=1
        build_bitbox01=1
        build_ledger=1
        build_keepkey=1
        build_jade=1
        build_bitbox02=1
        build_bitcoind=1
        shift
        ;;
    esac
done

# Makes debugging easier
set -ex

# Go into the working directory
mkdir -p work
cd work

# TEMPORARY ANTI-EXFIL: integration branches in Sjors's forks.
# Remove this block and restore upstream versions when the companion PRs land.
# Branch refs deliberately follow signing-only SHA changes before publication.
ANTI_EXFIL_REF="2026/10/taproot-anti-exfil"
TREZOR_REPOSITORY="https://github.com/Sjors/trezor-firmware.git"
JADE_REPOSITORY="https://github.com/Sjors/Jade.git"
BITBOX02_REPOSITORY="https://github.com/Sjors/bitbox02-firmware.git"
COLDCARD_EDGE_REPOSITORY="https://github.com/Sjors/firmware.git"
BITCOIN_REPOSITORY="https://github.com/Sjors/bitcoin.git"

# Pinned firmware versions
TREZOR_VERSION="${ANTI_EXFIL_REF}"
BITBOX01_VERSION="v7.1.0"
BITBOX02_VERSION="${ANTI_EXFIL_REF}"
KEEPKEY_VERSION="v7.10.0"
SPECULOS_VERSION="ed952a54801f59a71399462b5422976d84c817bb"  # Requires Python >=3.10 (v0.25.11+)
JADE_VERSION="${ANTI_EXFIL_REF}"

COLDCARD_VERSION="2026-07-31T0519-v5.6.0"
COLDCARD_EDGE_VERSION="${ANTI_EXFIL_REF}"

if [[ -n ${build_trezor_1} || -n ${build_trezor_t} ]]; then
    # TEMPORARY ANTI-EXFIL: build portable SDL3 libraries for current main.
    source ../setup_trezor_sdl3.sh
    build_trezor_sdl3

    # Clone trezor-firmware if it doesn't exist, or update it if it does
    if [ ! -d "trezor-firmware" ]; then
        git clone --recursive --shallow-submodules --branch ${TREZOR_VERSION} "${TREZOR_REPOSITORY}"
        cd trezor-firmware
    else
        cd trezor-firmware
        git remote set-url origin "${TREZOR_REPOSITORY}"
        git fetch --no-recurse-submodules origin "${TREZOR_VERSION}"
        git checkout --detach FETCH_HEAD
        git submodule sync --recursive
        git submodule update --init --recursive
    fi

    # Remove .venv so that poetry can symlink everything correctly
    find . -type d -name ".venv" -exec rm -rf {} +

    if [[ -n ${build_trezor_1} ]]; then
        # Build trezor one emulator. This is pretty fast, so rebuilding every time is ok
        # But there should be some caching that makes this faster
        uv sync --locked
        cd legacy
        export EMULATOR=1 TREZOR_TRANSPORT_V1=1 DEBUG_LINK=1 HEADLESS=1
        export CC=gcc-12
        uv run script/setup
        uv run script/cibuild
        bundle_trezor_sdl3 firmware/trezor.elf libSDL3.so.0
        # Delete any emulator.img file
        find . -name "emulator.img" -exec rm {} \;
        cd ..
    fi

    if [[ -n ${build_trezor_t} ]]; then
        # Current main pins this in flake.nix; keep the host default unchanged.
        TREZOR_RUST_NIGHTLY="nightly-2026-03-16"
        rustup toolchain install "${TREZOR_RUST_NIGHTLY}" --profile minimal --component rustfmt --component rust-src
        uv sync --locked
        cd core
        RUSTUP_TOOLCHAIN="${TREZOR_RUST_NIGHTLY}" uv run make build_unix TREZOR_MODEL=T2T1 PYOPT=0
        # Preserve the path used by HWI and emu.sh despite the xtask output move.
        mkdir -p build/unix
        cp build/artifacts/latest/firmware-emu build/unix/trezor-emu-core
        bundle_trezor_sdl3 build/unix/trezor-emu-core libSDL3.so.0 libSDL3_image.so.0
        # Delete any emulator.img file
        find . -name "trezor.flash" -exec rm {} \;
        cd ..
    fi
    cd ..
fi

if [[ -n ${build_coldcard} || -n ${build_coldcard_edge} ]]; then
    do_coldcard_firmware() {
        local coldcard_version="$1"
        local coldcard_dir="$2"
        local coldcard_requirements="$3"
        local coldcard_multisig_patch="$4"
        local coldcard_repository="${5:-https://github.com/Coldcard/firmware.git}"
        local coldcard_mpy_patch="${PWD}/../data/coldcard-ubuntu24-mpy.patch"
        # TEMPORARY ANTI-EXFIL: match the validated MicroPython compiler.
        local CC=gcc-13
        export CC

        # Clone coldcard firmware if it doesn't exist, or update it if it does
        coldcard_setup_needed=false
        if [ ! -d "${coldcard_dir}" ]; then
            git clone --branch "${coldcard_version}" "${coldcard_repository}" "${coldcard_dir}"
            cd "${coldcard_dir}"
            # Simulator setup initializes the required nested dependencies.
            git submodule update --init
            coldcard_setup_needed=true
        else
            cd "${coldcard_dir}"
            git remote set-url origin "${coldcard_repository}"
            git fetch --tags origin "${coldcard_version}"
            git checkout --force FETCH_HEAD
            git submodule sync --recursive
            git submodule update --init --force
            coldcard_setup_needed=true
        fi

        # Add multisig fixtures used by the Coldcard multisig display tests.
        git apply "../../data/${coldcard_multisig_patch}"

        # Build the simulator. This is cached, but it is also fast
        poetry run pip install -r "${coldcard_requirements}"
        pip install -r "${coldcard_requirements}"
        cd unix
        if [ "$coldcard_setup_needed" == true ] ; then
            pushd ../external/micropython
            # Do not treat new warnings from Ubuntu 24.04's compiler as errors.
            if [ -f ../../ubuntu24_mpy.patch ]; then
                git apply ../../ubuntu24_mpy.patch
            else
                git apply "${coldcard_mpy_patch}"
            fi
            popd
            pushd ../external/micropython/mpy-cross/
            make
            popd
            # Skip make setup, which builds MicroPython's bundled libffi and
            # fails with current Autoconf. The simulator links system libffi.
            # Initialize its only required MicroPython submodule directly.
            git -C ../external/micropython submodule update --init lib/berkeley-db-1.xx
            make ngu-setup
            ln -sf ../external/micropython/ports/unix/coldcard-mpy .
        fi
        make
        cd ../..
    }

    if [[ -n ${build_coldcard} ]]; then
        do_coldcard_firmware "${COLDCARD_VERSION}" firmware requirements.txt coldcard-multisig.patch
    fi
    if [[ -n ${build_coldcard_edge} ]]; then
        do_coldcard_firmware "${COLDCARD_EDGE_VERSION}" firmware unix/requirements.txt coldcard-edge-multisig.patch "${COLDCARD_EDGE_REPOSITORY}"
    fi
fi

if [[ -n ${build_bitbox01} ]]; then
    # Clone digital bitbox firmware if it doesn't exist, or update it if it does
    if [ ! -d "mcu" ]; then
        git clone --recursive --branch ${BITBOX01_VERSION} https://github.com/digitalbitbox/mcu.git
        cd mcu
    else
        cd mcu
        git fetch

        # Determine if we need to pull. From https://stackoverflow.com/a/3278427
        UPSTREAM=${1:-'@{u}'}
        LOCAL=$(git rev-parse @)
        REMOTE=$(git rev-parse "$UPSTREAM")
        BASE=$(git merge-base @ "$UPSTREAM")

        if [ $LOCAL = $REMOTE ]; then
            echo "Up-to-date"
        elif [ $LOCAL = $BASE ]; then
            git pull
        fi
    fi

    # Build the simulator. This is cached, but it is also fast
    mkdir -p build && cd build
    cmake .. -DBUILD_TYPE=simulator -DCMAKE_C_FLAGS="-Wno-format-truncation -Wno-array-parameter"
    make
    cd ../..
fi

if [[ -n ${build_keepkey} ]]; then
    poetry run pip install protobuf
    pip install protobuf
    # Clone keepkey firmware if it doesn't exist, or update it if it does
    keepkey_setup_needed=false
    if [ ! -d "keepkey-firmware" ]; then
        git clone --recursive --depth 1 --shallow-submodules --branch ${KEEPKEY_VERSION} https://github.com/keepkey/keepkey-firmware.git
        cd keepkey-firmware
        keepkey_setup_needed=true
    else
        cd keepkey-firmware
        cd deps/googletest
        git reset --hard HEAD~1 # Undo git-am for checking and updating
        cd ../..
        git reset --hard HEAD~1 # Undo git-am for checking and updating
        git fetch

        # Determine if we need to pull. From https://stackoverflow.com/a/3278427
        UPSTREAM=${1:-'@{u}'}
        LOCAL=$(git rev-parse @)
        REMOTE=$(git rev-parse "$UPSTREAM")
        BASE=$(git merge-base @ "$UPSTREAM")

        if [ $LOCAL = $REMOTE ]; then
            echo "Up-to-date"
        elif [ $LOCAL = $BASE ]; then
            git pull
            keepkey_setup_needed=true
        fi
    fi
    # Apply patches to make simulator build
    git am ../../data/keepkey-build.patch
    cd deps/googletest
    git am ../../../../data/keepkey-googletest.patch
    cd ../../

    # Build the simulator. This is cached, but it is also fast
    if [ "$keepkey_setup_needed" == true ] ; then
        git clean -ffdx
        git clone https://github.com/nanopb/nanopb.git -b nanopb-0.3.9.4
    fi
    cd nanopb
    git am ../../../data/nanopb-deprecated-mode.patch
    cd generator/proto
    make
    cd ../../../
    export PATH=$PATH:`pwd`/nanopb/generator
    cmake -C cmake/caches/emulator.cmake . -DNANOPB_DIR=nanopb/ -DPROTOC_BINARY=/usr/local/bin/protoc
    make
    # Delete any emulator.img file
    find . -name "emulator.img" -exec rm {} \;
    cd ..
fi

if [[ -n ${build_ledger} ]]; then
    # Clone ledger simulator Speculos if it doesn't exist, or update it if it does
    if [ ! -d "speculos" ]; then
        git clone --recursive --depth 1 --shallow-submodules --revision ${SPECULOS_VERSION} https://github.com/LedgerHQ/speculos.git
    else
        pushd speculos
        git fetch

        # Determine if we need to pull. From https://stackoverflow.com/a/3278427
        UPSTREAM=${1:-'@{u}'}
        LOCAL=$(git rev-parse @)
        REMOTE=$(git rev-parse "$UPSTREAM")
        BASE=$(git merge-base @ "$UPSTREAM")

        if [ $LOCAL = $REMOTE ]; then
            echo "Up-to-date"
        elif [ $LOCAL = $BASE ]; then
            git pull
        fi
        popd
    fi

    poetry run pip install -e ./speculos
    pip install -e ./speculos

    cd speculos

    # Build the simulator. This is cached, but it is also fast
    mkdir -p build
    cmake -Bbuild -S .
    make -C build/

    cd ..
fi

if [[ -n ${build_jade} ]]; then
    mkdir -p jade
    cd jade

    # Clone Blockstream Jade firmware if it doesn't exist, or update it if it does
    if [ ! -d "jade" ]; then
        git clone --recursive --branch ${JADE_VERSION} "${JADE_REPOSITORY}" ./jade
        cd jade
    else
        cd jade
        git remote set-url origin "${JADE_REPOSITORY}"
        git fetch origin "${JADE_VERSION}"
        git checkout --detach FETCH_HEAD
        git submodule update --init --recursive
    fi

    # TEMPORARY ANTI-EXFIL: ESP-IDF needs upstream tags for a SemVer version.
    git fetch --tags https://github.com/Blockstream/Jade.git

    # Deduce the relevant version of esp-idf to use
    ESP_IDF_BRANCH=$(grep "ARG ESP_IDF_BRANCH=" Dockerfile | cut -d\= -f2)
    ESP_IDF_COMMIT=$(grep "ARG ESP_IDF_COMMIT=" Dockerfile | cut -d\= -f2)
    cd ..

    # We will install the esp-idf tools in a given location (otherwise defaults to user home dir)
    export IDF_TOOLS_PATH="$(pwd)/esp-idf-tools"

    # If the directory exists, see if it is at the expected commit
    # If not, remove the entire directory (it will be re-cloned below)
    if [ -d "esp-idf" ]; then
        cd esp-idf
        LOCAL=$(git rev-parse @)
        if [ $LOCAL = $ESP_IDF_COMMIT ]; then
            echo "esp-idf up-to-date"
            cd ..
        else
            cd ..
            rm -fr esp-idf
        fi
    fi

    # Clone the upstream if the directory does not exist
    # Then build and install the tools
    if [ ! -d "esp-idf" ]; then
        git clone --quiet --depth=1 --branch ${ESP_IDF_BRANCH} --single-branch --recursive --shallow-submodules https://github.com/espressif/esp-idf.git ./esp-idf
        cd esp-idf

        git checkout ${ESP_IDF_COMMIT}
        git submodule update --recursive --init
        cd ..
    fi

    # Install the tools every run regardless
    # (Otherwise a cached CI run which skips the above esp-idf clone does not
    # always seem to pick up the locally installed python virtualenv, and instead uses
    # the system python/no-virtualenv which fails ...)
    # Only install the tools we need (ie. esp32)
    rm -fr "${IDF_TOOLS_PATH}"
    cd esp-idf
    ./install.sh esp32
    cd ..

    # Export the tools
    . ./esp-idf/export.sh

    # Install the emulator
    idf_tools.py install qemu-xtensa
    QEMU_EXE=$(find ${IDF_TOOLS_PATH} -type f -name qemu-system-xtensa)
    QEMU_BIOS_DIR=$(dirname "${QEMU_EXE}")/../share/qemu
    echo "Installed qemu emulator: ${QEMU_EXE}"
    echo "Installed qemu bios files: ${QEMU_BIOS_DIR}"

    # Build Blockstream Jade firmware configured for the emulator
    cd jade
    rm -fr sdkconfig
    cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
    idf.py fullclean all

    # Make the qemu flash image
    esptool.py --chip esp32 merge_bin --fill-flash-size 4MB -o main/qemu/flash_image.bin \
    --flash_mode dio --flash_freq 40m --flash_size 4MB \
    0x9000 build/partition_table/partition-table.bin \
    0xe000 build/ota_data_initial.bin \
    0x1000 build/bootloader/bootloader.bin \
    0x10000 build/jade.bin
    cd ..

    # Extract the minimal artifacts required to run the emulator
    rm -fr simulator
    mkdir simulator
    cp ${QEMU_EXE} simulator/
    cp -R ${QEMU_BIOS_DIR} simulator/pc-bios
    cp jade/main/qemu/flash_image.bin simulator/
    cp jade/main/qemu/qemu_efuse.bin simulator/

    cd ..
fi

if [[ -n ${build_bitbox02} ]]; then
    # Clone digital bitbox02 firmware if it doesn't exist, or update it if it does
    if [ ! -d "bitbox02-firmware" ]; then
        git clone --recursive --branch ${BITBOX02_VERSION} "${BITBOX02_REPOSITORY}"
        cd bitbox02-firmware
    else
        cd bitbox02-firmware
        git remote set-url origin "${BITBOX02_REPOSITORY}"
        git fetch origin "${BITBOX02_VERSION}"
        git checkout --detach FETCH_HEAD
        git submodule update --init --recursive
    fi

    # TEMPORARY ANTI-EXFIL: version generation needs upstream signed release tags.
    git fetch --tags https://github.com/BitBoxSwiss/bitbox02-firmware.git

    # Build the simulator. This is cached, but it is also fast
    CONTAINER_VERSION=$(cat .containerversion)
    docker pull shiftcrypto/firmware_v2:$CONTAINER_VERSION
    # The safe.directory config is so that git commands work. even though the repo folder mounted in
    # Docker is owned by root, which can be different from the owner on the host.
    docker run -i --rm --volume $(pwd):/bb02 shiftcrypto/firmware_v2:$CONTAINER_VERSION bash -c "git config --global --add safe.directory /bb02 && cd /bb02 && make -j simulator"
fi

if [[ -n ${build_bitcoind} ]]; then
    # TEMPORARY ANTI-EXFIL: Core's two-round host is needed by integration tests.
    if [ ! -d "bitcoin" ]; then
        git clone --single-branch --branch "${ANTI_EXFIL_REF}" "${BITCOIN_REPOSITORY}" bitcoin
        cd bitcoin
    else
        cd bitcoin
        git remote set-url origin "${BITCOIN_REPOSITORY}"
        git fetch origin "${ANTI_EXFIL_REF}"
        git checkout --detach FETCH_HEAD
    fi

    # Build bitcoind. This is super slow, but it is cached so it runs fairly quickly.
    pushd depends
    make -j $(nproc) NO_QT=1 NO_QR=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 NO_USDT=1
    popd

    # Do the build
    cmake -B build --toolchain depends/x86_64-pc-linux-gnu/toolchain.cmake -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF
    cmake --build build -j $(nproc) --target bitcoind
fi
