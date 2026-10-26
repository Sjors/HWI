#!/usr/bin/env bash
# TEMPORARY ANTI-EXFIL: current Trezor main needs SDL3, unavailable in Ubuntu 24.04.

build_trezor_sdl3() {
    local source_root="$PWD/trezor-sdl3"
    TREZOR_SDL3_PREFIX="$source_root/prefix"
    mkdir -p "$source_root"

    if [ ! -d "$source_root/SDL/.git" ]; then
        git clone --depth 1 --branch release-3.4.2 https://github.com/libsdl-org/SDL.git "$source_root/SDL"
    fi
    test "$(git -C "$source_root/SDL" rev-parse HEAD)" = 683181b47cfabd293e3ea409f838915b8297a4fd
    cmake -S "$source_root/SDL" -B "$source_root/SDL/build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$TREZOR_SDL3_PREFIX" \
        -DCMAKE_INSTALL_LIBDIR=lib -DSDL_SHARED=ON -DSDL_STATIC=OFF \
        -DSDL_TESTS=OFF -DSDL_EXAMPLES=OFF -DSDL_UNIX_CONSOLE_BUILD=ON \
        -DSDL_X11=OFF -DSDL_WAYLAND=OFF -DSDL_AUDIO=OFF -DSDL_KMSDRM=OFF \
        -DSDL_OPENGL=OFF -DSDL_OPENGLES=OFF -DSDL_VULKAN=OFF
    cmake --build "$source_root/SDL/build" --parallel 8
    cmake --install "$source_root/SDL/build"

    if [ ! -d "$source_root/SDL_image/.git" ]; then
        git clone --depth 1 --branch release-3.4.0 https://github.com/libsdl-org/SDL_image.git "$source_root/SDL_image"
    fi
    test "$(git -C "$source_root/SDL_image" rev-parse HEAD)" = ad58ecfc27a1bd09e510ceff8bbbdb1094806476
    cmake -S "$source_root/SDL_image" -B "$source_root/SDL_image/build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$TREZOR_SDL3_PREFIX" \
        -DCMAKE_INSTALL_PREFIX="$TREZOR_SDL3_PREFIX" -DCMAKE_INSTALL_LIBDIR=lib \
        -DSDLIMAGE_VENDORED=OFF -DSDLIMAGE_AVIF=OFF -DSDLIMAGE_JXL=OFF \
        -DSDLIMAGE_WEBP=OFF -DSDLIMAGE_TIF=OFF -DSDLIMAGE_PNG_SHARED=OFF \
        -DSDLIMAGE_JPG_SHARED=OFF -DSDLIMAGE_SAMPLES=OFF -DSDLIMAGE_TESTS=OFF
    cmake --build "$source_root/SDL_image/build" --parallel 8
    cmake --install "$source_root/SDL_image/build"

    export PKG_CONFIG_PATH="$TREZOR_SDL3_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
}

bundle_trezor_sdl3() {
    local binary="$1"
    shift
    local destination
    destination="$(dirname "$binary")"
    local library
    for library in "$@"; do
        cp -L "$TREZOR_SDL3_PREFIX/lib/$library" "$destination/$library"
        patchelf --set-rpath '$ORIGIN' "$destination/$library"
    done
    patchelf --set-rpath '$ORIGIN' "$binary"
}
