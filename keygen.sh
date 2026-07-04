#!/bin/bash
#
# Android signing key/cert generator.
#
# Platform keys: generated via development/tools/make_key (RSA 2048, AOSP default).
# APEX keys: generated via raw openssl (RSA 4096, CN=apex name, ".certificate.override"
# file naming), matching the reference gen_keys.py driver script.
#
# Output layout per APEX key (e.g. com.android.adbd):
#   com.android.adbd.pem                            <- raw RSA privkey (kept for avbpubkey/reruns)
#   com.android.adbd.certificate.override.x509.pem   <- self-signed cert (CN=com.android.adbd)
#   com.android.adbd.certificate.override.pk8        <- unencrypted PKCS8 DER privkey
#   com.android.adbd.avbpubkey                       <- extracted AVB public key
#     (com.android.vndk gets "<name>.pubkey" instead of ".avbpubkey")
#
# apex_hardware_keys / apex_cf_keys / apex_app_keys do NOT get their own generated
# key or Android.bp module -- they're PRODUCT_CERTIFICATE_OVERRIDES entries that
# point at an existing apex_keys module (com.android.hardware / com.google.cf /
# a named apex cert, respectively).

set -euo pipefail

# Define destination directory
destination_dir="vendor/private/keys"

RSA_PLATFORM_KEY_SIZE=2048
RSA_APEX_KEY_SIZE=4096
CERT_DAYS=10000

# ---------------------------------------------------------------------------
# Key lists
# ---------------------------------------------------------------------------

# Platform keys (kept from the original script's list)
platform_keys=(
    releasekey
    platform
    shared
    media
    networkstack
    verity
    otakey
    testkey
    cyngn-priv-app
    sdk_sandbox
    bluetooth
    verifiedboot
)

# APEX keys -- based on keys.py (build/make/target/product/security + apexkeys.txt)
apex_keys=(
    com.android.adbd
    com.android.adservices
    com.android.adservices.api
    com.android.appsearch
    com.android.appsearch.apk
    com.android.art
    com.android.bt
    com.android.bluetooth
    com.android.btservices
    com.android.cellbroadcast
    com.android.compos
    com.android.configinfrastructure
    com.android.connectivity.resources
    com.android.conscrypt
    com.android.crashrecovery
    com.android.devicelock
    com.android.extservices
    com.android.federatedcompute
    com.android.graphics.pdf
    com.android.hardware
    com.android.health.connect.backuprestore
    com.android.healthconnect.controller
    com.android.healthfitness
    com.android.hotspot2.osulogin
    com.android.i18n
    com.android.ipsec
    com.android.media
    com.android.mediaprovider
    com.android.media.swcodec
    com.android.nearby.halfsheet
    com.android.networkstack.tethering
    com.android.neuralnetworks
    com.android.nfcservices
    com.android.ondevicepersonalization
    com.android.os.statsd
    com.android.permission
    com.android.profiling
    com.android.resolv
    com.android.rkpd
    com.android.runtime
    com.android.safetycenter.resources
    com.android.scheduling
    com.android.sdkext
    com.android.support.apexer
    com.android.telephony
    com.android.telephonycore
    com.android.telephonymodules
    com.android.tethering
    com.android.tzdata
    com.android.uprobestats
    com.android.uwb
    com.android.uwb.resources
    com.android.virt
    com.android.vndk
    com.android.vndk.current
    com.android.wifi
    com.android.wifi.dialog
    com.android.wifi.resources
    com.google.cf
    com.google.pixel.camera.hal
    com.google.pixel.vibrator.hal
    com.qorvo.uwb
)

# Apexes signed with the 'com.android.hardware' cert (override, no own key)
apex_hardware_keys=(
    com.android.hardware.audio
    com.android.hardware.authsecret
    com.android.hardware.biometrics.face.virtual
    com.android.hardware.biometrics.fingerprint.virtual
    com.android.hardware.boot
    com.android.hardware.cas
    com.android.hardware.contexthub
    com.android.hardware.dumpstate
    com.android.hardware.gatekeeper
    com.android.hardware.gnss
    com.android.hardware.input.processor
    com.android.hardware.memtrack
    com.android.hardware.net.nlinterceptor
    com.android.hardware.neuralnetworks
    com.android.hardware.power
    com.android.hardware.rebootescrow
    com.android.hardware.secure_element
    com.android.hardware.security.authgraph
    com.android.hardware.security.secretkeeper
    com.android.hardware.sensors
    com.android.hardware.tetheroffload
    com.android.hardware.thermal
    com.android.hardware.threadnetwork
    com.android.hardware.usb
    com.android.hardware.uwb
    com.android.hardware.vibrator
    com.android.hardware.wifi
)

# Apexes signed with the 'com.google.cf' cert (override, no own key)
apex_cf_keys=(
    com.android.hardware.keymint.rust_cf_remote
    com.android.hardware.keymint.rust_cf_guest_trusty_nonsecure
    com.android.hardware.keymint.rust_nonsecure
    com.android.hardware.gatekeeper.cf_remote
    com.android.hardware.gatekeeper.nonsecure
    com.google.cf.input.config
    com.google.cf.oemlock
    com.google.cf.health
    com.google.cf.health.storage
    com.google.cf.vulkan
    com.google.cf.light
    com.google.cf.gralloc
    com.google.cf.confirmationui
    com.google.cf.nfc
    com.google.cf.identity
    com.google.cf.ir
    com.google.cf.bt
    com.google.cf.rild
    com.google.cf.wifi
)

# Apps signed with specific apex keys: "ModuleName:override.certificate.module"
apex_app_keys=(
    "AdServicesApk:com.android.adservices.api.certificate.override"
    "FederatedCompute:com.android.federatedcompute.certificate.override"
    "HalfSheetUX:com.android.nearby.halfsheet.certificate.override"
    "HealthConnectBackupRestore:com.android.health.connect.backuprestore.certificate.override"
    "HealthConnectController:com.android.healthconnect.controller.certificate.override"
    "OsuLogin:com.android.hotspot2.osulogin.certificate.override"
    "PdfViewer:com.android.graphics.pdf.certificate.override"
    "SafetyCenterResources:com.android.safetycenter.resources.certificate.override"
    "ServiceConnectivityResources:com.android.connectivity.resources.certificate.override"
    "ServiceUwbResources:com.android.uwb.resources.certificate.override"
    "ServiceWifiResources:com.android.wifi.resources.certificate.override"
    "WifiDialog:com.android.wifi.dialog.certificate.override"
)

# ---------------------------------------------------------------------------
# Directory / subject setup (original flow)
# ---------------------------------------------------------------------------

if [ -d ~/.android-certs ]; then
    read -r -p "~/.android-certs already exists. Do you want to delete it and proceed? (y/n): " choice
    if [ "$choice" != "y" ]; then
        echo "Exiting script."
        exit 1
    fi
    rm -rf ~/.android-certs
fi

# Default subject fields (matches config.py's SUBJECTS_PARAMS)
SUBJ_C="US"
SUBJ_ST="California"
SUBJ_L="Mountain View"
SUBJ_O="Android"
SUBJ_OU="Android"
SUBJ_CN="Android"
SUBJ_EMAIL="android@android.com"

default_subject="/C=$SUBJ_C/ST=$SUBJ_ST/L=$SUBJ_L/O=$SUBJ_O/OU=$SUBJ_OU/CN=$SUBJ_CN/emailAddress=$SUBJ_EMAIL"

read -r -p "Do you want to use the default subject line: '$default_subject'? (y/n): " use_default

if [ "$use_default" != "y" ]; then
    echo "Please enter the following details:"
    read -r -p "Country Shortform (C): " SUBJ_C
    read -r -p "State/Province (ST): " SUBJ_ST
    read -r -p "Location/City (L): " SUBJ_L
    read -r -p "Organization (O): " SUBJ_O
    read -r -p "Organizational Unit (OU): " SUBJ_OU
    read -r -p "Common Name (CN): " SUBJ_CN
    read -r -p "Email Address (emailAddress): " SUBJ_EMAIL
fi

# Platform keys keep a single shared subject (CN as set above)
platform_subject="/C=$SUBJ_C/ST=$SUBJ_ST/L=$SUBJ_L/O=$SUBJ_O/OU=$SUBJ_OU/CN=$SUBJ_CN/emailAddress=$SUBJ_EMAIL"

# Check if make_key exists and is executable
if [ ! -x ./development/tools/make_key ]; then
    echo "Error: make_key tool not found or not executable at ./development/tools/make_key"
    exit 1
fi

# Locate avbtool (symlinked into repos as external/avb/avbtool.py)
avbtool=""
if [ -x ./external/avb/avbtool.py ]; then
    avbtool="./external/avb/avbtool.py"
elif command -v avbtool >/dev/null 2>&1; then
    avbtool="avbtool"
else
    echo "Warning: avbtool.py not found at ./external/avb/avbtool.py and 'avbtool' not on PATH."
    echo "AVB public key extraction will be skipped."
fi

# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

mkdir -p ~/.android-certs

# -- Platform keys (make_key, RSA 2048) --
for key_type in "${platform_keys[@]}"; do
    echo "Generating key: $key_type"
    ./development/tools/make_key "$HOME/.android-certs/$key_type" "$platform_subject" < /dev/null || true

    if [[ ! -f "$HOME/.android-certs/$key_type.pk8" || ! -f "$HOME/.android-certs/$key_type.x509.pem" ]]; then
        echo "Error: Key files for '$key_type' were not generated properly."
        exit 1
    fi
done

# -- APEX keys (raw openssl, RSA 4096, CN=apex name) --
for apex in "${apex_keys[@]}"; do
    echo "Generating APEX key: $apex"

    apex_subject="/C=$SUBJ_C/ST=$SUBJ_ST/L=$SUBJ_L/O=$SUBJ_O/OU=$SUBJ_OU/CN=$apex/emailAddress=$SUBJ_EMAIL"
    base="$HOME/.android-certs/$apex"
    pkey="$base.pem"
    x509="$base.certificate.override.x509.pem"
    pk8="$base.certificate.override.pk8"

    openssl genrsa -out "$pkey" "$RSA_APEX_KEY_SIZE" 2>/dev/null
    openssl req -new -x509 -sha256 -days "$CERT_DAYS" -set_serial 1 \
        -key "$pkey" -out "$x509" -subj "$apex_subject" 2>/dev/null
    openssl pkcs8 -in "$pkey" -topk8 -outform DER -out "$pk8" -nocrypt 2>/dev/null

    if [[ ! -f "$x509" || ! -f "$pk8" ]]; then
        echo "Error: APEX cert files for '$apex' were not generated properly."
        exit 1
    fi

    # AVB public key extraction (com.android.vndk uses .pubkey instead of .avbpubkey)
    if [ -n "$avbtool" ]; then
        avb_out="$base.avbpubkey"
        [ "$apex" = "com.android.vndk" ] && avb_out="$base.pubkey"
        echo "Extracting AVB public key: $(basename "$avb_out")"
        "$avbtool" extract_public_key --key "$pkey" --output "$avb_out"
    fi
done

# ---------------------------------------------------------------------------
# Move into place
# ---------------------------------------------------------------------------

mkdir -p "$destination_dir"
mv "$HOME/.android-certs/"* "$destination_dir"
rm -rf ~/.android-certs

# Convenience symlinks
# 'nfc' privapp is now signed with the com.android.nfcservices apex cert
ln -sf "com.android.nfcservices.certificate.override.pk8" "$destination_dir/nfc.pk8"
ln -sf "com.android.nfcservices.certificate.override.x509.pem" "$destination_dir/nfc.x509.pem"

# 'signed' (referenced by PRODUCT_EXTRA_RECOVERY_KEYS in keys.mk) reuses releasekey
ln -sf "releasekey.pk8" "$destination_dir/signed.pk8"
ln -sf "releasekey.x509.pem" "$destination_dir/signed.x509.pem"

echo "IMPORTANT: Please make a backup copy of your keys in '$destination_dir' as they are essential for signing your builds."

# ---------------------------------------------------------------------------
# keys.mk
# ---------------------------------------------------------------------------

# Print an array of "key:value" entries with a trailing " \" on every line
# except the last (which gets none), indented for a Makefile continuation.
print_mk_block() {
    local -n _entries="$1"
    local n=${#_entries[@]}
    local i
    for ((i = 0; i < n; i++)); do
        if ((i < n - 1)); then
            echo "    ${_entries[$i]} \\"
        else
            echo "    ${_entries[$i]}"
        fi
    done
}

apex_self_overrides=()
for apex in "${apex_keys[@]}"; do
    apex_self_overrides+=("$apex:$apex.certificate.override")
done

hardware_overrides=()
for apex in "${apex_hardware_keys[@]}"; do
    hardware_overrides+=("$apex:com.android.hardware.certificate.override")
done

cf_overrides=()
for apex in "${apex_cf_keys[@]}"; do
    cf_overrides+=("$apex:com.google.cf.certificate.override")
done

{
    echo "# DO NOT EDIT THIS FILE MANUALLY"
    echo
    echo "PRODUCT_CERTIFICATE_OVERRIDES := \\"
    print_mk_block apex_self_overrides
    echo
    echo "PRODUCT_CERTIFICATE_OVERRIDES += \\"
    print_mk_block hardware_overrides
    echo
    echo "PRODUCT_CERTIFICATE_OVERRIDES += \\"
    print_mk_block cf_overrides
    echo
    echo "PRODUCT_CERTIFICATE_OVERRIDES += \\"
    print_mk_block apex_app_keys
    echo
    echo "PRODUCT_DEFAULT_DEV_CERTIFICATE := $destination_dir/releasekey"
    echo "PRODUCT_EXTRA_RECOVERY_KEYS += $destination_dir/signed"
    echo 'PRODUCT_MAINLINE_BLUETOOTH_SEPOLICY_DEV_CERTIFICATES := $(dir $(PRODUCT_DEFAULT_DEV_CERTIFICATE))'
} > "$destination_dir/keys.mk"

# ---------------------------------------------------------------------------
# BUILD.bazel
# ---------------------------------------------------------------------------

cat > "$destination_dir/BUILD.bazel" <<EOF
filegroup(
    name = "android_certificate_directory",
    srcs = glob([
        "*.pk8",
        "*.pem",
        "*.avbpubkey",
        "*.pubkey",
    ]),
    visibility = ["//visibility:public"],
)
EOF

# ---------------------------------------------------------------------------
# Android.bp -- one android_app_certificate module per APEX key
# ---------------------------------------------------------------------------

{
    echo "// DO NOT EDIT THIS FILE MANUALLY"
    echo
    n=${#apex_keys[@]}
    for ((i = 0; i < n; i++)); do
        apex="${apex_keys[$i]}"
        cat <<EOF
android_app_certificate {
    name: "$apex.certificate.override",
    certificate: "$apex.certificate.override",
}
EOF
        ((i < n - 1)) && echo
    done
} > "$destination_dir/Android.bp"

# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

chmod -R 755 "$destination_dir"

echo "Key generation and setup completed successfully."
