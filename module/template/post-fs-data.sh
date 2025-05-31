#!/system/bin/sh
# shellcheck disable=SC2034
MODDIR=${0%/*}

MODULE_MIN_MAGISK_VERSION=27005

MODULE_MIN_ZYGISKSU_VERSION=497
MODULE_MIN_REZYGISK_VERSION=361

HAS_ZYGISKSU=false
HAS_REZYGISK=false

rm -f /data/adb/nohello/no_clr_ptracemsg

if [ -d "/data/adb/modules/zygisksu" ]; then
  if [ ! -f "/data/adb/modules/zygisksu/disable" ]; then
    HAS_ZYGISKSU=true
    ZYGISKSU_VERSION=$(grep versionCode /data/adb/modules/zygisksu/module.prop | sed 's/versionCode=//g')
    if [ -z "$ZYGISKSU_VERSION" ]; then
      touch "$MODDIR/disable"
    elif [ "$ZYGISKSU_VERSION" -lt "$MODULE_MIN_ZYGISKSU_VERSION" ]; then
      touch "$MODDIR/disable"
    elif [ "$ZYGISKSU_VERSION" -ge 521 ]; then
      touch /data/adb/nohello/no_clr_ptracemsg
      touch /data/adb/nohello/no_dirtyro_ar
    fi
  fi
fi

if [ -d "/data/adb/modules/rezygisk" ]; then
  if [ ! -f "/data/adb/modules/rezygisk/disable" ]; then
    HAS_REZYGISK=true
    REZYGISK_VERSION=$(grep versionCode /data/adb/modules/rezygisk/module.prop | sed 's/versionCode=//g')
    if [ -z "$REZYGISK_VERSION" ]; then
      touch "$MODDIR/disable"
    elif [ "$REZYGISK_VERSION" -lt "$MODULE_MIN_REZYGISK_VERSION" ]; then
      touch "$MODDIR/disable"
    elif [ "$REZYGISK_VERSION" -ge 362 ]; then
      touch /data/adb/nohello/no_clr_ptracemsg
    fi
  fi
fi

if [ "$HAS_ZYGISKSU" = true ] && [ "$HAS_REZYGISK" = true ]; then
  touch "$MODDIR/disable"
fi

if [ "$HAS_ZYGISKSU" = false ] && [ "$HAS_REZYGISK" = false ]; then
  MAGISK_VERSION="$(magisk -V)"
  if [ -z "$MAGISK_VERSION" ]; then
    touch "$MODDIR/disable"
  elif [ "$MAGISK_VERSION" -lt "$MODULE_MIN_MAGISK_VERSION" ]; then
    touch "$MODDIR/disable"
  fi
fi

if [ ! -f /data/adb/post-fs-data.d/.nohello_cleanup.sh ]; then
  mkdir -p /data/adb/post-fs-data.d
  cat "$MODDIR/cleanup.sh" > /data/adb/post-fs-data.d/.nohello_cleanup.sh
  chmod +x /data/adb/post-fs-data.d/.nohello_cleanup.sh
fi
