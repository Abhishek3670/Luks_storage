#!/bin/bash
# Automated permission tests for LUKS Web Manager
# Requires: curl, jq

BASE_URL="http://127.0.0.1:8081"
COOKIE_JAR="cookies.txt"

function login() {
  USER="$1"
  PASS="$2"
  curl -s -c $COOKIE_JAR -X POST "$BASE_URL/login" \
    -d "username=$USER" -d "password=$PASS" -o /dev/null
}

function upload_test() {
  USER="$1"; PASS="$2"; PATH="$3"; DESC="$4"
  login "$USER" "$PASS"
  # Simulate upload (no file, just check permission logic)
  RESPONSE=$(curl -s -b $COOKIE_JAR -F "current_path=$PATH" -F "files=@/etc/hosts" "$BASE_URL/upload")
  if echo "$RESPONSE" | grep -qi 'permission'; then
    echo "[FAIL] $DESC: Permission denied as expected."
  elif echo "$RESPONSE" | grep -qi 'success'; then
    echo "[PASS] $DESC: Upload succeeded."
  else
    echo "[INFO] $DESC: Response: $RESPONSE"
  fi
}

function delete_test() {
  USER="$1"; PASS="$2"; PATH="$3"; FILE="$4"; DESC="$5"
  login "$USER" "$PASS"
  # Simulate delete (file must exist for real test)
  RESPONSE=$(curl -s -b $COOKIE_JAR -X POST -H "Content-Type: application/json" \
    -d "{\"item_name\": \"$FILE\", \"current_path\": \"$PATH\"}" "$BASE_URL/delete_json")
  if echo "$RESPONSE" | grep -qi 'permission'; then
    echo "[FAIL] $DESC: Permission denied as expected."
  elif echo "$RESPONSE" | grep -qi 'success' && echo "$RESPONSE" | grep -qi 'true'; then
    echo "[PASS] $DESC: Delete succeeded."
  else
    echo "[INFO] $DESC: Response: $RESPONSE"
  fi
}

# Test cases
# user1: write/delete on /testfolder, inherited for /testfolder/subfolder
# user2: read-only on /testfolder, write/delete on /testfolder/subfolder
# admin: all permissions

# Upload tests
upload_test user1 password "/testfolder" "user1 upload to /testfolder (should PASS)"
upload_test user2 password "/testfolder" "user2 upload to /testfolder (should FAIL)"
upload_test user1 password "/testfolder/subfolder" "user1 upload to /testfolder/subfolder (should PASS)"
upload_test user2 password "/testfolder/subfolder" "user2 upload to /testfolder/subfolder (should PASS)"
upload_test user1 password "/randomfolder" "user1 upload to /randomfolder (should FAIL)"
upload_test user2 password "/randomfolder" "user2 upload to /randomfolder (should FAIL)"
upload_test admin password "/testfolder" "admin upload to /testfolder (should PASS)"

# Delete tests (assumes testfile.txt exists in each folder)
delete_test user1 password "/testfolder" "testfile.txt" "user1 delete in /testfolder (should PASS)"
delete_test user2 password "/testfolder" "testfile.txt" "user2 delete in /testfolder (should FAIL)"
delete_test user1 password "/testfolder/subfolder" "testfile.txt" "user1 delete in /testfolder/subfolder (should PASS)"
delete_test user2 password "/testfolder/subfolder" "testfile.txt" "user2 delete in /testfolder/subfolder (should PASS)"
delete_test user1 password "/randomfolder" "testfile.txt" "user1 delete in /randomfolder (should FAIL)"
delete_test user2 password "/randomfolder" "testfile.txt" "user2 delete in /randomfolder (should FAIL)"
delete_test admin password "/testfolder" "testfile.txt" "admin delete in /testfolder (should PASS)"

rm -f $COOKIE_JAR 