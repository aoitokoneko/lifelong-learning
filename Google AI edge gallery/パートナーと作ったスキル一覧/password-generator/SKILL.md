---
name: password-generator
description: Generate strong passwords with customizable length and character types (uppercase, lowercase, numbers, symbols).
metadata:
  homepage: https://github.com/google-ai-edge/gallery
---

# Password Generator

## Instructions

Call the `run_js` tool with the following exact parameters:
- script name: index.html
- data: A JSON string with the following fields:
  - length: Integer. The desired password length (default: 12, min: 5, max: 32).
  - use_caps: Boolean. Whether to include uppercase letters A-Z (default: true).
  - use_low: Boolean. Whether to include lowercase letters a-z (default: true).
  - use_num: Boolean. Whether to include numbers 0-9 (default: true).
  - use_sym: Boolean. Whether to include symbols and special characters (default: true).

If the user does not specify certain options, use the default values.
