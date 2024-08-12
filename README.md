# Silent Chrome - Silently Install Web Store Extensions on Google Chrome on MacOS
Author: AsaurusRex

## Purpose
This is a project showcasing hows how to silently install Web Store extensions on Google Chrome on MacOS. See the blog post on silently installing Web Store Extensions: https://medium.com/@marcusthebrody/silently-install-chrome-extensions-macos-version-becf164679c2

## Requirements:
This code is designed to run with Python3, but you might want to modify it depending on what your target MacOS system has.

## Technique
To run this technique:

1. Download your desired extension on a test/attacker controlled laptop. Navigate to the Secure Preferences file and carve out the desired json blob for your extension (see extension_json above for an example of what this would look like for cookiebro).

2. Paste the json blob into the extension_json variable in the script above, and make sure to strip out the first_install_time and last_update_time fields, replacing them as in the example with the current time.

3. Run this script on the target machine. It will write the desired extension to the Secure Preferences file. But your extension will not be loaded yet.

4. Kill the currently running Google Chrome process/processes; e.g. use the command killall “Google Chrome”. When Chrome is launched again, the extension will be loaded, but in a corrupted state.

5. You will need to kill Chrome one more time, which will trigger Chrome to repair the extension the next time it is started up. It appears that this is because different versions of Chrome, and different machines, will replace the json blob in Secure Preferences in non-predictable way (which will mess up your HMAC and Super_Mac, causing the corrupted state). I plan to research this further to see if there is a way to avoid it.

6. Once Chrome has repaired the extension, it will be installed as normal in the browser and will persist every time the browser is loaded. While it is not ideal to have to kill Chrome twice, at least we now have extension persistence!

## Future Works

Abuse existing extensions which will always exist, like Google Hangouts.

Mess more with the Preferences file vs the Secure Preferences File

See how we can load custom extensions vs those that exist in the Web Store.

Figure out how to avoid the “repair” problem — see if there is a consistent json blob structure which is universal.


