Hash Suite Droid
==============

Hash Suite Droid is, as far as we're aware, the first multi-hash cracker developed specifically for Android devices (as compared to the rather rough unofficial builds of John the Ripper for Android).


Features highlight:

- UI optimizes to screen size: The UI changes depending on the screen size. For example, with small-screen smartphones Hash Suite Droid shows 3 tabs, whereas with tablets it shows all functionality on one screen.
- Cracking On: Pressing the power button while cracking shuts down the screen, but the cracking continues. Cracking also continues if the user starts another app. To stop the attack, users need to press the Stop action item or close Hash Suite Droid.
- Battery aware: Hash Suite Droid automatically stops attacks when the battery's charge drops below a user-defined threshold.
- Common "config.db" file: Users can import/export (interchange) the config.db file and use it either on the PC or on the phone or tablet. For example, users can begin an attack on their smartphone/tablet and finish it with Hash Suite for Windows on a PC, or vice versa.
- Many features from the PC version: Rules, compressed wordlists, ability to resume interrupted attacks, high performance, etc. This version has almost the same functionality as the PC version.


Requirements:

- Android 3.0 or newer.
- ARM CPU supporting armeabi-v7a.
- INTERNET permission to download wordlists.
- WRITE_EXTERNAL_STORAGE permission to export files.
- WAKE_LOCK permission to prevent Android from putting the CPU to sleep while cracking.


Missing features:

- 7-Zip compressed wordlist support (many other archive types are supported).
- Reports.
- GPU support (once we implement this, we expect to reach desktop CPU class performance on mobile GPUs).


Notice: This is a beta version. Please provide comments, suggestions, benchmark results and any other feedback.
