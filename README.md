Hash Suite Droid
==============

Hash Suite Droid is, as far as we're aware, the first multi-hash cracker developed specifically for Android devices (as compared to the rather rough unofficial builds of John the Ripper for Android).


Features highlight:

- UI optimizes to screen size: The UI changes depending on the screen size. For example, with small-screen smartphones Hash Suite Droid shows 3 tabs, whereas with tablets it shows all functionality on one screen.
- Cracking On: Pressing the power button while cracking shuts down the screen, but the cracking continues. Cracking also continues if the user starts another app. To stop the attack, users need to press the Stop action item or close Hash Suite Droid.
- Battery aware: Hash Suite Droid automatically stops attacks when the battery's charge drops below or the temperature raise above a user-defined threshold.
- Common "config.db" file: Users can import/export (interchange) the config.db file and use it either on the PC or on the phone or tablet. For example, users can begin an attack on their smartphone/tablet and finish it with Hash Suite for Windows on a PC, or vice versa.
- Features similar to the PC version: Rules, compressed wordlists, ability to resume interrupted attacks, high performance (hand-crafted ARM NEON assembly code, GPU cracking via OpenCL), etc. Reports is the only feature currently not supported.


Requirements:

- Android 4.0.3 or newer.
- ARM CPU supporting armeabi-v7a or arm64-v8a.
- INTERNET permission to download wordlists.
- READ_EXTERNAL_STORAGE permission to import files.
- WRITE_EXTERNAL_STORAGE permission to export files.
- WAKE_LOCK permission to prevent Android from putting the CPU to sleep while cracking.


Please provide comments, suggestions, benchmark results (found in /sdcard/Android/data/com.hashsuite.droid/files/benchmark.csv) and any other feedback.
More details in the webpage: http://hashsuite.openwall.net/Android
