# keep the dnstt aar bridge classes (jni/native reflection)
-keep class mobile.** { *; }
-dontwarn mobile.**

-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**
