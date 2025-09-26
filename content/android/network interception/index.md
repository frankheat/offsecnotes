---
title: "Network interception"
weight: 4
description: "Learn Android network interception techniques for pentesting. Covers cleartext traffic, SSL interception, certificate handling, and bypassing restrictions with VPNs and transparent proxies."
---

# Network interception

In android there are several ways to make HTTP requests. For example using `HttpURLConnection` (low-level API built into Java), `OkHttp` (A popular third-party library) etc.

---

## Cleartext Traffic

Starting from Android 9 (API level 28), HTTP clients like `URLConnection`, `Cronet`, and `OkHttp` enforce the use of HTTPS, thus disabling cleartext traffic by default. However, it's important to note that other HTTP client libraries, such as `Ktor`, may not enforce these restrictions \[[↗](https://developer.android.com/privacy-and-security/risks/cleartext-communications#risk-http)].

However, if developers explicitly set `usesCleartextTraffic=true` \[[↗](https://developer.android.com/reference/android/security/NetworkSecurityPolicy#isCleartextTrafficPermitted\(\))] in the manifest or network security configuration \[[↗](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted)], cleartext traffic is permitted.

---

## SSL interception

To intercept TLS/SSL traffic, the proxy certificate must be trusted by the device. Android recognizes two types of certificates: **user** certificates and **system** certificates. Applications can explicitly configure which certificate types they trust using **network security config**.

Example `network_security_config.xml`:

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

{{< details summary="Default configuration" >}}

Source \[[↗](https://developer.android.com/privacy-and-security/security-config#CustomTrust)].

Android 7.0 (API level 24) and higher.

```xml
<base-config>
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

Android 6.0 (API level 23) and lower.

```xml
<base-config>
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

{{< /details >}}

If the application doesn't accept user certificates you need to install system certificate (or patching network security config).

### User Certificate

Install it in the user CA store via Android settings. In general apps trust user certificates if it targets Android 6 (API 23) or lower, or network security config allows it.


{{< details summary="Install user certificate guide" >}}

1. Download the certificate from `http://<burp_proxy_listener>`
2. Go on setting, search certificate and install by selected it

**Install on older Android ≤ 11**

If you try to install this certificate, it'll be grayed out and you'll not be able to install it. To install it you need to change its extension.

```sh
mv cacert.der cacert.crt
```

{{< /details >}}


{{< hint style=notes >}}
Keep in mind that Android accepts both **DER** and **PEM** formats. When you install a certificate as a **user** (regardless of the format), Android automatically converts it to **DER** format.
{{< /hint >}}


### System Certificate

**Requirement**: rooted device.

* Rooted physical device
* Rooted emulator
* Android Virtual Device (AVD) using non Google Play Store emulator image (If you need it you could [root it](https://8ksec.io/rooting-an-android-emulator-for-mobile-security-testing/))

{{< details summary="Install system certificate guide (temporary)" >}}

This method use a **temporary RAM-based filesystem** (tmpfs) to override the system certificate directory in memory without actually modifying the read-only system image.

1. Export certificate in DER format from Burp Suite
2. By default, all Android system certificates are in PEM format. While Android can handle certificates in DER format, I recommend converting them to PEM to ensure broader compatibility. Some libraries may behave inconsistently with DER certificates. For example, I've observed that Flutter applications fail to work properly with DER-formatted certificates. In this step, you'll convert the certificate from **DER to PEM** format and rename it using its subject hash.


    ```sh
    openssl x509 -inform DER -in cacert.der -out cacert.pem
    mv cacert.pem $(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1).0
    ```

3. Create a folder on the device

    ```sh
    adb shell

    mkdir /data/local/tmp/cacerts-added/
    ```

4. Push the certificate in the created folder

    ```sh
    adb push <subject_hash.0> /data/local/tmp/cacerts-added/
    ```

5. Add your custom cert to the same folder

    ```sh
    cp /system/etc/security/cacerts/* /data/local/tmp/cacerts-added/
    ```

6. Switch to root user

    ```sh
    su
    ```

7. Mount tmpfs over system certs

    ```sh    
    mount -t tmpfs tmpfs /system/etc/security/cacerts
    ```

8. Copy combined certs into the tmpfs mount

    ```sh
    cp /data/local/tmp/cacerts-added/* /system/etc/security/cacerts/
    ```

9. Update the perms & SELinux context labels

    ```sh
    chown root:root /system/etc/security/cacerts/*
    chmod 644 /system/etc/security/cacerts/*
    chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
    ```

The next time you could just run the step 6-9.

{{< /details >}}

<details>

{{< details summary="Install system certificate on Android ≥ 14 guide" >}}

1. Install the proxy certificate as a regular user certificate
2. `adb shell`
3. Run [this script](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/) by Tim Perry

    ```sh
    # Create a separate temp directory, to hold the current certificates
    # Otherwise, when we add the mount we can't read the current certs anymore.
    mkdir -p -m 700 /data/local/tmp/tmp-ca-copy

    # Copy out the existing certificates
    cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/tmp-ca-copy/

    # Create the in-memory mount on top of the system certs folder
    mount -t tmpfs tmpfs /system/etc/security/cacerts

    # Copy the existing certs back into the tmpfs, so we keep trusting them
    mv /data/local/tmp/tmp-ca-copy/* /system/etc/security/cacerts/

    # Copy our new cert in, so we trust that too
    cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

    # Update the perms & selinux context labels
    chown root:root /system/etc/security/cacerts/*
    chmod 644 /system/etc/security/cacerts/*
    chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

    # Deal with the APEX overrides, which need injecting into each namespace:

    # First we get the Zygote process(es), which launch each app
    ZYGOTE_PID=$(pidof zygote || true)
    ZYGOTE64_PID=$(pidof zygote64 || true)
    # N.b. some devices appear to have both!

    # Apps inherit the Zygote's mounts at startup, so we inject here to ensure
    # all newly started apps will see these certs straight away:
    for Z_PID in "$ZYGOTE_PID" "$ZYGOTE64_PID"; do
        if [ -n "$Z_PID" ]; then
            nsenter --mount=/proc/$Z_PID/ns/mnt -- \
                /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
        fi
    done

    # Then we inject the mount into all already running apps, so they
    # too see these CA certs immediately:

    # Get the PID of every process whose parent is one of the Zygotes:
    APP_PIDS=$(
        echo "$ZYGOTE_PID $ZYGOTE64_PID" | \
        xargs -n1 ps -o 'PID' -P | \
        grep -v PID
    )

    # Inject into the mount namespace of each of those apps:
    for PID in $APP_PIDS; do
        nsenter --mount=/proc/$PID/ns/mnt -- \
            /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts &
    done
    wait # Launched in parallel - wait for completion here

    echo "System certificate injected"
    ```

{{< /details >}}

### Patching Network Security Config

1. Unpack the apk

    ```sh
    apktool d target.apk
    ```

2. Modify the `AndroidManifest.xml` to add a `networkSecurityConfig` (`xml/network_security_config.xml`). If it's already present edit the file.

    **AndroidManifest.xml**

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <manifest ... >
        <application android:networkSecurityConfig="@xml/network_security_config"
                        ... >
            ...
        </application>
    </manifest>
    ```

    **network_security_config.xml**

    ```xml
    <!-- Example -->
    <network-security-config>
        <base-config>
            <trust-anchors>
                <certificates src="system" />
                <certificates src="user" />
            </trust-anchors>
        </base-config>
    </network-security-config>
    ```

3. Repack & sign the apk

    ```sh
    # Repack
    apktool b
    # Sign
    java -jar uber-apk-signer.jar -apk <app_name>.apk
    ```

   {{< hint style=notes >}}
   Unpacking and repacking an app can break stuff.
   {{< /hint >}}

---

## Intercepting Without Proxy Support

If you configure an HTTP proxy in Android settings, you can intercept network traffic. However;

* Connections made directly via TCP sockets bypass the proxy and cannot be intercepted.
* Applications may bypass the HTTP proxy settings if the developer configures them to disallow proxy usage. E.g. with **OkHttp**:

    ```java
    OkHttpClient client = new OkHttpClient.Builder()
        .proxy(java.net.Proxy.NO_PROXY) // Disables proxy usage
        .build();
    ```

* Also framework like **Flutter** and **Xamarin** application does not respect system proxy.

### Android Studio emulator

**Requirement**: the proxy certificate must be installed in the system certificate store.

In Android Studio, you can configure a global proxy for an emulated device by going to the device’s **Settings > Proxy -> Manual proxy configuration**.
In the host name field set burp suite proxy with `http` protocol: e.g. `http://192.168.1.90` and port number.

{{< hint style=warning >}}
If **your proxy is unreachable**, try changing the emulator version. You can find other versions here: https://developer.android.com/studio/emulator_archive.
{{< /hint >}}


### HTTP Interception with VPN (Rethink app)

{{< hint style=warning >}}
This method is not recommended when using the Android Studio emulator. Strange things could happen. 
{{< /hint >}}

**Requirement**: the proxy certificate must be installed in the system certificate store.

If the proxy settings are ignored, use an Android VPN service app to intercept app traffic. You can use the open-source RethinkDNS app \[[↗](https://play.google.com/store/apps/details?id=com.celzero.bravedns)].

Steps:

1. Set DNS settings to "System DNS"
2. Add an HTTP(S) CONNECT proxy (your `http://burpsuiteip:port`)
3. Start the VPN service

### DNS Spoofing & Transparent Proxy (Rethink app)

{{< hint style=warning >}}
This method is not recommended when using the Android Studio emulator. Strange things could happen. 
{{< /hint >}}

**Requirement**: The proxy certificate must be installed in the system certificate store.

Before starting, you need to bind Burp to a privileged port.

{{< details summary="Binding Burp to a privileged port (with authbind)" >}}

Reference: \[[↗](https://www.mwells.org/coding/2016/authbind-port-80-443/)].

```sh
sudo touch /etc/authbind/byport/443
sudo chown $USER:$USER /etc/authbind/byport/443
sudo chmod 755 /etc/authbind/byport/443

authbind --deep java -Djava.net.preferIPv4Stack=true -jar burpsuite.jar
```

{{< /details >}}

1. We need some kind of DNS server where we can control the IP. Example `dnsmasq.conf`:

    ```sh
    address=/target.com/192.168.1.50
    log-queries
    ```

2. Run `dnsmasq` with docker:

    ```sh
    docker pull andyshinn/dnsmasq
    docker run --name my-dnsmasq --rm -it -p 0.0.0.0:53:53/udp -v /tmp/dnsmasq.conf:/etc/dnsmasq.conf andyshinn/dnsmasq
    ```

3. Enforce DNS usage using Android's VPN feature with tools like RethinkDNS.

   * From "configure" -> "DNS" -> Change DNS settings to "Other DNS"
   * Select "DNS Proxy"
   * Create a new entry pointing at your local DNS server host

4. Finally, configure your proxy tool for invisible proxying. Burp will act as an HTTP(S) server, parse the `HOST` header, and forward requests. Ensure an invisible proxy listener is set on ports 443 and 80.

   {{< details summary="Invisible proxying" >}}

   **Normal Proxy**\
   In a normal proxy, the client (e.g., a browser or app) is explicitly configured to use the proxy. This means the client intentionally routes traffic through the proxy. Thus:

   * The client is aware of the existence of the proxy.
   * HTTPS requires the client to accept the certificate generated by the proxy (MITM).
   * The request contains both the relative path (/path) and the full address (e.g. `GET http://www.example.com/path HTTP/1.1`)

   **Invisible Proxy**\
   An [invisible proxy](https://portswigger.net/burp/documentation/desktop/tools/proxy/invisible) operates without the client being explicitly configured to use it. This is useful when the client does not support proxy configurations. Therefore, the client remains unaware of the proxy. However:

   With plain HTTP, a proxy-style request looks like this:

   ```http
   GET http://example.org/foo.php HTTP/1.1
   Host: example.org
   ```

   A non-proxy-style request looks like this:

   ```http
   GET /foo.php HTTP/1.1
   Host: example.org
   ```

   Proxies usually use the full URL in the first line to determine the destination, ignoring the `Host` header. In invisible proxying, Burp parses the `Host` header from non-proxy-style requests to determine the destination.

   {{< /details >}}
