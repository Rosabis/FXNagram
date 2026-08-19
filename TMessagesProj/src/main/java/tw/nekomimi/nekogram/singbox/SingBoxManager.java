package tw.nekomimi.nekogram.singbox;

import android.net.ConnectivityManager;
import android.net.DnsResolver;
import android.net.Network;
import android.os.Build;
import android.os.CancellationSignal;
import android.system.ErrnoException;
import android.text.TextUtils;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.SharedConfig;

import java.io.File;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.nekohasekai.libbox.BoxService;
import io.nekohasekai.libbox.ExchangeContext;
import io.nekohasekai.libbox.InterfaceUpdateListener;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.LocalDNSTransport;
import io.nekohasekai.libbox.NetworkInterfaceIterator;
import io.nekohasekai.libbox.Notification;
import io.nekohasekai.libbox.PlatformInterface;
import io.nekohasekai.libbox.SetupOptions;
import io.nekohasekai.libbox.StringIterator;
import io.nekohasekai.libbox.TunOptions;
import io.nekohasekai.libbox.WIFIState;

public class SingBoxManager {

    private static final String TAG = "SingBoxManager";
    private static final int LOCAL_SOCKS_PORT = 11789;
    private static final int RCODE_NXDOMAIN = 3;
    private static final ExecutorService DNS_EXECUTOR = Executors.newCachedThreadPool();
    private static final ExecutorService LIFECYCLE_EXECUTOR = Executors.newSingleThreadExecutor();

    private static SingBoxManager instance;
    private volatile boolean running = false;
    private volatile String currentLink = "";
    private BoxService currentService;
    private final AtomicInteger lifecycleGeneration = new AtomicInteger();

    private static final PlatformInterface minimalPlatform = new PlatformInterface() {
        @Override
        public LocalDNSTransport localDNSTransport() { return androidLocalDnsTransport; }
        @Override
        public boolean usePlatformAutoDetectInterfaceControl() { return false; }
        @Override
        public void autoDetectInterfaceControl(int fd) {}
        @Override
        public int openTun(TunOptions options) { return -1; }
        @Override
        public boolean useProcFS() { return false; }
        @Override
        public int findConnectionOwner(int ipProtocol, String sourceAddress, int sourcePort, String destinationAddress, int destinationPort) { return -1; }
        @Override
        public void startDefaultInterfaceMonitor(InterfaceUpdateListener listener) {}
        @Override
        public void closeDefaultInterfaceMonitor(InterfaceUpdateListener listener) {}
        @Override
        public NetworkInterfaceIterator getInterfaces() {
            return new NetworkInterfaceIterator() {
                @Override
                public boolean hasNext() { return false; }
                @Override
                public io.nekohasekai.libbox.NetworkInterface next() { return null; }
            };
        }
        @Override
        public boolean underNetworkExtension() { return false; }
        @Override
        public boolean includeAllNetworks() { return false; }
        @Override
        public void clearDNSCache() {}
        @Override
        public WIFIState readWIFIState() { return Libbox.newWIFIState("", ""); }
        @Override
        public StringIterator systemCertificates() {
            return getSystemCertificates();
        }
        @Override
        public void writeLog(String message) {
            FileLog.d("sing-box: " + message);
        }
        @Override
        public int uidByPackageName(String packageName) { return -1; }
        @Override
        public void sendNotification(Notification notification) {}
        @Override
        public String packageNameByUid(int uid) { return ""; }
    };

    private static final LocalDNSTransport androidLocalDnsTransport = new LocalDNSTransport() {
        @Override
        public boolean raw() {
            return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q;
        }

        @Override
        public void exchange(ExchangeContext ctx, byte[] message) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                ctx.errorCode(RCODE_NXDOMAIN);
                return;
            }
            Network network = getActiveNetwork();
            if (network == null) {
                throw new IllegalStateException("missing active network");
            }
            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<Throwable> error = new AtomicReference<>();
            DnsResolver.getInstance().rawQuery(network, message, DnsResolver.FLAG_NO_RETRY,
                    DNS_EXECUTOR, new CancellationSignal(), new DnsResolver.Callback<byte[]>() {
                        @Override
                        public void onAnswer(byte[] answer, int rcode) {
                            try {
                                if (rcode == 0) {
                                    ctx.rawSuccess(answer);
                                } else {
                                    ctx.errorCode(rcode);
                                }
                            } finally {
                                latch.countDown();
                            }
                        }

                        @Override
                        public void onError(DnsResolver.DnsException e) {
                            try {
                                if (e.getCause() instanceof ErrnoException) {
                                    ctx.errnoCode(((ErrnoException) e.getCause()).errno);
                                } else {
                                    error.set(e);
                                }
                            } finally {
                                latch.countDown();
                            }
                        }
                    });
            awaitDnsResult(latch, error);
        }

        @Override
        public void lookup(ExchangeContext ctx, String networkName, String domain) {
            Network network = getActiveNetwork();
            if (network == null) {
                throw new IllegalStateException("missing active network");
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                lookupWithDnsResolver(ctx, network, networkName, domain);
                return;
            }
            try {
                ctx.success(joinAddresses(network.getAllByName(domain)));
            } catch (UnknownHostException e) {
                ctx.errorCode(RCODE_NXDOMAIN);
            }
        }
    };

    private static class EmptyStringIterator implements StringIterator {
        @Override
        public boolean hasNext() { return false; }
        @Override
        public String next() { return null; }
        @Override
        public int len() { return 0; }
    }

    private static class ListStringIterator implements StringIterator {
        private final List<String> items;
        private int index = 0;

        ListStringIterator(List<String> items) {
            this.items = items;
        }

        @Override
        public boolean hasNext() { return index < items.size(); }
        @Override
        public String next() { return hasNext() ? items.get(index++) : null; }
        @Override
        public int len() { return items.size(); }
    }

    private static volatile List<String> cachedSystemCertificates;

    private static Network getActiveNetwork() {
        ConnectivityManager connectivityManager = (ConnectivityManager) ApplicationLoader.applicationContext
                .getSystemService(android.content.Context.CONNECTIVITY_SERVICE);
        return connectivityManager != null ? connectivityManager.getActiveNetwork() : null;
    }

    private static void lookupWithDnsResolver(ExchangeContext ctx, Network network, String networkName, String domain) {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Throwable> error = new AtomicReference<>();
        DnsResolver.Callback<Collection<java.net.InetAddress>> callback = new DnsResolver.Callback<Collection<java.net.InetAddress>>() {
            @Override
            public void onAnswer(Collection<java.net.InetAddress> answer, int rcode) {
                try {
                    if (rcode == 0) {
                        ctx.success(joinAddresses(answer));
                    } else {
                        ctx.errorCode(rcode);
                    }
                } finally {
                    latch.countDown();
                }
            }

            @Override
            public void onError(DnsResolver.DnsException e) {
                try {
                    if (e.getCause() instanceof ErrnoException) {
                        ctx.errnoCode(((ErrnoException) e.getCause()).errno);
                    } else {
                        error.set(e);
                    }
                } finally {
                    latch.countDown();
                }
            }
        };
        int queryType = -1;
        if (networkName != null && networkName.endsWith("4")) {
            queryType = DnsResolver.TYPE_A;
        } else if (networkName != null && networkName.endsWith("6")) {
            queryType = DnsResolver.TYPE_AAAA;
        }
        if (queryType != -1) {
            DnsResolver.getInstance().query(network, domain, queryType, DnsResolver.FLAG_NO_RETRY,
                    DNS_EXECUTOR, new CancellationSignal(), callback);
        } else {
            DnsResolver.getInstance().query(network, domain, DnsResolver.FLAG_NO_RETRY,
                    DNS_EXECUTOR, new CancellationSignal(), callback);
        }
        awaitDnsResult(latch, error);
    }

    private static void awaitDnsResult(CountDownLatch latch, AtomicReference<Throwable> error) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
        Throwable throwable = error.get();
        if (throwable != null) {
            throw new RuntimeException(throwable);
        }
    }

    private static String joinAddresses(Collection<java.net.InetAddress> addresses) {
        StringBuilder builder = new StringBuilder();
        for (java.net.InetAddress address : addresses) {
            if (address == null || address.getHostAddress() == null) {
                continue;
            }
            if (builder.length() > 0) {
                builder.append('\n');
            }
            builder.append(address.getHostAddress());
        }
        return builder.toString();
    }

    private static String joinAddresses(java.net.InetAddress[] addresses) {
        StringBuilder builder = new StringBuilder();
        for (java.net.InetAddress address : addresses) {
            if (address == null || address.getHostAddress() == null) {
                continue;
            }
            if (builder.length() > 0) {
                builder.append('\n');
            }
            builder.append(address.getHostAddress());
        }
        return builder.toString();
    }

    private static StringIterator getSystemCertificates() {
        if (cachedSystemCertificates != null) {
            return new ListStringIterator(cachedSystemCertificates);
        }
        try {
            List<String> certs = new ArrayList<>();
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                java.security.cert.Certificate cert = ks.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    StringWriter sw = new StringWriter();
                    sw.write("-----BEGIN CERTIFICATE-----\n");
                    sw.write(android.util.Base64.encodeToString(
                            cert.getEncoded(),
                            android.util.Base64.NO_WRAP | android.util.Base64.DEFAULT));
                    sw.write("\n-----END CERTIFICATE-----\n");
                    certs.add(sw.toString());
                }
            }
            cachedSystemCertificates = certs;
            return new ListStringIterator(certs);
        } catch (Exception e) {
            FileLog.e(TAG + ": failed to load system certificates", e);
            return new EmptyStringIterator();
        }
    }

    public static synchronized SingBoxManager getInstance() {
        if (instance == null) {
            instance = new SingBoxManager();
        }
        return instance;
    }

    private SingBoxManager() {}

    public boolean isRunning() {
        return running;
    }

    public String getCurrentLink() {
        return currentLink;
    }

    public int getLocalSocksPort() {
        return LOCAL_SOCKS_PORT;
    }

    public boolean isSingBoxProxy(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null || TextUtils.isEmpty(proxyInfo.secret)) {
            return false;
        }
        String secret = proxyInfo.secret;
        return secret.startsWith("vless://") ||
               secret.startsWith("hysteria://") ||
               secret.startsWith("hysteria2://") ||
               secret.startsWith("hy2://") ||
               secret.startsWith("vmess://") ||
               secret.startsWith("vmess1://") ||
               secret.startsWith("trojan://") ||
               secret.startsWith("ss://") ||
               secret.startsWith("tuic://") ||
               secret.startsWith("naive+https://") ||
               secret.startsWith("naive+quic://") ||
               secret.startsWith("anytls://") ||
               secret.startsWith("shadowtls://");
    }

    public void start(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null || !isSingBoxProxy(proxyInfo)) {
            return;
        }
        String link = proxyInfo.secret;
        int generation;
        BoxService oldService;
        synchronized (this) {
            if (link.equals(currentLink)) {
                return;
            }
            running = false;
            currentLink = link;
            oldService = currentService;
            currentService = null;
            generation = lifecycleGeneration.incrementAndGet();
        }
        LIFECYCLE_EXECUTOR.execute(() -> startInternal(link, generation, oldService));
    }

    private void startInternal(String link, int generation, BoxService oldService) {
        BoxService service = null;
        try {
            closeService(oldService);

            if (generation != lifecycleGeneration.get()) {
                return;
            }

            String config = linkToConfig(link);
            if (config == null) {
                FileLog.e(TAG + ": failed to generate config for " + link);
                synchronized (this) {
                    if (generation == lifecycleGeneration.get()) {
                        currentLink = "";
                    }
                }
                return;
            }
            FileLog.d(TAG + ": starting sing-box for link = " + link);
            FileLog.d(TAG + ": generated config = " + config);

            File baseDir = new File(ApplicationLoader.applicationContext.getFilesDir(), "sing-box");
            baseDir.mkdirs();
            File tempDir = new File(baseDir, "temp");
            tempDir.mkdirs();

            SetupOptions setupOptions = new SetupOptions();
            setupOptions.setBasePath(baseDir.getAbsolutePath());
            setupOptions.setWorkingPath(tempDir.getAbsolutePath());
            setupOptions.setTempPath(new File(tempDir, "tmp").getAbsolutePath());
            Libbox.setup(setupOptions);

            service = Libbox.newService(config, minimalPlatform);
            service.start();
            synchronized (this) {
                if (generation == lifecycleGeneration.get()) {
                    currentService = service;
                    running = true;
                    service = null;
                }
            }
            FileLog.d(TAG + ": sing-box started for " + link.substring(0, Math.min(link.length(), 50)));
        } catch (Exception e) {
            FileLog.e(TAG + ": failed to start sing-box", e);
            synchronized (this) {
                if (generation == lifecycleGeneration.get()) {
                    running = false;
                    currentLink = "";
                }
            }
        } finally {
            closeService(service);
        }
    }

    public void ping(SharedConfig.ProxyInfo proxyInfo, long timeoutMs, PingCallback callback) {
        new Thread(() -> {
            long startTime = System.currentTimeMillis();
            try {
                startBlocking(proxyInfo);
                if (!running) {
                    AndroidUtilities.runOnUIThread(() -> callback.onResult(-1));
                    return;
                }
                java.net.Socket socket = new java.net.Socket();
                java.net.Proxy proxy = new java.net.Proxy(java.net.Proxy.Type.SOCKS,
                        new java.net.InetSocketAddress("127.0.0.1", LOCAL_SOCKS_PORT));
                socket.connect(new java.net.InetSocketAddress("149.154.167.50", 443), (int) timeoutMs);
                long pingTime = System.currentTimeMillis() - startTime;
                socket.close();
                AndroidUtilities.runOnUIThread(() -> callback.onResult(pingTime));
            } catch (Exception e) {
                FileLog.e(TAG + ": ping failed", e);
                AndroidUtilities.runOnUIThread(() -> callback.onResult(-1));
            }
        }).start();
    }

    public interface PingCallback {
        void onResult(long pingTime);
    }

    public void stop() {
        BoxService service;
        synchronized (this) {
            lifecycleGeneration.incrementAndGet();
            running = false;
            currentLink = "";
            service = currentService;
            currentService = null;
        }
        if (service != null) {
            LIFECYCLE_EXECUTOR.execute(() -> closeService(service));
        }
    }

    private static void closeService(BoxService service) {
        if (service == null) {
            return;
        }
        try {
            service.close();
        } catch (Exception e) {
            FileLog.e(TAG + ": failed to stop sing-box", e);
        }
    }

    private void startBlocking(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null || !isSingBoxProxy(proxyInfo)) {
            return;
        }
        String link = proxyInfo.secret;
        BoxService oldService;
        int generation;
        synchronized (this) {
            if (running && link.equals(currentLink)) {
                return;
            }
            running = false;
            currentLink = link;
            oldService = currentService;
            currentService = null;
            generation = lifecycleGeneration.incrementAndGet();
        }
        try {
            Future<?> future = LIFECYCLE_EXECUTOR.submit(() -> startInternal(link, generation, oldService));
            future.get();
        } catch (Exception e) {
            FileLog.e(TAG + ": failed to start sing-box for ping", e);
        }
    }

    public String linkToConfig(String link) {
        try {
            if (link.startsWith("vless://")) {
                return buildVlessConfig(link);
            } else if (link.startsWith("hysteria2://") || link.startsWith("hy2://")) {
                return buildHysteria2Config(link);
            } else if (link.startsWith("hysteria://")) {
                return buildHysteriaConfig(link);
            } else if (link.startsWith("trojan://")) {
                return buildTrojanConfig(link);
            } else if (link.startsWith("vmess://") || link.startsWith("vmess1://")) {
                return buildVmessConfig(link);
            } else if (link.startsWith("ss://")) {
                return buildShadowsocksConfig(link);
            } else if (link.startsWith("tuic://")) {
                return buildTuicConfig(link);
            } else if (link.startsWith("naive+https://") || link.startsWith("naive+quic://")) {
                return buildNaiveConfig(link);
            } else if (link.startsWith("anytls://")) {
                return buildAnytlsConfig(link);
            } else if (link.startsWith("shadowtls://")) {
                return buildShadowtlsConfig(link);
            }
        } catch (Exception e) {
            FileLog.e(TAG + ": failed to parse link", e);
        }
        return null;
    }

    private String buildBaseConfig(String outbound) throws Exception {
        JSONObject config = new JSONObject();

        JSONObject log = new JSONObject();
        log.put("level", "debug");
        config.put("log", log);

        JSONObject dns = new JSONObject();
        JSONArray dnsServers = new JSONArray();
        JSONObject localDns = new JSONObject();
        localDns.put("type", "local");
        localDns.put("tag", "local");
        dnsServers.put(localDns);
        dns.put("servers", dnsServers);
        dns.put("final", "local");
        config.put("dns", dns);

        JSONArray inbounds = new JSONArray();
        JSONObject socksIn = new JSONObject();
        socksIn.put("type", "socks");
        socksIn.put("tag", "socks-in");
        socksIn.put("listen", "127.0.0.1");
        socksIn.put("listen_port", LOCAL_SOCKS_PORT);
        inbounds.put(socksIn);
        config.put("inbounds", inbounds);

        JSONArray outbounds = new JSONArray();
        outbounds.put(new JSONObject(outbound));
        JSONObject direct = new JSONObject();
        direct.put("type", "direct");
        direct.put("tag", "direct");
        outbounds.put(direct);
        config.put("outbounds", outbounds);

        JSONObject route = new JSONObject();
        route.put("final", "proxy");
        route.put("default_domain_resolver", "local");
        config.put("route", route);

        return config.toString();
    }

    private String buildVlessConfig(String link) throws Exception {
        android.net.Uri uri = android.net.Uri.parse(link);
        JSONObject outbound = new JSONObject();
        outbound.put("type", "vless");
        outbound.put("server", uri.getHost());
        int port = uri.getPort();
        if (port == -1) port = 443;
        outbound.put("server_port", port);
        outbound.put("uuid", uri.getUserInfo());

        String security = uri.getQueryParameter("security");
        if (security == null) security = "none";
        JSONObject tls = new JSONObject();
        tls.put("enabled", "tls".equals(security) || "reality".equals(security));
        if ("tls".equals(security) || "reality".equals(security)) {
            String sni = uri.getQueryParameter("sni");
            if (sni != null) tls.put("server_name", sni);
            String fp = uri.getQueryParameter("fp");
            if (fp != null) {
                JSONObject utls = new JSONObject();
                utls.put("enabled", true);
                utls.put("fingerprint", fp);
                tls.put("utls", utls);
            }
            if ("reality".equals(security)) {
                JSONObject reality = new JSONObject();
                reality.put("enabled", true);
                String pbk = uri.getQueryParameter("pbk");
                if (pbk != null) reality.put("public_key", pbk);
                String sid = uri.getQueryParameter("sid");
                if (sid != null) reality.put("short_id", sid);
                tls.put("reality", reality);
            }
            String alpn = uri.getQueryParameter("alpn");
            if (alpn != null) {
                JSONArray alpnArr = new JSONArray();
                for (String a : alpn.split(",")) {
                    alpnArr.put(a.trim());
                }
                tls.put("alpn", alpnArr);
            }
            if ("true".equals(uri.getQueryParameter("allowInsecure"))) {
                tls.put("insecure", true);
            }
        }
        outbound.put("tls", tls);

        String type = uri.getQueryParameter("type");
        if (type == null) type = "tcp";
        if (!"tcp".equals(type)) {
            JSONObject transport = new JSONObject();
            if ("ws".equals(type)) {
                transport.put("type", "ws");
                String path = uri.getQueryParameter("path");
                if (path != null) transport.put("path", URLDecoder.decode(path, "UTF-8"));
                String host = uri.getQueryParameter("host");
                if (host != null) {
                    JSONObject headers = new JSONObject();
                    headers.put("Host", host);
                    transport.put("headers", headers);
                }
            } else if ("grpc".equals(type)) {
                transport.put("type", "grpc");
                String serviceName = uri.getQueryParameter("serviceName");
                if (serviceName != null) transport.put("service_name", serviceName);
            } else if ("http".equals(type) || "h2".equals(type)) {
                transport.put("type", "http");
                String path = uri.getQueryParameter("path");
                if (path != null) transport.put("path", path);
                String host = uri.getQueryParameter("host");
                if (host != null) transport.put("host", new JSONArray().put(host));
            }
            if (transport.length() > 0) outbound.put("transport", transport);
        }

        String flow = uri.getQueryParameter("flow");
        if (flow != null) outbound.put("flow", flow);

        outbound.put("tag", "proxy");
        return buildBaseConfig(outbound.toString());
    }

    private String buildHysteria2Config(String link) throws Exception {
        android.net.Uri uri = android.net.Uri.parse(link);
        JSONObject outbound = new JSONObject();
        outbound.put("type", "hysteria2");
        outbound.put("server", uri.getHost());

        int port = uri.getPort();
        if (port == -1) {
            String encodedAuthority = uri.getEncodedAuthority();
            if (encodedAuthority != null) {
                int colonIdx = encodedAuthority.lastIndexOf(':');
                if (colonIdx != -1) {
                    String portStr = encodedAuthority.substring(colonIdx + 1);
                    if (portStr.contains("-")) {
                        JSONArray serverPorts = new JSONArray();
                        serverPorts.put(portStr.replace("-", ":"));
                        outbound.put("server_ports", serverPorts);
                    } else {
                        try {
                            port = Integer.parseInt(portStr);
                        } catch (NumberFormatException ignored) {
                            port = 443;
                        }
                    }
                }
            }
            if (!outbound.has("server_ports")) {
                if (port == -1) port = 443;
                outbound.put("server_port", port);
            }
        } else {
            outbound.put("server_port", port);
        }

        String hopInterval = uri.getQueryParameter("hop_interval");
        if (hopInterval != null) outbound.put("hop_interval", hopInterval);

        String password = uri.getUserInfo();
        if (password != null) outbound.put("password", URLDecoder.decode(password, "UTF-8"));

        String up = uri.getQueryParameter("up");
        if (up == null) up = uri.getQueryParameter("up_mbps");
        if (up != null) {
            try {
                outbound.put("up_mbps", Integer.parseInt(up.replaceAll("[^0-9]", "")));
            } catch (NumberFormatException e) {
                outbound.put("up_mbps", 100);
            }
        } else {
            outbound.put("up_mbps", 100);
        }

        String down = uri.getQueryParameter("down");
        if (down == null) down = uri.getQueryParameter("down_mbps");
        if (down != null) {
            try {
                outbound.put("down_mbps", Integer.parseInt(down.replaceAll("[^0-9]", "")));
            } catch (NumberFormatException e) {
                outbound.put("down_mbps", 100);
            }
        } else {
            outbound.put("down_mbps", 100);
        }

        JSONObject tls = new JSONObject();
        tls.put("enabled", true);
        String sni = uri.getQueryParameter("sni");
        if (sni != null) tls.put("server_name", sni);
        else tls.put("server_name", uri.getHost());
        if ("1".equals(uri.getQueryParameter("insecure")) || "true".equals(uri.getQueryParameter("insecure"))) {
            tls.put("insecure", true);
        }
        outbound.put("tls", tls);

        String obfs = uri.getQueryParameter("obfs");
        if (obfs != null) {
            JSONObject obfsObj = new JSONObject();
            obfsObj.put("type", obfs);
            String obfsPassword = uri.getQueryParameter("obfs-password");
            if (obfsPassword != null) obfsObj.put("password", obfsPassword);
            outbound.put("obfs", obfsObj);
        }

        outbound.put("tag", "proxy");
        return buildBaseConfig(outbound.toString());
    }

    private String buildHysteriaConfig(String link) throws Exception {
        android.net.Uri uri = android.net.Uri.parse(link);
        JSONObject outbound = new JSONObject();
        outbound.put("type", "hysteria");
        outbound.put("server", uri.getHost());
        int port = uri.getPort();
        if (port == -1) port = 443;
        outbound.put("server_port", port);

        String up = uri.getQueryParameter("up");
        if (up == null) up = uri.getQueryParameter("up_mbps");
        if (up != null) {
            try {
                outbound.put("up_mbps", Integer.parseInt(up.replaceAll("[^0-9]", "")));
            } catch (NumberFormatException e) {
                outbound.put("up_mbps", 100);
            }
        } else {
            outbound.put("up_mbps", 100);
        }

        String down = uri.getQueryParameter("down");
        if (down == null) down = uri.getQueryParameter("down_mbps");
        if (down != null) {
            try {
                outbound.put("down_mbps", Integer.parseInt(down.replaceAll("[^0-9]", "")));
            } catch (NumberFormatException e) {
                outbound.put("down_mbps", 100);
            }
        } else {
            outbound.put("down_mbps", 100);
        }

        String auth = uri.getQueryParameter("auth");
        if (auth != null) outbound.put("auth_str", URLDecoder.decode(auth, "UTF-8"));

        JSONObject tls = new JSONObject();
        tls.put("enabled", true);
        String sni = uri.getQueryParameter("peer") != null ? uri.getQueryParameter("peer") : uri.getQueryParameter("sni");
        if (sni != null) tls.put("server_name", sni);
        else tls.put("server_name", uri.getHost());
        if ("1".equals(uri.getQueryParameter("insecure")) || "true".equals(uri.getQueryParameter("insecure"))) {
            tls.put("insecure", true);
        }
        outbound.put("tls", tls);

        outbound.put("tag", "proxy");
        return buildBaseConfig(outbound.toString());
    }

    private String buildTrojanConfig(String link) throws Exception {
        android.net.Uri uri = android.net.Uri.parse(link);
        JSONObject outbound = new JSONObject();
        outbound.put("type", "trojan");
        outbound.put("server", uri.getHost());
        int port = uri.getPort();
        if (port == -1) port = 443;
        outbound.put("server_port", port);

        String password = uri.getUserInfo();
        if (password == null) password = uri.getQueryParameter("password");
        if (password != null) outbound.put("password", URLDecoder.decode(password, "UTF-8"));

        JSONObject tls = new JSONObject();
        tls.put("enabled", true);
        String sni = uri.getQueryParameter("sni");
        if (sni != null) tls.put("server_name", sni);
        else tls.put("server_name", uri.getHost());
        if ("true".equals(uri.getQueryParameter("allowInsecure"))) {
            tls.put("insecure", true);
        }
        outbound.put("tls", tls);

        String type = uri.getQueryParameter("type");
        if ("ws".equals(type)) {
            JSONObject transport = new JSONObject();
            transport.put("type", "ws");
            String path = uri.getQueryParameter("path");
            if (path != null) transport.put("path", URLDecoder.decode(path, "UTF-8"));
            String host = uri.getQueryParameter("host");
            if (host != null) {
                JSONObject headers = new JSONObject();
                headers.put("Host", host);
                transport.put("headers", headers);
            }
            outbound.put("transport", transport);
        } else if ("grpc".equals(type)) {
            JSONObject transport = new JSONObject();
            transport.put("type", "grpc");
            String serviceName = uri.getQueryParameter("serviceName");
            if (serviceName != null) transport.put("service_name", serviceName);
            outbound.put("transport", transport);
        }

        outbound.put("tag", "proxy");
        return buildBaseConfig(outbound.toString());
    }

    private String buildVmessConfig(String link) throws Exception {
        if (link.startsWith("vmess://")) {
            String encoded = link.substring("vmess://".length());
            byte[] decoded = android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP);
            JSONObject obj = new JSONObject(new String(decoded, "UTF-8"));

            JSONObject outbound = new JSONObject();
            outbound.put("type", "vmess");
            outbound.put("server", obj.optString("add", ""));
            outbound.put("server_port", obj.optInt("port", 443));
            outbound.put("uuid", obj.optString("id", ""));
            outbound.put("alter_id", obj.optInt("aid", 0));
            String scy = obj.optString("scy", "auto");
            if (!"auto".equals(scy)) outbound.put("security", scy);

            JSONObject tls = new JSONObject();
            String tlsVal = obj.optString("tls", "");
            tls.put("enabled", "tls".equals(tlsVal));
            if ("tls".equals(tlsVal)) {
                String sni = obj.optString("sni", "");
                if (!TextUtils.isEmpty(sni)) tls.put("server_name", sni);
                String alpn = obj.optString("alpn", "");
                if (!TextUtils.isEmpty(alpn)) {
                    JSONArray alpnArr = new JSONArray();
                    for (String a : alpn.split(",")) alpnArr.put(a.trim());
                    tls.put("alpn", alpnArr);
                }
            }
            outbound.put("tls", tls);

            String net = obj.optString("net", "tcp");
            if ("ws".equals(net)) {
                JSONObject transport = new JSONObject();
                transport.put("type", "ws");
                String path = obj.optString("path", "");
                if (!TextUtils.isEmpty(path)) transport.put("path", path);
                String host = obj.optString("host", "");
                if (!TextUtils.isEmpty(host)) {
                    JSONObject headers = new JSONObject();
                    headers.put("Host", host);
                    transport.put("headers", headers);
                }
                outbound.put("transport", transport);
            } else if ("grpc".equals(net)) {
                JSONObject transport = new JSONObject();
                transport.put("type", "grpc");
                String serviceName = obj.optString("path", "");
                if (!TextUtils.isEmpty(serviceName)) transport.put("service_name", serviceName);
                outbound.put("transport", transport);
            } else if ("h2".equals(net)) {
                JSONObject transport = new JSONObject();
                transport.put("type", "http");
                String path = obj.optString("path", "");
                if (!TextUtils.isEmpty(path)) transport.put("path", path);
                String host = obj.optString("host", "");
                if (!TextUtils.isEmpty(host)) transport.put("host", new JSONArray().put(host));
                outbound.put("transport", transport);
            }

            outbound.put("tag", "proxy");
            return buildBaseConfig(outbound.toString());
        }
        return null;
    }

    private String buildShadowsocksConfig(String link) throws Exception {
        String remaining = link.substring("ss://".length());
        int hashIdx = remaining.indexOf('#');
        if (hashIdx != -1) remaining = remaining.substring(0, hashIdx);

        String encodedPart;
        String serverPart;
        int atIdx = remaining.indexOf('@');
        if (atIdx != -1) {
            encodedPart = remaining.substring(0, atIdx);
            serverPart = remaining.substring(atIdx + 1);
        } else {
            return null;
        }

        byte[] methodPassword = android.util.Base64.decode(encodedPart, android.util.Base64.NO_WRAP);
        String mpStr = new String(methodPassword, "UTF-8");
        int colonIdx = mpStr.indexOf(':');
        String method = mpStr.substring(0, colonIdx);
        String password = mpStr.substring(colonIdx + 1);

        String[] serverPort = serverPart.split(":");
        String server = serverPort[0];
        int port = serverPort.length > 1 ? Integer.parseInt(serverPort[1]) : 8388;

        JSONObject outbound = new JSONObject();
        outbound.put("type", "shadowsocks");
        outbound.put("server", server);
        outbound.put("server_port", port);
        outbound.put("method", method);
        outbound.put("password", password);
        outbound.put("tag", "proxy");

        return buildBaseConfig(outbound.toString());
    }

    private String buildTuicConfig(String link) throws Exception {
        android.net.Uri uri = android.net.Uri.parse(link);
        JSONObject outbound = new JSONObject();
        outbound.put("type", "tuic");
        outbound.put("server", uri.getHost());
        int port = uri.getPort();
        if (port == -1) port = 443;
        outbound.put("server_port", port);

        String userInfo = uri.getUserInfo();
        if (userInfo != null && userInfo.contains(":")) {
            int colonIdx = userInfo.indexOf(':');
            outbound.put("uuid", userInfo.substring(0, colonIdx));
            outbound.put("password", URLDecoder.decode(userInfo.substring(colonIdx + 1), "UTF-8"));
        } else if (userInfo != null) {
            outbound.put("uuid", userInfo);
        }

        String congestionControl = uri.getQueryParameter("congestion_control");
        if (congestionControl != null) outbound.put("congestion_control", congestionControl);

        String udpRelayMode = uri.getQueryParameter("udp_relay_mode");
        if (udpRelayMode != null) outbound.put("udp_relay_mode", udpRelayMode);

        String zeroRtt = uri.getQueryParameter("zero_rtt_handshake");
        if ("1".equals(zeroRtt) || "true".equals(zeroRtt)) outbound.put("zero_rtt_handshake", true);

        JSONObject tls = new JSONObject();
        tls.put("enabled", true);
        String sni = uri.getQueryParameter("sni");
        if (sni != null) tls.put("server_name", sni);
        else tls.put("server_name", uri.getHost());
        String alpn = uri.getQueryParameter("alpn");
        if (alpn != null) {
            JSONArray alpnArr = new JSONArray();
            for (String a : alpn.split(",")) alpnArr.put(a.trim());
            tls.put("alpn", alpnArr);
        }
        if ("1".equals(uri.getQueryParameter("allow_insecure")) || "true".equals(uri.getQueryParameter("allow_insecure"))
                || "1".equals(uri.getQueryParameter("insecure")) || "true".equals(uri.getQueryParameter("insecure"))) {
            tls.put("insecure", true);
        }
        outbound.put("tls", tls);

        outbound.put("tag", "proxy");
        return buildBaseConfig(outbound.toString());
    }

    private String buildNaiveConfig(String link) throws Exception {
        android.net.Uri uri = android.net.Uri.parse(link);
        JSONObject outbound = new JSONObject();
        outbound.put("type", "naive");
        outbound.put("server", uri.getHost());
        int port = uri.getPort();
        if (port == -1) port = 443;
        outbound.put("server_port", port);

        String userInfo = uri.getUserInfo();
        if (userInfo != null) {
            int colonIdx = userInfo.indexOf(':');
            if (colonIdx != -1) {
                outbound.put("username", URLDecoder.decode(userInfo.substring(0, colonIdx), "UTF-8"));
                outbound.put("password", URLDecoder.decode(userInfo.substring(colonIdx + 1), "UTF-8"));
            } else {
                outbound.put("username", URLDecoder.decode(userInfo, "UTF-8"));
            }
        }

        JSONObject tls = new JSONObject();
        tls.put("enabled", true);
        String peer = uri.getQueryParameter("peer");
        if (peer != null) tls.put("server_name", peer);
        else {
            String sni = uri.getQueryParameter("sni");
            if (sni != null) tls.put("server_name", sni);
        }
        if ("1".equals(uri.getQueryParameter("insecure")) || "true".equals(uri.getQueryParameter("insecure"))) {
            tls.put("insecure", true);
        }
        String alpn = uri.getQueryParameter("alpn");
        if (alpn != null) {
            JSONArray alpnArr = new JSONArray();
            for (String a : alpn.split(",")) alpnArr.put(a.trim());
            tls.put("alpn", alpnArr);
        }
        outbound.put("tls", tls);

        if (link.startsWith("naive+quic://")) {
            outbound.put("quic", true);
        }

        outbound.put("tag", "proxy");
        return buildBaseConfig(outbound.toString());
    }

    private String buildAnytlsConfig(String link) throws Exception {
        android.net.Uri uri = android.net.Uri.parse(link);
        JSONObject outbound = new JSONObject();
        outbound.put("type", "anytls");
        outbound.put("server", uri.getHost());
        int port = uri.getPort();
        if (port == -1) port = 443;
        outbound.put("server_port", port);

        String password = uri.getUserInfo();
        if (password != null) outbound.put("password", URLDecoder.decode(password, "UTF-8"));

        JSONObject tls = new JSONObject();
        String security = uri.getQueryParameter("security");
        if (security == null) security = "tls";
        tls.put("enabled", "tls".equals(security) || "reality".equals(security));
        if ("tls".equals(security) || "reality".equals(security)) {
            String sni = uri.getQueryParameter("sni");
            if (sni != null) tls.put("server_name", sni);
            else tls.put("server_name", uri.getHost());
            String fp = uri.getQueryParameter("fp");
            if (fp != null) {
                JSONObject utls = new JSONObject();
                utls.put("enabled", true);
                utls.put("fingerprint", fp);
                tls.put("utls", utls);
            }
            if ("reality".equals(security)) {
                JSONObject reality = new JSONObject();
                reality.put("enabled", true);
                String pbk = uri.getQueryParameter("pbk");
                if (pbk != null) reality.put("public_key", pbk);
                String sid = uri.getQueryParameter("sid");
                if (sid != null) reality.put("short_id", sid);
                tls.put("reality", reality);
            }
            String alpn = uri.getQueryParameter("alpn");
            if (alpn != null) {
                JSONArray alpnArr = new JSONArray();
                for (String a : alpn.split(",")) alpnArr.put(a.trim());
                tls.put("alpn", alpnArr);
            }
            if ("1".equals(uri.getQueryParameter("allow_insecure")) || "true".equals(uri.getQueryParameter("allow_insecure"))
                    || "1".equals(uri.getQueryParameter("insecure")) || "true".equals(uri.getQueryParameter("insecure"))) {
                tls.put("insecure", true);
            }
        }
        outbound.put("tls", tls);

        outbound.put("tag", "proxy");
        return buildBaseConfig(outbound.toString());
    }

    private String buildShadowtlsConfig(String link) throws Exception {
        android.net.Uri uri = android.net.Uri.parse(link);
        JSONObject outbound = new JSONObject();
        outbound.put("type", "shadowtls");
        outbound.put("server", uri.getHost());
        int port = uri.getPort();
        if (port == -1) port = 443;
        outbound.put("server_port", port);

        String versionStr = uri.getQueryParameter("version");
        if (versionStr != null) {
            outbound.put("version", Integer.parseInt(versionStr));
        } else {
            outbound.put("version", 3);
        }

        String password = uri.getUserInfo();
        if (password == null) password = uri.getQueryParameter("password");
        if (password != null) outbound.put("password", URLDecoder.decode(password, "UTF-8"));

        JSONObject tls = new JSONObject();
        tls.put("enabled", true);
        String sni = uri.getQueryParameter("sni");
        if (sni != null) tls.put("server_name", sni);
        else tls.put("server_name", uri.getHost());
        String fp = uri.getQueryParameter("fp");
        if (fp != null) {
            JSONObject utls = new JSONObject();
            utls.put("enabled", true);
            utls.put("fingerprint", fp);
            tls.put("utls", utls);
        }
        String alpn = uri.getQueryParameter("alpn");
        if (alpn != null) {
            JSONArray alpnArr = new JSONArray();
            for (String a : alpn.split(",")) alpnArr.put(a.trim());
            tls.put("alpn", alpnArr);
        }
        if ("1".equals(uri.getQueryParameter("insecure")) || "true".equals(uri.getQueryParameter("insecure"))) {
            tls.put("insecure", true);
        }
        outbound.put("tls", tls);

        outbound.put("tag", "proxy");
        return buildBaseConfig(outbound.toString());
    }
}
