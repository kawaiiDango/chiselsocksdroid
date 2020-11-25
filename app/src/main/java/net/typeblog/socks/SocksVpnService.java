package net.typeblog.socks;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.AsyncTask;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Log;

import net.typeblog.socks.util.Routes;
import net.typeblog.socks.util.Utility;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Objects;
import java.util.Queue;

import static net.typeblog.socks.util.Constants.*;
import static net.typeblog.socks.BuildConfig.DEBUG;

public class SocksVpnService extends VpnService {
    class VpnBinder extends IVpnService.Stub {
        @Override
        public boolean isRunning() {
            return mRunning;
        }

        @Override
        public void stop() {
            stopMe();
        }
    }

    private static final String TAG = SocksVpnService.class.getSimpleName();

    private ParcelFileDescriptor mInterface;
    private boolean mRunning = false;
    private final IBinder mBinder = new VpnBinder();
    private Notification.Builder nb;
    private Notification.BigTextStyle bigTextStyle;
    private NotificationManager notificationManager;
    private final int NOTIFICATION_ID = 1;
    private final int NOTIFICATION_ERR_ID = 2;
    private String NOTIFICATION_CHANNEL_ID = BuildConfig.APPLICATION_ID;
    private String NOTIFICATION_CHANNEL_ERR_ID = BuildConfig.APPLICATION_ID+".err";
    private final Queue<String> chiselLogQ = new LinkedList<>();

    private BroadcastReceiver bReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent.getAction().equals(INTENT_DISCONNECT))
                stopMe();
        }
    };

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        if (DEBUG) {
            Log.d(TAG, "starting");
        }

        if (intent == null) {
            return START_STICKY;
        }

        if (mRunning) {
            return START_STICKY;
        }

        final String name = intent.getStringExtra(INTENT_NAME);
        final String chiselServer = intent.getStringExtra(INTENT_PREFIX + PREF_CHISEL_SERVER);

        notificationManager = (NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        // Notifications on Oreo and above need a channel
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel1 = new NotificationChannel(NOTIFICATION_CHANNEL_ID,
                    getString(R.string.channel_connected), NotificationManager.IMPORTANCE_NONE);
            NotificationChannel channel2 = new NotificationChannel(NOTIFICATION_CHANNEL_ERR_ID,
                    getString(R.string.channel_err), NotificationManager.IMPORTANCE_HIGH);
            Objects.requireNonNull(notificationManager).createNotificationChannel(channel1);
            Objects.requireNonNull(notificationManager).createNotificationChannel(channel2);
            nb = new Notification.Builder(this, NOTIFICATION_CHANNEL_ID);
        } else
            nb = new Notification.Builder(this);
        bigTextStyle = new Notification.BigTextStyle().bigText(null);

        PendingIntent dcPi = PendingIntent.getBroadcast(getApplicationContext(), 1,
                new Intent(INTENT_DISCONNECT), PendingIntent.FLAG_UPDATE_CURRENT);
        Notification.Action dcAction = new Notification.Action(0, getString(R.string.disconnect), dcPi);
        // Create the notification

        PendingIntent contentIntent = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), PendingIntent.FLAG_UPDATE_CURRENT);
        String title = getString(R.string.notify_msg_connecting, name);
        nb.setContentTitle(title)
                .setPriority(Notification.PRIORITY_LOW)
                .setSmallIcon(R.drawable.vd_progress)
                .setContentIntent(contentIntent)
                .addAction(dcAction)
                .setStyle(bigTextStyle
                    .setBigContentTitle(title));

        startForeground(NOTIFICATION_ID, nb.build());
        notificationManager.cancel(NOTIFICATION_ERR_ID);

        if (chiselServer != null)
            new ChiselTask().execute(intent); //connect socks after chisel
        else {
            startProxyIfNotRunning(intent);
            nb.setContentTitle(getString(R.string.notify_msg_connected, name))
                    .setSmallIcon(R.drawable.vd_socks_outline)
                    .setPriority(Notification.PRIORITY_MIN);
            bigTextStyle.setBigContentTitle(getString(R.string.notify_msg_connected, name));
            notificationManager.notify(NOTIFICATION_ID, nb.build());
        }

        IntentFilter filter = new IntentFilter();
        filter.addAction(INTENT_DISCONNECT);
        registerReceiver(bReceiver, filter);
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        super.onRevoke();
        stopMe();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        stopMe();
    }

    private void stopMe() {
        stopForeground(true);

        try {
            unregisterReceiver(bReceiver);
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "bReceiver not registered");
        }

        Utility.killPidFile(getFilesDir() + "/chisel.pid");
        Utility.killPidFile(getFilesDir() + "/tun2socks.pid");
        Utility.killPidFile(getFilesDir() + "/pdnsd.pid");

        getApplicationContext().sendBroadcast(new Intent(INTENT_DISCONNECTED));

        try {
            if (mInterface != null) {
                System.jniclose(mInterface.getFd());
                mInterface.close();
            }
            stopSelf();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void configure(String name, String route, boolean perApp, boolean bypass, String[] apps, boolean ipv6) {
        Builder b = new Builder();
        b.setMtu(1500)
                .setSession(name)
                .addAddress("26.26.26.1", 24)
                .addDnsServer("8.8.8.8");

        if (ipv6) {
            // Route all IPv6 traffic
            b.addAddress("fdfe:dcba:9876::1", 126)
                    .addRoute("::", 0);
        }

        Routes.addRoutes(this, b, route);

        // Add the default DNS
        // Note that this DNS is just a stub.
        // Actual DNS requests will be redirected through pdnsd.
        b.addRoute("8.8.8.8", 32);

        // Do app routing
        if (!perApp) {
            // Just bypass myself
            try {
                b.addDisallowedApplication(BuildConfig.APPLICATION_ID);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            if (bypass) {
                // First, bypass myself
                try {
                    b.addDisallowedApplication(BuildConfig.APPLICATION_ID);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                for (String p : apps) {
                    if (TextUtils.isEmpty(p))
                        continue;

                    try {
                        b.addDisallowedApplication(p.trim());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } else {
                for (String p : apps) {
                    if (TextUtils.isEmpty(p) || p.trim().equals(BuildConfig.APPLICATION_ID)) {
                        continue;
                    }

                    try {
                        b.addAllowedApplication(p.trim());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }

        mInterface = b.establish();
    }

    private void start(int fd, String server, int port, String user, String passwd, String dns, int dnsPort, boolean ipv6, String udpgw) {
        // Start DNS daemon first
        Utility.makePdnsdConf(this, dns, dnsPort);

        Utility.exec(String.format(Locale.US, "%s/libpdnsd.so -c %s/pdnsd.conf",
                getApplicationInfo().nativeLibraryDir, getFilesDir()));

        String command = String.format(Locale.US,
                "%s/libtun2socks.so --netif-ipaddr 26.26.26.2"
                        + " --netif-netmask 255.255.255.0"
                        + " --socks-server-addr %s:%d"
                        + " --tunfd %d"
                        + " --tunmtu 1500"
                        + " --loglevel 3"
                        + " --pid %s/tun2socks.pid"
                        + " --sock %s/sock_path"
                , getApplicationInfo().nativeLibraryDir, server, port, fd, getFilesDir(), getApplicationInfo().dataDir);

        if (user != null) {
            command += " --username " + user;
            command += " --password " + passwd;
        }

        if (ipv6) {
            command += " --netif-ip6addr fdfe:dcba:9876::2";
        }

        command += " --dnsgw 26.26.26.1:8091";

        if (udpgw != null) {
            command += " --udpgw-remote-server-addr " + udpgw;
        }

        if (DEBUG) {
            Log.d(TAG, command);
        }

        if (Utility.exec(command) != 0) {
            stopMe();
            return;
        }

        // Try to send the Fd through socket.
        int i = 0;
        while (i < 5) {
            if (System.sendfd(fd, getApplicationInfo().dataDir + "/sock_path") != -1) {
                mRunning = true;
                getApplicationContext().sendBroadcast(new Intent(INTENT_CONNECTED));
                return;
            }

            i++;

            try {
                Thread.sleep(1000 * i);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // Should not get here. Must be a failure.
        stopMe();
    }

    private void startProxyIfNotRunning(Intent intent){
        if (mInterface == null) {
            final String name = intent.getStringExtra(INTENT_NAME);
            final String server = intent.getStringExtra(INTENT_SERVER);
            final int port = intent.getIntExtra(INTENT_PORT, 1080);
            final String username = intent.getStringExtra(INTENT_USERNAME);
            final String passwd = intent.getStringExtra(INTENT_PASSWORD);
            final String route = intent.getStringExtra(INTENT_ROUTE);
            final String dns = intent.getStringExtra(INTENT_DNS);
            final int dnsPort = intent.getIntExtra(INTENT_DNS_PORT, 53);
            final boolean perApp = intent.getBooleanExtra(INTENT_PER_APP, false);
            final boolean appBypass = intent.getBooleanExtra(INTENT_APP_BYPASS, false);
            final String[] appList = intent.getStringArrayExtra(INTENT_APP_LIST);
            final boolean ipv6 = intent.getBooleanExtra(INTENT_IPV6_PROXY, false);
            final String udpgw = intent.getStringExtra(INTENT_UDP_GW);
            // Create an fd.
            configure(name, route, perApp, appBypass, appList, ipv6);

            if (DEBUG)
                Log.d(TAG, "fd: " + mInterface.getFd());

            if (mInterface != null)
                start(mInterface.getFd(), server, port, username, passwd, dns, dnsPort, ipv6, udpgw);
        }
    }

    class ChiselTask extends AsyncTask<Intent, String, Boolean>{

        @Override
        protected Boolean doInBackground(Intent... intents) {
            Intent intent = intents[0];
            final String chiselServer = intent.getStringExtra(INTENT_PREFIX + PREF_CHISEL_SERVER);
            if (chiselServer == null)
                return true;
            final String name = intent.getStringExtra(INTENT_NAME);
            final int port = intent.getIntExtra(INTENT_PORT, 1080);
            final String chiselAdditionalRemotes = intent.getStringExtra(INTENT_PREFIX + PREF_CHISEL_ADDITIONAL_REMOTES);
            final String chiselUsername = intent.getStringExtra(INTENT_PREFIX + PREF_CHISEL_USERNAME);
            final String chiselPassword = intent.getStringExtra(INTENT_PREFIX + PREF_CHISEL_PASSWORD);
            final String chiselFingerprint = intent.getStringExtra(INTENT_PREFIX + PREF_CHISEL_FINGERPRINT);
            final String chiselHeaders = intent.getStringExtra(INTENT_PREFIX + PREF_CHISEL_HEADERS);
            int chiselMRC = intent.getIntExtra(INTENT_PREFIX + PREF_CHISEL_MAX_RETRY_COUNT, -1);
            final int chiselMRI = intent.getIntExtra(INTENT_PREFIX + PREF_CHISEL_MAX_RETRY_INTERVAL, -1);

            boolean chiselConnected = false;
            ArrayList<String> chiselCommands = new ArrayList<>();
            chiselCommands.add(getApplicationInfo().nativeLibraryDir + "/libchisel.so");
            chiselCommands.add("client");
            chiselCommands.add("--pid");
            chiselCommands.add("--keepalive");
            chiselCommands.add("30s");
            if (!chiselUsername.equals("") && !chiselPassword.equals("")) {
                chiselCommands.add("--auth");
                chiselCommands.add(chiselUsername + ":" + chiselPassword);
            }
            if (chiselMRC < 0) {
                chiselMRC = 5;
                chiselCommands.add("--max-retry-count");
                chiselCommands.add("" + chiselMRC);
            }
            if (chiselMRI > 0) {
                chiselCommands.add("--max-retry-interval");
                chiselCommands.add(chiselMRI + "s");
            }
            if (!chiselFingerprint.equals("")) {
                chiselCommands.add("--fingerprint");
                chiselCommands.add(chiselFingerprint);
            }
            if (!chiselHeaders.equals("")) {
                for (String line : chiselHeaders.split("\n")) {
                    if (line.contains(":")) {
                        chiselCommands.add("--header");
                        chiselCommands.add(line);
                    }
                }
            }

            chiselCommands.add(chiselServer);
            chiselCommands.add(port + ":socks");
            if (!chiselAdditionalRemotes.equals(""))
                for (String remote : chiselAdditionalRemotes.split(" "))
                    chiselCommands.add(remote);
            try {
                String[] arr = new String[chiselCommands.size()];
                Process p = Runtime.getRuntime().exec(chiselCommands.toArray(arr), null, getFilesDir());
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getErrorStream()));
                String line;
                while((line = br.readLine()) != null) {
                    chiselLogQ.add(line);
                    if (chiselLogQ.size()>4)
                        chiselLogQ.remove();
                    if (line.contains("Connected") && !chiselConnected) {
                        chiselConnected = true;
                        startProxyIfNotRunning(intent);

                        nb.setContentTitle(getString(R.string.notify_msg_connected, name))
                                .setSmallIcon(R.drawable.vd_socks_outline)
                                .setPriority(Notification.PRIORITY_MIN);
                        bigTextStyle.setBigContentTitle(getString(R.string.notify_msg_connected, name));
                    } else if (line.contains("Retrying in") && chiselConnected) {
                        chiselConnected = false;
                        nb.setContentTitle(getString(R.string.notify_msg_connecting, name))
                                .setSmallIcon(R.drawable.vd_progress)
                                .setPriority(Notification.PRIORITY_LOW);
                        bigTextStyle.setBigContentTitle(getString(R.string.notify_msg_connecting, name));
                    }
                    nb.setStyle(bigTextStyle.bigText(line));
                    nb.setContentText(line);
                    notificationManager.notify(NOTIFICATION_ID, nb.build());
//                    if (chiselConnected)
//                        break;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (!chiselConnected){
                StringBuilder log = new StringBuilder();
                for(String line : chiselLogQ)
                    log.append(line).append("\n");
                Notification.Builder nbErr;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    nbErr = new Notification.Builder(getApplicationContext(), NOTIFICATION_CHANNEL_ERR_ID);
                } else
                    nbErr = new Notification.Builder(getApplicationContext());
                PendingIntent contentIntent = PendingIntent.getActivity(getApplicationContext(), 0,
                        new Intent(getApplicationContext(), MainActivity.class), PendingIntent.FLAG_UPDATE_CURRENT);
                nbErr.setContentTitle(getString(R.string.notify_msg_failed, name))
                        .setPriority(Notification.PRIORITY_HIGH)
                        .setSmallIcon(R.drawable.vd_exclaim)
                        .setAutoCancel(true)
                        .setContentIntent(contentIntent)
                        .setContentText(log)
                        .setStyle(bigTextStyle
                                .setBigContentTitle(getString(R.string.notify_msg_failed, name))
                                .bigText(log));

                notificationManager.notify(NOTIFICATION_ERR_ID, nbErr.build());
                stopMe();
                return false;
            }
            return true;
        }

        @Override
        protected void onPostExecute(Boolean aBoolean) {
            super.onPostExecute(aBoolean);
        }
    }
}
