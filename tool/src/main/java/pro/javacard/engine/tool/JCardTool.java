// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.tool;

import apdu4j.remote.AbstractTCPAdapter;
import apdu4j.remote.JCSDKClient;
import apdu4j.remote.JCSDKServer;
import apdu4j.remote.JSONAdapter;
import apdu4j.remote.VSmartCardClient;
import com.licel.jcardsim.base.InstallSpec;
import javacard.framework.Applet;
import javacard.framework.SystemException;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.bouncycastle.util.encoders.Hex;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.NonBlockingReader;
import pro.javacard.capfile.CAPFile;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.data.BitField;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class JCardTool {
    static OptionParser parser = new OptionParser();

    // Generic options
    static OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "help"), "Show this help").forHelp();
    static OptionSpec<Void> OPT_VERSION = parser.acceptsAll(Arrays.asList("V", "version"), "Show version");
    static OptionSpec<Void> OPT_CONTROL = parser.acceptsAll(Arrays.asList("c", "control"), "Start control interface");

    // VSmartCard options
    static OptionSpec<Void> OPT_VSMARTCARD = parser.accepts("vsmartcard", "Run a VSmartCard client");
    static OptionSpec<Integer> OPT_VSMARTCARD_PORT = parser.accepts("vsmartcard-port", "VSmartCard port").withRequiredArg().ofType(Integer.class).defaultsTo(VSmartCardClient.DEFAULT_VSMARTCARD_PORT);
    static OptionSpec<String> OPT_VSMARTCARD_HOST = parser.accepts("vsmartcard-host", "VSmartCard host").withRequiredArg().ofType(String.class).defaultsTo(VSmartCardClient.DEFAULT_VSMARTCARD_HOST);
    static OptionSpec<String> OPT_VSMARTCARD_ATR = parser.accepts("vsmartcard-atr", "VSmartCard ATR").withRequiredArg().ofType(String.class).defaultsTo(AbstractTCPAdapter.DEFAULT_ATR_HEX);
    static OptionSpec<String> OPT_VSMARTCARD_PROTOCOL = parser.accepts("vsmartcard-protocol", "VSmartCard protocol").withRequiredArg().ofType(String.class).defaultsTo("*");

    // Second VSmartCard options (for dual-interface simulation, e.g. contact + contactless)
    static OptionSpec<Void> OPT_VSMARTCARD2 = parser.accepts("vsmartcard2", "Run a second VSmartCard client");
    static OptionSpec<Integer> OPT_VSMARTCARD2_PORT = parser.accepts("vsmartcard2-port", "Second VSmartCard port").withRequiredArg().ofType(Integer.class).defaultsTo(VSmartCardClient.DEFAULT_VSMARTCARD_PORT + 1);
    static OptionSpec<String> OPT_VSMARTCARD2_HOST = parser.accepts("vsmartcard2-host", "Second VSmartCard host").withRequiredArg().ofType(String.class).defaultsTo(VSmartCardClient.DEFAULT_VSMARTCARD_HOST);
    static OptionSpec<String> OPT_VSMARTCARD2_ATR = parser.accepts("vsmartcard2-atr", "Second VSmartCard ATR").withRequiredArg().ofType(String.class).defaultsTo(AbstractTCPAdapter.DEFAULT_ATR_HEX);
    static OptionSpec<String> OPT_VSMARTCARD2_PROTOCOL = parser.accepts("vsmartcard2-protocol", "Second VSmartCard protocol").withRequiredArg().ofType(String.class).defaultsTo("T=CL");

    // Oracle options
    static OptionSpec<Void> OPT_JCSDK = parser.accepts("jcsdk", "Run a JCSDK server");
    static OptionSpec<Integer> OPT_JCSDK_PORT = parser.accepts("jcsdk-port", "JCSDK port").withRequiredArg().ofType(Integer.class).defaultsTo(JCSDKServer.DEFAULT_JCSDK_PORT);
    static OptionSpec<String> OPT_JCSDK_HOST = parser.accepts("jcsdk-host", "JCSDK host").withRequiredArg().ofType(String.class).defaultsTo(JCSDKServer.DEFAULT_JCSDK_HOST);
    static OptionSpec<String> OPT_JCSDK_ATR = parser.accepts("jcsdk-atr", "JCSDK ATR").withRequiredArg().ofType(String.class).defaultsTo(AbstractTCPAdapter.DEFAULT_ATR_HEX);
    static OptionSpec<String> OPT_JCSDK_PROTOCOL = parser.accepts("jcsdk-protocol", "JCSDK protocol").withRequiredArg().ofType(String.class).defaultsTo("*");

    // JSON adapter options
    static OptionSpec<Void> OPT_JSON = parser.accepts("json", "Run a JSON adapter");
    static OptionSpec<Integer> OPT_JSON_PORT = parser.accepts("json-port", "JSON adapter port").withRequiredArg().ofType(Integer.class).defaultsTo(JSONAdapter.DEFAULT_JSON_PORT);
    static OptionSpec<String> OPT_JSON_HOST = parser.accepts("json-host", "JSON adapter host").withRequiredArg().ofType(String.class).defaultsTo(JSONAdapter.DEFAULT_JSON_HOST);

    // Passthrough
    static OptionSpec<String> OPT_PASSTHROUGH_HOST = parser.accepts("passthrough-host", "JCSDK simulator host").withRequiredArg().ofType(String.class);

    // Generic override.
    static OptionSpec<String> OPT_ATR = parser.accepts("atr", "ATR to use (hex)").withRequiredArg().ofType(String.class).defaultsTo(AbstractTCPAdapter.DEFAULT_ATR_HEX);
    static OptionSpec<String> OPT_PROTOCOL = parser.accepts("protocol", "Protocol to use").withRequiredArg().ofType(String.class).defaultsTo("*");

    // .cap/.jar files to load
    static OptionSpec<File> toLoad = parser.nonOptions("path to .cap or .jar or classes directory").ofType(File.class);

    static OptionSpec<String> OPT_APPLET = parser.accepts("applet", "Applet class to install").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_PARAMS = parser.accepts("params", "Installation parameters").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_AID = parser.accepts("aid", "Applet AID").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_PRIVILEGES = parser.accepts("privileges", "GP privileges to grant the installed applet, comma-separated (e.g. CVMManagement,CardReset)").withRequiredArg().ofType(String.class);

    // Class loader for .jar/.cap/classes
    static final AppletClassLoader loader = new AppletClassLoader();


    static AbstractTCPAdapter configureVSmartCard(AbstractTCPAdapter adapter, OptionSet options) {
        return configureVSmartCard(adapter, options, OPT_VSMARTCARD_HOST, OPT_VSMARTCARD_PORT, OPT_VSMARTCARD_ATR);
    }

    static AbstractTCPAdapter configureVSmartCard(AbstractTCPAdapter adapter, OptionSet options,
                                                  OptionSpec<String> hostOpt, OptionSpec<Integer> portOpt, OptionSpec<String> atrOpt) {
        adapter = adapter.withHost(options.valueOf(hostOpt));
        adapter = adapter.withPort(options.valueOf(portOpt));
        if (options.has(OPT_ATR)) {
            adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_ATR)));
        }
        if (options.has(atrOpt)) {
            adapter = adapter.withATR(Hex.decode(options.valueOf(atrOpt)));
        }
        return adapter;
    }

    public static void main(String[] args) {
        String version = JCardTool.class.getPackage().getImplementationVersion();

        try {
            OptionSet options = parser.parse(args);

            if (options.has(OPT_VERSION)) {
                System.out.println("JCardEngine v" + version);
                return;
            }

            if (options.has(OPT_HELP) || args.length == 0) {
                parser.printHelpOn(System.out);
                return;
            }

            if (options.nonOptionArguments().isEmpty() && !options.has(OPT_PASSTHROUGH_HOST)) {
                System.err.println("Missing applets. Check --help");
                System.exit(2);
            }


            ExecutorService exec = Executors.newFixedThreadPool(4);
            List<AbstractTCPAdapter> adapters = new ArrayList<>();

            if (options.has(OPT_PASSTHROUGH_HOST)) {
                JCSDKClient upstream = new JCSDKClient(options.valueOf(OPT_PASSTHROUGH_HOST), options.valueOf(OPT_JCSDK_PORT));
                AbstractTCPAdapter adapter = new VSmartCardClient(upstream);
                adapter = configureVSmartCard(adapter, options);
                adapters.add(adapter);
            } else {
                Set<String> availableApplets = new TreeSet<>();
                Map<String, byte[]> defaultAID = new HashMap<>();

                // Set up simulator. Right now a sample thingy
                JavaCardEngine sim = new JavaCardEngine.Builder().withClassLoader(loader).build();

                // Load non-options as applets & classes
                for (File f : options.valuesOf(toLoad)) {
                    Path p = f.toPath();

                    if (Files.isRegularFile(p) && p.getFileName().toString().endsWith(".cap")) {
                        CAPFile cap = CAPFile.fromFile(p);
                        for (Map.Entry<pro.javacard.capfile.AID, String> app : cap.getApplets().entrySet()) {
                            defaultAID.put(app.getValue(), app.getKey().getBytes());
                        }
                    }
                    availableApplets.addAll(loader.addApplet(p));
                }

                List<InstallSpec> spec = new ArrayList<>();

                if (availableApplets.isEmpty()) {
                    System.err.println("No applets found");
                    System.exit(1);
                } else if (options.has(OPT_APPLET)) {
                    Class<? extends Applet> applet = requireExtendsApplet(loader.loadClass(options.valueOf(OPT_APPLET)));
                    final byte[] aid;
                    if (!options.has(OPT_AID) && defaultAID.containsKey(options.valueOf(OPT_APPLET))) {
                        aid = defaultAID.get(options.valueOf(OPT_APPLET));
                    } else {
                        aid = Hex.decode(options.valueOf(OPT_AID));
                    }
                    byte[] params = options.has(OPT_PARAMS) ? Hex.decode(options.valueOf(OPT_PARAMS)) : null;
                    spec.add(InstallSpec.of(aid, applet, params));
                } else if (availableApplets.size() == 1) {
                    String klass = availableApplets.iterator().next();
                    Class<? extends Applet> applet = requireExtendsApplet(loader.loadClass(klass));
                    final byte[] aid;
                    if (!options.has(OPT_AID) && defaultAID.containsKey(klass)) {
                        aid = defaultAID.get(klass);
                    } else {
                        aid = Hex.decode(options.valueOf(OPT_AID));
                    }
                    byte[] params = options.has(OPT_PARAMS) ? Hex.decode(options.valueOf(OPT_PARAMS)) : null;
                    spec.add(InstallSpec.of(aid, applet, params));
                } else {
                    System.err.println("Multiple applets found, use --applet");
                    for (String applet : availableApplets) {
                        System.err.println("- " + applet);
                    }
                    System.exit(1);
                }

                byte[] privileges = parsePrivileges(options.valueOf(OPT_PRIVILEGES));
                for (InstallSpec s : spec) {
                    if (privileges != null) {
                        sim.installApplet(s.getAID(), s.getAppletClass(), privileges, s.getParamters());
                    } else {
                        sim.installApplet(s.getAID(), s.getAppletClass(), s.getParamters());
                    }
                }

                if (options.has(OPT_VSMARTCARD) || options.has(OPT_VSMARTCARD_PORT) || options.has(OPT_VSMARTCARD_HOST) || options.has(OPT_VSMARTCARD_PROTOCOL) || options.has(OPT_VSMARTCARD_ATR)) {
                    var protocol = options.has(OPT_VSMARTCARD_PROTOCOL) ? options.valueOf(OPT_VSMARTCARD_PROTOCOL) : options.valueOf(OPT_PROTOCOL);
                    AbstractTCPAdapter adapter = new VSmartCardClient(p -> sim.connectFor(Duration.ofSeconds(1), p, false)); // TODO: parameter for timeout
                    adapter = adapter.withProtocol(protocol);
                    adapter = configureVSmartCard(adapter, options);
                    adapters.add(adapter);
                }

                if (options.has(OPT_VSMARTCARD2) || options.has(OPT_VSMARTCARD2_PORT) || options.has(OPT_VSMARTCARD2_HOST) || options.has(OPT_VSMARTCARD2_PROTOCOL) || options.has(OPT_VSMARTCARD2_ATR)) {
                    var protocol = options.has(OPT_VSMARTCARD2_PROTOCOL) ? options.valueOf(OPT_VSMARTCARD2_PROTOCOL) : options.valueOf(OPT_PROTOCOL);
                    AbstractTCPAdapter adapter = new VSmartCardClient(p -> sim.connectFor(Duration.ofSeconds(1), p, false));
                    adapter = adapter.withProtocol(protocol);
                    adapter = configureVSmartCard(adapter, options, OPT_VSMARTCARD2_HOST, OPT_VSMARTCARD2_PORT, OPT_VSMARTCARD2_ATR);
                    // Both interfaces start active; apdu4j's connected(false) can't be called before the
                    // adapter's thread exists (it does thread.interrupt() unconditionally -> NPE). Use the
                    // 's'/switch and connect/disconnect control commands at runtime to manage which is live.
                    adapters.add(adapter);
                }

                if (options.has(OPT_JCSDK) || options.has(OPT_JCSDK_PORT) || options.has(OPT_JCSDK_HOST) || options.has(OPT_JCSDK_PROTOCOL) || options.has(OPT_JCSDK_ATR)) {
                    var protocol = options.has(OPT_JCSDK_PROTOCOL) ? options.valueOf(OPT_JCSDK_PROTOCOL) : options.valueOf(OPT_PROTOCOL);
                    AbstractTCPAdapter adapter = new JCSDKServer(sim::connect);
                    adapter = adapter.withProtocol(protocol);
                    adapter = adapter.withHost(options.valueOf(OPT_JCSDK_HOST));
                    adapter = adapter.withPort(options.valueOf(OPT_JCSDK_PORT));
                    if (options.has(OPT_ATR)) {
                        adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_ATR)));
                    }
                    if (options.has(OPT_JCSDK_ATR)) {
                        adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_JCSDK_ATR)));
                    }
                    adapters.add(adapter);
                }

                if (options.has(OPT_JSON) || options.has(OPT_JSON_PORT) || options.has(OPT_JSON_HOST)) {
                    AbstractTCPAdapter adapter = new JSONAdapter(p -> sim.connectFor(Duration.ofSeconds(1), p, true));
                    adapter = adapter.withProtocol(options.valueOf(OPT_PROTOCOL));
                    adapter = adapter.withHost(options.valueOf(OPT_JSON_HOST));
                    adapter = adapter.withPort(options.valueOf(OPT_JSON_PORT));
                    if (options.has(OPT_ATR)) {
                        adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_ATR)));
                    }
                    adapters.add(adapter);
                }
            }

            // Trap ctrl-c and similar signals
            Thread shutdownThread = new Thread(() -> {
                System.err.println("Ctrl-C, quitting JCardEngine");
                exec.shutdownNow();
            });

            if (adapters.isEmpty()) {
                System.err.println("Use one of --vsmartcard or --jcsdk or --passthrough-host");
                System.exit(2);
            }

            Runtime.getRuntime().addShutdownHook(shutdownThread);
            if (options.has(OPT_CONTROL)) {
                // A card lives in one reader at a time: start only the active interface presenting the
                // card. Other interfaces stay dormant (their reader reports no card) until 's'/switch
                // hands the single card over, submitting that adapter on first use.
                int[] activeAdapter = {0};
                boolean[] started = new boolean[adapters.size()];
                if (!adapters.isEmpty()) {
                    exec.submit(adapters.get(0));
                    started[0] = true;
                }

                if (System.console() != null) {
                    // Interactive TTY: use jline raw mode for single-keypress control.
                    // nativeSignals seems to be the trick to keep ctrl-c working with raw mode
                    TerminalBuilder tb = TerminalBuilder.builder().nativeSignals(false).system(true).graphemeCluster(false);
                    try (Terminal terminal = tb.build()) {
                        terminal.enterRawMode();
                        NonBlockingReader reader = terminal.reader();
                        while (!Thread.currentThread().isInterrupted()) {
                            int c = reader.read();
                            if (c == 27 || c == 113) {
                                // esc or q
                                System.err.println("Quit.");
                                break;
                            } else {
                                if (!handleControlCommand(String.valueOf((char) c), adapters, exec, started, activeAdapter))
                                    System.err.println("Press 't' to trigger tap, 'c'/'connect' present, 'disconnect' remove, 's' to switch interface, 'q' or Esc to quit.");
                            }
                        }
                    }
                } else {
                    // Piped stdin: read line-based commands (for scripting)
                    System.err.println("Control mode (stdin): send 'switch', 'tap', 'connect', 'disconnect', or 'quit'");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim().toLowerCase();
                        if (line.equals("quit") || line.equals("q")) {
                            System.err.println("Quit.");
                            break;
                        } else {
                            if (!handleControlCommand(line, adapters, exec, started, activeAdapter))
                                System.err.println("Unknown command: " + line + ". Use: switch, tap, connect, disconnect, quit");
                        }
                    }
                }
            } else {
                // This blocks until all are done, unless ctrl-c is hit
                exec.invokeAll(adapters);
            }

            Runtime.getRuntime().removeShutdownHook(shutdownThread);
            exec.shutdownNow();
            while (!exec.isTerminated()) {
                if (exec.awaitTermination(1, TimeUnit.MINUTES)) {
                    break;
                }
            }
            System.err.println("Thank you for using JCardEngine v" + version + "!");
        } catch (OptionException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (IllegalArgumentException e) {
            System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(2);
        }
    }

    // Returns true if command was recognized. The card is presented on one interface at a time;
    // 'started' tracks which adapters have been submitted (dormant ones never present a card), and
    // commands act on the currently active interface.
    private static boolean handleControlCommand(String cmd, List<AbstractTCPAdapter> adapters, ExecutorService exec, boolean[] started, int[] activeAdapter) {
        int active = activeAdapter[0];
        switch (cmd) {
            case "t":
            case "tap":
                System.err.println("Triggering a fresh tap: boop!");
                if (active < started.length && started[active]) {
                    adapters.get(active).tap();
                }
                return true;
            case "c":
            case "connect":
                // Present the card on the active interface.
                if (active < started.length && started[active]) {
                    System.err.println("Connecting the card");
                    adapters.get(active).connected(true);
                }
                return true;
            case "disconnect":
                // Remove the card from the active interface.
                if (active < started.length && started[active]) {
                    System.err.println("Disconnecting the card");
                    adapters.get(active).connected(false);
                }
                return true;
            case "s":
            case "switch":
                if (adapters.size() < 2) {
                    System.err.println("No second interface to switch to.");
                    return true;
                }
                // Hand the one card to the next reader: remove it from the current interface, present
                // it on the next. State (EEPROM + transient) carries across - it is the same card.
                if (started[active]) {
                    adapters.get(active).connected(false);
                }
                activeAdapter[0] = (active + 1) % adapters.size();
                int next = activeAdapter[0];
                if (!started[next]) {
                    exec.submit(adapters.get(next)); // first activation: starts presenting the card
                    started[next] = true;
                } else {
                    adapters.get(next).connected(true);
                }
                System.err.println("Switched to interface " + (next + 1) + " (" + adapters.get(next) + ")");
                return true;
            default:
                return false;
        }
    }

    // Encode a comma-separated list of GP privilege names (e.g. "CVMManagement,CardReset") into the
    // GP privilege bitfield expected by installApplet(). Returns null when no --privileges was given.
    private static byte[] parsePrivileges(String spec) {
        if (spec == null || spec.isBlank()) {
            return null;
        }
        var privs = EnumSet.noneOf(Privilege.class);
        for (String name : spec.split(",")) {
            String n = name.trim();
            if (n.isEmpty()) {
                continue;
            }
            Privilege match = null;
            for (Privilege p : Privilege.values()) {
                if (p.name().equalsIgnoreCase(n)) {
                    match = p;
                    break;
                }
            }
            if (match == null) {
                throw new IllegalArgumentException("Unknown privilege '" + n + "'. Valid: " + Arrays.toString(Privilege.values()));
            }
            privs.add(match);
        }
        return privs.isEmpty() ? null : BitField.toBytes(privs);
    }

    @SuppressWarnings("unchecked")
    private static Class<? extends Applet> requireExtendsApplet(Class<?> cls) {
        System.out.println("Validating " + cls.getName());
        if (!Applet.class.isAssignableFrom(cls)) {
            throw new SystemException(SystemException.ILLEGAL_VALUE);
        }
        return (Class<? extends Applet>) cls;
    }
}
