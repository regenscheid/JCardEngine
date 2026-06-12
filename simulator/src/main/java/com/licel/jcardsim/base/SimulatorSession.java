// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.BIBO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.*;

// A BIBO session over the simulator, guarding the single card lock for the duration of a card
// "power-up".
//
// Opportunistic locking: the lock is held while the session is active but is handed back after
// `idleTimeout` of no APDU traffic, so another interface/session can use the same card in the
// meantime. The session itself stays open across that release - transceive() transparently
// re-acquires the lock on the next command. Only an explicit close() (card power-off) ends the
// session (and resets the card if resetOnClose). This lets a long-lived adapter that caches its
// BIBO (e.g. apdu4j's vsmartcard client) survive idle periods instead of failing with
// "Session already closed", while still releasing the lock so a second reader can take the card.
// idleTimeout == 0 disables the release (lock held until close).
public class SimulatorSession implements BIBO {
    private static final Logger log = LoggerFactory.getLogger(SimulatorSession.class);

    // I like my threads with nice names.
    static ThreadFactory namedThreadFactory = r -> {
        Thread t = new Thread(r, "IdleWatchdog");
        t.setDaemon(true); // not blocking shutdown
        return t;
    };
    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(namedThreadFactory);

    private final Duration idleTimeout;
    private final Simulator simulator;
    private final String protocol;
    private final byte protocol_byte;
    private final boolean resetOnClose;
    final Thread owner;

    // All guarded by `this`.
    private boolean closed = false;       // session ended (power-off); terminal
    private boolean holdingLock = false;  // currently owns simulator.lock
    private long activityGen = 0;         // bumped on activity; an idle release only fires if unchanged
    private ScheduledFuture<?> timeoutTask;

    SimulatorSession(Simulator simulator, String protocol, Duration timeout, boolean resetOnClose) {
        this.simulator = simulator;
        this.owner = Thread.currentThread();
        this.protocol = protocol;
        this.resetOnClose = resetOnClose;
        this.idleTimeout = timeout;
        this.protocol_byte = APDUHelper.getProtocolByte(protocol);
        log.trace("Acquiring lock ...");
        simulator.lock.acquireUninterruptibly();
        synchronized (this) {
            holdingLock = true;
            armIdleTimer();
        }
        log.trace("Locked");
    }

    // (Re)arm the idle-release timer. Must hold `this`.
    private void armIdleTimer() {
        if (idleTimeout.isZero()) {
            return; // 0 = never release on idle: hold the lock until close()
        }
        long gen = ++activityGen;
        if (timeoutTask != null) {
            timeoutTask.cancel(false);
        }
        timeoutTask = scheduler.schedule(() -> releaseOnIdle(gen), idleTimeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    // Idle: hand the card lock back so another session can use the card. The session stays open;
    // transceive() re-acquires on the next command. No reset (that only happens on close()).
    private synchronized void releaseOnIdle(long gen) {
        if (closed || gen != activityGen) {
            return; // stale: closed, or activity happened after this timer was armed
        }
        if (holdingLock) {
            holdingLock = false;
            simulator.lock.release();
            log.debug("Idle, released card lock for {} (session stays open)", owner.getName());
        }
    }

    @Override
    public synchronized byte[] transceive(byte[] commandAPDU) {
        if (closed) {
            throw new IllegalStateException("Session already closed");
        }
        if (!holdingLock) {
            // The idle release handed the lock away; take it back (may block until the current
            // holder goes idle and releases it).
            log.trace("Re-acquiring lock ...");
            simulator.lock.acquireUninterruptibly();
            holdingLock = true;
        }
        activityGen++; // invalidate any in-flight idle release for the window we process in
        try {
            return simulator._transceive(protocol_byte, commandAPDU);
        } finally {
            armIdleTimer(); // count idle from the end of this command
        }
    }

    @Override
    public synchronized void close() {
        // Do nothing if already closed
        if (closed) {
            return;
        }
        closed = true;
        if (timeoutTask != null) {
            timeoutTask.cancel(false);
        }
        if (resetOnClose) {
            simulator.reset();
        }
        if (holdingLock) {
            holdingLock = false;
            simulator.lock.release();
        }
        log.trace("Unlocked");
    }
}
