package org.trvedata.sgm;

import org.trvedata.sgm.misc.Instrumentation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

class MetricsCapturer {

    private final Metric setupSentBytes = new TrafficMetric("setupsentbytes");
    private final Metric operationSentBytes = new TrafficMetric("operationsentbytes");

    private final Map<ThreadedClient, TimeMetric> setupTimes = new HashMap<>();
    private final Map<ThreadedClient, TimeMetric> operationTimes = new HashMap<>();
    private final ArrayList<PrimitiveCaptureResult> primitiveResults = new ArrayList<>();

    private final ThreadSafeNetwork mNetwork;
    private final Collection<ThreadedClient> mClients;

    public MetricsCapturer(final ThreadSafeNetwork network, final Collection<ThreadedClient> clients) {
        mNetwork = network;
        mClients = clients;
        for (final ThreadedClient client : mClients) {
            setupTimes.put(client, new TimeMetric("setuptime"));
            operationTimes.put(client, new TimeMetric("operationtime"));
        }
    }

    public void setupBegin() {
        for (final ThreadedClient client : mClients) setupTimes.get(client).startValue = 0L;
        setupSentBytes.startValue = mNetwork.getSentBytes();
    }

    public void setupEnd() {
        for (final ThreadedClient client : mClients) setupTimes.get(client).endValue = client.getCpuTime();
        setupSentBytes.endValue = mNetwork.getSentBytes();
    }

    public void operationBegin() {
        for (final ThreadedClient client : mClients) operationTimes.get(client).startValue = 0L;
        for (final ThreadedClient client : mClients) client.clearPrimitiveSnapshots();
        primitiveResults.clear();
        operationSentBytes.startValue = mNetwork.getSentBytes();
    }

    public void operationEnd() {
        for (final ThreadedClient client : mClients) {
            if (operationTimes.get(client) != null) operationTimes.get(client).endValue = client.getCpuTime();
        }
        int receiverIndex = 0;
        for (final ThreadedClient client : mClients) {
            for (final ThreadedClient.PrimitiveSnapshot snapshot : client.primitiveSnapshots()) {
                primitiveResults.add(PrimitiveCaptureResult.receiver(snapshot, receiverIndex++));
            }
        }
        primitiveResults.add(PrimitiveCaptureResult.system(primitiveResults));
        operationSentBytes.endValue = mNetwork.getSentBytes();
    }

    public void recordSenderPrimitives(final Instrumentation.Counters counters) {
        primitiveResults.add(PrimitiveCaptureResult.sender(counters));
    }

    public MetricCaptureResult getTrafficResults(final EvaluationSimulation.TestRunParameters params) {
        return new MetricCaptureResult(params, null, setupSentBytes, operationSentBytes);
    }

    public ArrayList<MetricCaptureResult> getTimeResultsForClients(final EvaluationSimulation.TestRunParameters params) {
        final ArrayList<MetricCaptureResult> results = new ArrayList<>();
        for (final ThreadedClient client : mClients) {
            if (setupTimes.get(client) != null && operationTimes.get(client) != null) {
                results.add(new MetricCaptureResult(params, client.getRole(), setupTimes.get(client), operationTimes.get(client)));
            }
        }
        return results;
    }

    public ArrayList<PrimitiveCaptureResult> getPrimitiveResults(final EvaluationSimulation.TestRunParameters params) {
        final ArrayList<PrimitiveCaptureResult> results = new ArrayList<>();
        for (final PrimitiveCaptureResult result : primitiveResults) {
            result.params = params;
            results.add(result);
        }
        return results;
    }

    public abstract static class Metric {
        public final String name;
        public long startValue = -1L;
        public long endValue = -1L;

        private Metric(final String name) {
            this.name = name;
        }

        public abstract double getValue();
    }

    /**
     * Captures in nano seconds, returns in milliseconds
     */
    public static class TimeMetric extends Metric {
        public static final double NS_IN_MS = 1_000_000.0;

        private TimeMetric(String name) {
            super(name);
        }

        public double getValue() {
            if (startValue < 0 || endValue < 0) throw new IllegalStateException();
            return (endValue - startValue) / NS_IN_MS;
        }
    }

    public static class TrafficMetric extends Metric {

        private TrafficMetric(String name) {
            super(name);
        }

        public double getValue() {
            if (startValue < 0 || endValue < 0) throw new IllegalStateException();
            return endValue - startValue;
        }
    }

    public static class MetricCaptureResult {
        public final EvaluationSimulation.TestRunParameters params;
        private final ThreadedClient.ClientRole clientRole;
        private final Metric[] metrics;

        private MetricCaptureResult(
                final EvaluationSimulation.TestRunParameters params,
                final ThreadedClient.ClientRole clientRole,
                final Metric... metrics) {
            this.params = params;
            this.clientRole = clientRole;
            this.metrics = metrics;
        }

        public String getCsvHeader() {
            final StringBuilder sb = new StringBuilder();
            sb.append("groupsize,history_size,protocol,operation");
            if (clientRole != null) sb.append(",clientrole");
            for (final Metric metric : metrics) sb.append(',').append(metric.name);
            return sb.toString();
        }

        @Override
        public String toString() {
            return getCsvHeader() + " -> " + toCsvRow();
        }

        public String toCsvRow() {
            final StringBuilder sb = new StringBuilder();
            sb.append(params.groupsize).append(',')
                    .append(params.historySize).append(',')
                    .append(params.dcgkaChoice).append(',')
                    .append(params.operation.opcode);
            if (clientRole != null) sb.append(',').append(clientRole);
            for (final Metric metric : metrics) sb.append(',').append(metric.getValue());
            return sb.toString();
        }
    }

    public static class PrimitiveCaptureResult {
        private EvaluationSimulation.TestRunParameters params;
        private final String role;
        private final int receiverIndex;
        private final String messageKind;
        private final Instrumentation.Counters counters;

        private PrimitiveCaptureResult(
                final String role,
                final int receiverIndex,
                final String messageKind,
                final Instrumentation.Counters counters) {
            this.role = role;
            this.receiverIndex = receiverIndex;
            this.messageKind = messageKind;
            this.counters = counters;
        }

        public static PrimitiveCaptureResult sender(final Instrumentation.Counters counters) {
            return new PrimitiveCaptureResult("sender", -1, "sender_operation", counters);
        }

        public static PrimitiveCaptureResult receiver(
                final ThreadedClient.PrimitiveSnapshot snapshot,
                final int receiverIndex) {
            return new PrimitiveCaptureResult(roleName(snapshot.clientRole), receiverIndex, snapshot.messageKind, snapshot.counters);
        }

        public static PrimitiveCaptureResult system(final ArrayList<PrimitiveCaptureResult> results) {
            final Instrumentation.Counters system = new Instrumentation.Counters();
            for (final PrimitiveCaptureResult result : results) {
                if (result.isAuxiliaryAck()) continue;
                system.hash += result.counters.hash;
                system.aeadEncrypt += result.counters.aeadEncrypt;
                system.aeadDecrypt += result.counters.aeadDecrypt;
                system.randomCalls += result.counters.randomCalls;
                system.randomBytes += result.counters.randomBytes;
                system.keygen += result.counters.keygen;
                system.dh += result.counters.dh;
                system.hpkeEncrypt += result.counters.hpkeEncrypt;
                system.hpkeDecrypt += result.counters.hpkeDecrypt;
                system.sign += result.counters.sign;
                system.verify += result.counters.verify;
                system.prf += result.counters.prf;
                system.pubkeyNanos += result.counters.pubkeyNanos;
                system.symNanos += result.counters.symNanos;
                system.totalNanos += result.counters.totalNanos;
            }
            return new PrimitiveCaptureResult("system", -1, "system", system);
        }

        private boolean isAuxiliaryAck() {
            return "ack".equals(messageKind);
        }

        private static String roleName(final ThreadedClient.ClientRole role) {
            switch (role) {
                case SENDER:
                    return "sender";
                case NEW_RECIPIENT:
                    return "new_receiver";
                case RECIPIENT:
                default:
                    return "receiver";
            }
        }

        public String getCsvHeader() {
            return "groupsize,history_size,protocol,operation,role,receiver_index,message_kind,is_auxiliary_ack,"
                    + "hash,aead_encrypt,aead_decrypt,random_calls,random_bytes,keygen,dh,"
                    + "hpke_encrypt,hpke_decrypt,sign,verify,prf,pubkey_ms,sym_ms,total_ms";
        }

        public String toCsvRow() {
            final StringBuilder sb = new StringBuilder();
            sb.append(params.groupsize).append(',')
                    .append(params.historySize).append(',')
                    .append(params.dcgkaChoice).append(',')
                    .append(params.operation.opcode).append(',')
                    .append(role).append(',')
                    .append(receiverIndex).append(',')
                    .append(messageKind).append(',')
                    .append(isAuxiliaryAck()).append(',')
                    .append(counters.hash).append(',')
                    .append(counters.aeadEncrypt).append(',')
                    .append(counters.aeadDecrypt).append(',')
                    .append(counters.randomCalls).append(',')
                    .append(counters.randomBytes).append(',')
                    .append(counters.keygen).append(',')
                    .append(counters.dh).append(',')
                    .append(counters.hpkeEncrypt).append(',')
                    .append(counters.hpkeDecrypt).append(',')
                    .append(counters.sign).append(',')
                    .append(counters.verify).append(',')
                    .append(counters.prf).append(',')
                    .append(counters.pubkeyNanos / 1.0e6).append(',')
                    .append(counters.symNanos / 1.0e6).append(',')
                    .append(counters.totalNanos / 1.0e6);
            return sb.toString();
        }
    }

}
