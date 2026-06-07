package org.trvedata.sgm;

import org.trvedata.sgm.DsgmClient.DcgkaChoice;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.crypto.IdentityKeyPair;
import org.trvedata.sgm.crypto.InMemoryPreKeySource;
import org.trvedata.sgm.crypto.PreKeySecret;
import org.trvedata.sgm.misc.Instrumentation;
import org.trvedata.sgm.misc.Logger;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

import static org.trvedata.sgm.MetricsCapturer.MetricCaptureResult;
import static org.trvedata.sgm.MetricsCapturer.PrimitiveCaptureResult;

public class EvaluationSimulation {

    private final CliEvaluation mArgs;

    public EvaluationSimulation(final CliEvaluation args) {
        mArgs = args;
        Logger.setLoggingLevel(Logger.Level.WARN);
    }

    public void run() throws InterruptedException {
        if (mArgs.historySweep) {
            runHistorySweep();
            return;
        }

        // test parameters. Default to the committed 8..512 ladder (which the committed
        // baselines were generated with); --group-sizes overrides it to extend the range.
        final ArrayList<Integer> groupSizes = new ArrayList<>();
        final int[] sizes = (mArgs.groupSizes != null && mArgs.groupSizes.length > 0)
                ? mArgs.groupSizes
                : new int[]{8, 16, 32, 64, 128, 256, 512};
        for (final int gs : sizes) groupSizes.add(gs);
        final Operation[] operations = new Operation[]{Operation.MESSAGE, Operation.REMOVE, Operation.ADD, Operation.UPDATE};
        final int iterations = mArgs.iterations;

        // results parameters and collection
        final ArrayList<TestRunParameters> parameters = new ArrayList<>();
        final TestRunResults results = TestRunResults.empty();

        for (int i = 0; i < iterations; i++) {
            for (final int gs : groupSizes) {
                for (final Operation operation : operations) {
                    parameters.add(new TestRunParameters(gs, operation, DcgkaChoice.FULL));
                }
            }
        }
        Collections.shuffle(parameters, new Random(0));

        // warming up the JVM and JIT
        for (int i = 0; i < iterations; i++) {
            runTestCase(new TestRunParameters(10, Operation.UPDATE, DcgkaChoice.FULL));
        }
        System.out.println("warm-up finished");

        // actual execution
        for (int i = 0; i < parameters.size(); i++) {
            // add some time for the GC to run
            System.gc();
            Thread.sleep(1000);

            final TestRunResults result = runTestCase(parameters.get(i));
            results.add(result);

            final int threadCnt = Thread.getAllStackTraces().keySet().size();
            System.out.println((i) + "/" + parameters.size() + ": " + result.toString() + " #threads=" + threadCnt);

        }

        // output CSV
        if (mArgs.csvOutputFolder != null) {
            mArgs.csvOutputFolder.mkdirs();
            writeCsv(results.trafficMetrics, new File(mArgs.csvOutputFolder, "traffic.csv"));
            writeCsv(results.timeMetrics, new File(mArgs.csvOutputFolder, "time.csv"));
            writePrimitiveCsv(results.primitiveMetrics, new File(mArgs.csvOutputFolder, "dcgka-primitives.csv"));
        }
    }

    private void runHistorySweep() throws InterruptedException {
        final int iterations = mArgs.iterations;
        final ArrayList<TestRunParameters> parameters = new ArrayList<>();
        final TestRunResults results = TestRunResults.empty();

        for (int i = 0; i < iterations; i++) {
            for (final int historySize : mArgs.historySizes) {
                if (historySize % 2 != 0) {
                    throw new IllegalArgumentException("DCGKA history sweep uses add/remove pairs, so history sizes must be even: " + historySize);
                }
                parameters.add(new TestRunParameters(mArgs.fixedGroupSize, Operation.ADD, DcgkaChoice.FULL, historySize));
            }
        }

        runTestCase(new TestRunParameters(mArgs.fixedGroupSize, Operation.ADD, DcgkaChoice.FULL, 2));
        System.out.println("history-sweep warm-up finished");

        for (int i = 0; i < parameters.size(); i++) {
            System.gc();
            Thread.sleep(1000);

            final TestRunResults result = runTestCase(parameters.get(i));
            results.add(result);

            final int threadCnt = Thread.getAllStackTraces().keySet().size();
            System.out.println((i) + "/" + parameters.size() + ": " + result.toString() + " #threads=" + threadCnt);
        }

        if (mArgs.csvOutputFolder != null) {
            mArgs.csvOutputFolder.mkdirs();
            writeCsv(results.trafficMetrics, new File(mArgs.csvOutputFolder, "traffic.csv"));
            writeCsv(results.timeMetrics, new File(mArgs.csvOutputFolder, "time.csv"));
            writePrimitiveCsv(results.primitiveMetrics, new File(mArgs.csvOutputFolder, "dcgka-primitives.csv"));
        }
    }

    private void writeCsv(final ArrayList<MetricCaptureResult> results, final File csvOutput) {
        try (final BufferedWriter outputWriter = new BufferedWriter(new FileWriter(csvOutput))) {
            outputWriter.write(results.get(0).getCsvHeader());
            outputWriter.newLine();

            for (final MetricCaptureResult result : results) {
                outputWriter.write(result.toCsvRow());
                outputWriter.newLine();
            }
        } catch (final IOException e) {
            throw new RuntimeException("Failed to write CSV output file", e);
        }
    }

    private void writePrimitiveCsv(final ArrayList<PrimitiveCaptureResult> results, final File csvOutput) {
        try (final BufferedWriter outputWriter = new BufferedWriter(new FileWriter(csvOutput))) {
            outputWriter.write(results.get(0).getCsvHeader());
            outputWriter.newLine();

            for (final PrimitiveCaptureResult result : results) {
                outputWriter.write(result.toCsvRow());
                outputWriter.newLine();
            }
        } catch (final IOException e) {
            throw new RuntimeException("Failed to write CSV output file", e);
        }
    }

    private TestRunResults runTestCase(final TestRunParameters params) throws InterruptedException {
        final ThreadSafeNetwork network = new ThreadSafeNetwork();
        final InMemoryPreKeySource preKeySource = new InMemoryPreKeySource();
        final ArrayList<ThreadedClient> clients = createThreadedClients(network, preKeySource, params.groupsize, params.dcgkaChoice);

        final MetricsCapturer metrics = new MetricsCapturer(network, clients);

        // START
        for (ThreadedClient client : clients) client.start();

        final ArrayList<IdentityKey> memberKeys = new ArrayList<>();
        for (final ThreadedClient client : clients) memberKeys.add((IdentityKey) client.getIdentifier());

        final ThreadedClient sender = clients.get(0);
        final ArrayList<ThreadedClient> receivers = new ArrayList<>(clients.subList(1, clients.size())); // copy necessary

        // Make prekeys for a potential future added member now, since they should not count against the add time
        final IdentityKeyPair toAddKeyPair = IdentityKey.generateKeyPair();
        final PreKeySecret toAddPreKeySecret = preKeySource.registerUser(toAddKeyPair, params.groupsize + 1);

        // SETUP
        metrics.setupBegin();

        sender.createGroup(memberKeys);
        for (ThreadedClient client : clients) client.waitUntilSetupFinished();

        // clients need to be stopped and restarted as the thread cpu time can only be read in "finished" thread state
        for (final ThreadedClient client : clients) client.stop();
        for (final ThreadedClient client : clients) client.join();
        metrics.setupEnd();
        for (final ThreadedClient client : clients) client.start();

        for (int historyIndex = 0; historyIndex < params.historySize / 2; historyIndex++) {
            performHistoryMembershipPair(clients, network, preKeySource, params, historyIndex);
        }

        if (params.historySize > 0) {
            for (final ThreadedClient client : clients) client.stop();
            for (final ThreadedClient client : clients) client.join();
            for (final ThreadedClient client : clients) client.start();
        }

        // OPERATION
        for (final ThreadedClient client : clients) client.clearNextOperation();
        metrics.operationBegin();

        Instrumentation.reset();
        final long senderCpuStart = Utils.getCpuTimeForCurrentThread();
        switch (params.operation) {
            case MESSAGE:
                for (final ThreadedClient client : receivers) client.expectNextOperation(1);// sender excluded
                sender.expectNextOperation(0);
                sender.sendMessage("0123456789ABCDEF0123456789ABCDEF"); // 32 byte e.g. AES key
                break;

            case ADD:
                for (final ThreadedClient client : clients) client.expectNextOperation(params.groupsize);
                // Create added client ourselves instead of using DsgmClientFactory, so we can give it the
                // pre-made prekeys.
                final DsgmClient dsgmClient = new DsgmClient(network, toAddPreKeySecret, preKeySource, "NewMember",
                        toAddKeyPair, createClientImplementation(params.dcgkaChoice));
                final ThreadedClient toBeAdded = new ThreadedClient(dsgmClient, network, ThreadedClient.ClientRole.NEW_RECIPIENT);

                toBeAdded.expectNextOperation(params.groupsize);
                toBeAdded.start();
                clients.add(toBeAdded);

                sender.addMember(toBeAdded);
                receivers.add(toBeAdded);
                break;

            case REMOVE:
                final ThreadedClient toBeRemoved = receivers.get(0);
                for (final ThreadedClient client : clients) {
                    if (client != toBeRemoved) client.expectNextOperation(params.groupsize - 2);
                }
                toBeRemoved.expectNextOperation(1);

                sender.removeMember(toBeRemoved);
                receivers.remove(toBeRemoved); // important as the removed client does not call `onRemove()`
                break;

            case UPDATE:
                for (final ThreadedClient client : clients) client.expectNextOperation(params.groupsize - 1);
                sender.update();
                break;
        }
        final Instrumentation.Counters senderSnapshot = Instrumentation.snapshot();
        senderSnapshot.totalNanos = Utils.getCpuTimeForCurrentThread() - senderCpuStart;
        metrics.recordSenderPrimitives(senderSnapshot);

        for (final ThreadedClient client : receivers) client.waitUntilNextOperationFinished(params.operation);// sender excluded
        sender.waitUntilNextOperationFinishedSender();

        // CLEAN-UP
        for (final ThreadedClient client : clients) client.stop();
        for (final ThreadedClient client : clients) client.join();
        metrics.operationEnd();

        return TestRunResults.fromMetricsCapturer(metrics, params);
    }

    private void performHistoryMembershipPair(
            final ArrayList<ThreadedClient> clients,
            final ThreadSafeNetwork network,
            final InMemoryPreKeySource preKeySource,
            final TestRunParameters params,
            final int historyIndex) throws InterruptedException {
        final ThreadedClient sender = clients.get(0);
        final int currentGroupSize = clients.size();
        final IdentityKeyPair keyPair = IdentityKey.generateKeyPair();
        final PreKeySecret preKeySecret = preKeySource.registerUser(keyPair, currentGroupSize + 1);
        final DsgmClient dsgmClient = new DsgmClient(network, preKeySecret, preKeySource, "HistoryMember" + historyIndex,
                keyPair, createClientImplementation(params.dcgkaChoice));
        final ThreadedClient added = new ThreadedClient(dsgmClient, network, ThreadedClient.ClientRole.RECIPIENT);

        for (final ThreadedClient client : clients) client.expectNextOperation(currentGroupSize);
        added.expectNextOperation(currentGroupSize);
        added.start();
        sender.addMember(added);
        for (final ThreadedClient client : clients) {
            if (client == sender) continue;
            client.waitUntilNextOperationFinished(Operation.ADD);
        }
        added.waitUntilNextOperationFinished(Operation.ADD);
        sender.waitUntilNextOperationFinishedSender();
        clients.add(added);

        final int sizeAfterAdd = clients.size();
        for (final ThreadedClient client : clients) {
            if (client != added) client.expectNextOperation(sizeAfterAdd - 2);
        }
        added.expectNextOperation(1);
        sender.removeMember(added);
        for (final ThreadedClient client : clients) {
            if (client == sender || client == added) continue;
            client.waitUntilNextOperationFinished(Operation.REMOVE);
        }
        sender.waitUntilNextOperationFinishedSender();
        clients.remove(added);
        added.stop();
        added.join();

        for (final ThreadedClient client : clients) client.clearPrimitiveSnapshots();
    }


    private ArrayList<ThreadedClient> createThreadedClients(final ThreadSafeNetwork network,
                                                            final InMemoryPreKeySource inMemoryPreKeySource,
                                                            final int gs,
                                                            final DcgkaChoice dcgkaChoice) {
        final DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(network,
                inMemoryPreKeySource, gs, createClientImplementation(dcgkaChoice));
        final ArrayList<ThreadedClient> clients = new ArrayList<>(gs);
        for (int i = 0; i < gs; i++) {
            clients.add(new ThreadedClient(factoryResult.clients[i], network, gs, i == 0 ? ThreadedClient.ClientRole.SENDER : ThreadedClient.ClientRole.RECIPIENT));
        }
        return clients;
    }

    private DsgmClient.DgmClientImplementationConfiguration createClientImplementation(final DcgkaChoice dcgkaChoice) {
        return new DsgmClient.DgmClientImplementationConfiguration(dcgkaChoice, true, true, true);
    }

    public static class TestRunParameters {
        public final int groupsize;
        public final Operation operation;
        public final DcgkaChoice dcgkaChoice;
        public final int historySize;

        public TestRunParameters(final int groupsize, final Operation operation, final DcgkaChoice dcgkaChoice) {
            this(groupsize, operation, dcgkaChoice, 0);
        }

        public TestRunParameters(final int groupsize, final Operation operation, final DcgkaChoice dcgkaChoice, final int historySize) {
            this.groupsize = groupsize;
            this.operation = operation;
            this.dcgkaChoice = dcgkaChoice;
            this.historySize = historySize;
        }
    }

    private static class TestRunResults {
        public final ArrayList<MetricCaptureResult> trafficMetrics = new ArrayList<>();
        public final ArrayList<MetricCaptureResult> timeMetrics = new ArrayList<>();
        public final ArrayList<PrimitiveCaptureResult> primitiveMetrics = new ArrayList<>();

        private TestRunResults() {
        }

        public static TestRunResults empty() {
            return new TestRunResults();
        }


        public static TestRunResults fromMetricsCapturer(final MetricsCapturer metricsCapturer, final TestRunParameters params) {
            final TestRunResults instance = new TestRunResults();
            instance.trafficMetrics.add(metricsCapturer.getTrafficResults(params));
            instance.timeMetrics.addAll(metricsCapturer.getTimeResultsForClients(params));
            instance.primitiveMetrics.addAll(metricsCapturer.getPrimitiveResults(params));
            return instance;
        }

        public void add(final TestRunResults other) {
            this.trafficMetrics.addAll(other.trafficMetrics);
            this.timeMetrics.addAll(other.timeMetrics);
            this.primitiveMetrics.addAll(other.primitiveMetrics);
        }

        @Override
        public String toString() {
            return "TestRunResults{" + "trafficMetrics=" + trafficMetrics + ", #timeMetrics=" + timeMetrics.size() + '}';
        }
    }
}
