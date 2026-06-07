package org.trvedata.sgm;

import picocli.CommandLine;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.concurrent.Callable;

import static picocli.CommandLine.Command;
import static picocli.CommandLine.Option;

@Command(
        description = "Runs the simulation for gathering stats for the evaluation",
        name = "cli_evaluation",
        mixinStandardHelpOptions = true,
        version = "0.1"
)
public class CliEvaluation implements Callable<Integer> {

    @Option(names = {"-o", "--output-folder"}, description = "Output CSV folder (must exist)")
    public File csvOutputFolder;

    @Option(names = {"-i", "--iterations"}, defaultValue = "10", description = "Number of iterations for each test scenario")
    public int iterations;

    @Option(names = {"--group-sizes"}, split = ",",
            description = "Comma-separated group sizes for the group-size sweep (default: sqrt(2) ladder 8..128). " +
                    "Override (e.g. 8,16,32,64,128,256,512,1024) to extend the range; the regenerated series then no " +
                    "longer matches the committed baseline.")
    public int[] groupSizes = new int[0];

    @Option(names = {"--history-sweep"}, description = "Fix the group size and sweep history size for add/welcome evaluation")
    public boolean historySweep;

    @Option(names = {"--fixed-group-size"}, defaultValue = "32", description = "Fixed group size used by --history-sweep")
    public int fixedGroupSize;

    @Option(names = {"--history-sizes"}, split = ",", defaultValue = "0,2,4,8,16,32,64",
            description = "Comma-separated history sizes used by --history-sweep")
    public int[] historySizes;

    public static void main(final String[] args) {
        final ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        if (!threadBean.isThreadCpuTimeSupported()) {
            System.out.println("Thread CPU time is not supported by this JVM");
            System.exit(1);
        }

        final int exitCode = new CommandLine(new CliEvaluation()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        final EvaluationSimulation evaluationSimulation = new EvaluationSimulation(this);
        evaluationSimulation.run();
        return 0;
    }
}
