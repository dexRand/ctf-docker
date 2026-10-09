// Ghidra headless postScript: decompile every function.
// Output goes to the file given as the first script arg (keeps it clean from
// the INFO log lines Ghidra prints on stdout); without an arg it uses println.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter out = null;
        if (args != null && args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            out = new PrintWriter(new BufferedWriter(new FileWriter(args[0])));
        }
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        int ok = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk()) {
                continue;
            }
            try {
                DecompileResults res = dec.decompileFunction(f, 60, monitor);
                if (res != null && res.getDecompiledFunction() != null) {
                    String block = "/* ===== " + f.getName() + " @ " + f.getEntryPoint() + " ===== */\n"
                            + res.getDecompiledFunction().getC() + "\n";
                    if (out != null) {
                        out.print(block);
                    } else {
                        println(block);
                    }
                    ok++;
                }
            } catch (Exception e) {
                // keep going on the other functions
            }
        }
        dec.dispose();
        if (out != null) {
            out.close();
        } else {
            println("/* decompiled functions: " + ok + " */");
        }
    }
}
