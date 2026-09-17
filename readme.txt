Simple SpectreV1 reproducer that is verified working on bare-metal Skylake-X based Linux machine.
This doesn't achieve anything remotely interesting; All it does is prove that cache timing side-channels
still work on Intel machines (likely AMD too). A hardened branch-predictor or explicit compiler/runtime
mitigation flags would render this non-functional but as far as I know, CPU vendors expect software
to deal with SpectreV1-esq attacks rather than solve it in hardware so this should work on modern
Intel/AMD machines too.

Compile: g++ -O1 main.cpp -o main
Run: ./main 160 2

The two optional arguments to the program are `threshold` and `hits`. `threshold` describes the threshold
(in cycles) below which a probed cache line is considered cached. The program runs a few rounds of the
train -> flush -> load -> probe cycle; 'hits' determines how many times the cache line probe must fall
below `threshold` to be considered signal. If you're trying the reproducer on a different machine, you
might have to tweak `threshold` and `hit` for favorable results.
