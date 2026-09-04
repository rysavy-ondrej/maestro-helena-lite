# Source before running ./bin/risingwave when the system has no libpython3.12.
#   source bin/env.sh && ./bin/risingwave single_node --store-directory ./.rwdata
_bin="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -d "$_bin/lib" ] && export LD_LIBRARY_PATH="$_bin/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
