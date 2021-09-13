/*

Copyright (C) 2019-2021, Alexandre Gazet.

This file is part of ret-sync.

ret-sync is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

package retsync;

import static java.util.Map.entry;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

//@formatter:off
public class DebuggerDialects {

    private static final HashMap<String, String> WINDBG_DIALECT = new HashMap<String, String>(
            Map.ofEntries(
                    entry("prefix", "!"),
                    entry("si", "t"),
                    entry("so", "p"),
                    entry("go", "g"),
                    entry("bp", "bp "),
                    entry("hbp", "ba e 1 "),
                    entry("bp1", "bp /1 "),
                    entry("hbp1", "ba e 1 /1 ")
                    ));

    private static final HashMap<String, String> GDB_DIALECT = new HashMap<String, String>(
            Map.ofEntries(
                    entry("prefix", ""),
                    entry("si", "si"),
                    entry("so", "ni"),
                    entry("go", "continue"),
                    entry("run", "run"),
                    entry("bp", "b *"),
                    entry("hbp", "hb *"),
                    entry("bp1", "tb *"),
                    entry("hbp1", "thb *")
                    ));

    private static final HashMap<String, String> LLDB_DIALECT = new HashMap<String, String>(
            Map.ofEntries(
                    entry("prefix", ""),
                    entry("si", "si"),
                    entry("so", "ni"),
                    entry("go", "continue"),
                    entry("run", "run"),
                    entry("bp", "b *"),
                    entry("hbp", "xxx"),
                    entry("bp1", "tb *"),
                    entry("hbp1", "xxx")
                    ));

    private static final HashMap<String, String> OLLYDBG_DIALECT = new HashMap<String, String>(
            Map.ofEntries(
                    entry("prefix", ""),
                    entry("si", "si"),
                    entry("so", "so"),
                    entry("go", "go"),
                    entry("bp", "bb "),
                    entry("hbp", "xxx "),
                    entry("bp1", "xxx "),
                    entry("hbp1", "xxx ")
                    ));

    private static final HashMap<String, String> X64DBG_DIALECT = new HashMap<String, String>(
            Map.ofEntries(
                    entry("prefix", "!"),
                    entry("si", "sti"),
                    entry("so", "sto"),
                    entry("go", "go"),
                    entry("bp", "bp "),
                    entry("hbp", "bph "),
                    entry("bp1", "bp "),
                    entry("hbp1", "bph "),
                    entry("oneshot_post", ",ss")
                    ));

    public static final HashMap<String, HashMap<String, String>> DIALECTS = new  HashMap<String, HashMap<String, String>>(
            Map.ofEntries(
                    entry("windbg", WINDBG_DIALECT),
                    entry("gdb", GDB_DIALECT),
                    entry("lldb", LLDB_DIALECT),
                    entry("ollydbg2", OLLYDBG_DIALECT),
                    entry("x64_dbg", X64DBG_DIALECT)
                    ));

    public static final List<String> WINDOWS_BASED_DBG = Arrays.asList("windbg", "ollydbg2", "x64_dbg");
}
//@formatter:on
