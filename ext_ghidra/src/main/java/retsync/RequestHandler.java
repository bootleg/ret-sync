/*

Copyright (C) 2019-2020, Alexandre Gazet.

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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.io.FilenameUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class RequestHandler {
    private RetSyncPlugin rsplugin;
    private final Lock clientLock = new ReentrantLock(true);
    private NoticeHandler noticeHandler;
    private SyncHandler syncHandler;
    ClientHandler curClient;

    public static class RequestType {
        public static final String NOTICE = "[notice]";
        public static final String SYNC = "[sync]";

        public static String extract(String request) {
            String tag = null;

            if (request.startsWith("[notice]")) {
                tag = RequestType.NOTICE;
            } else if (request.startsWith("[sync]")) {
                tag = RequestType.SYNC;
            }

            return tag;
        }

        public static String normalize(String request, String tag) {
            return request.substring(tag.length()).replace("\\", "\\\\").replace("\n", "");
        }
    }

    public RequestHandler(RetSyncPlugin plugin) {
        rsplugin = plugin;
        noticeHandler = new NoticeHandler();
        syncHandler = new SyncHandler();
    }

    public void lock() {
        clientLock.lock();
    }

    public void unlock() {
        clientLock.unlock();
    }

    public boolean parse(ClientHandler client, String request) {
        boolean bExit = false;
        String payload;
        String tag;

        curClient = client;
        tag = RequestType.extract(request);

        if (tag == null) {
            rsplugin.cs.println(String.format("[sync] unknown request"));
            return bExit;
        }

        payload = RequestType.normalize(request, tag);
        try {
            JSONTokener tokener = new JSONTokener(payload);
            JSONObject jsonObj = new JSONObject(tokener);

            switch (tag) {
            case RequestType.NOTICE:
                bExit = noticeHandler.parse(jsonObj);
                break;
            case RequestType.SYNC:
                if (rsplugin.syncEnabled) {
                    bExit = syncHandler.parse(jsonObj);
                }
                break;
            }
        } catch (JSONException exc) {
            rsplugin.cs.println(String.format("[x] fail to parse json request: %s\n<< %s", exc.toString(), payload));
        }

        return bExit;
    }

    public class NoticeHandler {

        public NoticeHandler() {
        }

        private String getNormalizedFileName(String pathString) {
            Path path = Paths.get(pathString);

            // current OS is Linux/Mac while remote OS is Windows
            if (curClient.isWinOS && System.getProperty("file.separator").equals("/")) {
                path = Paths.get(FilenameUtils.separatorsToUnix(path.toString()));
            }

            return path.getFileName().toString();
        }

        public boolean parse(JSONObject notice) {
            boolean bExit = false;
            String type = notice.getString("type");

            switch (type) {
            // a new debugger client connects
            case "new_dbg":
                String dialect = notice.getString("dialect");
                rsplugin.cs.println(String.format("[<] new_dbg: %s", notice.getString("msg")));

                if (DebuggerDialects.DIALECTS.containsKey(dialect)) {
                    curClient.dialect = DebuggerDialects.DIALECTS.get(dialect);

                    if (DebuggerDialects.WINDOWS_BASED_DBG.contains(dialect))
                        curClient.isWinOS = true;
                } else
                    dialect = "unknown";

                rsplugin.uiComponent.setConnected(dialect);
                rsplugin.clrs.startEnhancedDecompHighlight();
                rsplugin.cs.println(String.format("             dialect: %s", dialect));
                break;

                // debugger client disconnects
            case "dbg_quit":
                rsplugin.cs.println(String.format("[<] %s", notice.getString("msg")));
                rsplugin.clrs.cbColorFinal();
                rsplugin.clrs.stopEnhancedDecompHighlight();
                rsplugin.uiComponent.resetClient();
                rsplugin.syncEnabled = false;
                rsplugin.program = null;
                curClient = null;
                break;

                // debugger encountered an error
            case "dbg_err":
                rsplugin.clrs.cbColorFinal();
                rsplugin.syncEnabled = false;
                rsplugin.cs.println(String.format("[<] dbg err: disabling current program"));
                break;

                // debugger notice that its current module has changed
            case "module":
                rsplugin.syncEnabled = false;
                rsplugin.clrs.cbColorFinal();

                String modname = getNormalizedFileName(notice.getString("path"));

                if (RetSyncPlugin.DEBUG_MODULES)
                    rsplugin.cs.println(String.format("[<] module: %s", modname));

                if (notice.has("modules")) {
                    Map<String, Long> bases = new HashMap<String, Long>();
                    JSONArray modules = notice.getJSONArray("modules");

                    if (RetSyncPlugin.DEBUG_MODULES)
                        rsplugin.cs.println(String.format("            modules:"));

                    for (int i = 0; i < modules.length(); i++) {
                        JSONObject mod = modules.getJSONObject(i);
                        String modname2 = getNormalizedFileName(mod.getString("path"));
                        modname2 = rsplugin.aliases.getOrDefault(modname2, modname2);
                        long base = mod.getLong("base");

                        if (RetSyncPlugin.DEBUG_MODULES) {
                            if (bases.putIfAbsent(modname2, base) == null) {
                                rsplugin.cs.println(String.format("               0x%x %s", base, modname2));
                            } else {
                                rsplugin.cs.println(String.format("               0x%x %s [SKIPPED]", base, modname2));
                            }
                        }
                    }
                    rsplugin.setRemoteModuleBases(bases);
                }

                // handle sync mode
                if (!rsplugin.syncModAuto) {
                    rsplugin.cs.println(String.format("[!] sync mod auto off, dropping mod request (%s)", modname));
                    break;
                }

                // handle name aliasing, requested module name is overwritten on-the-fly
                if (rsplugin.aliases.containsKey(modname)) {
                    modname = rsplugin.aliases.get(modname);
                }

                // check if mod from request is the same as the current program
                if (rsplugin.program != null) {
                    if (rsplugin.program.getName().equalsIgnoreCase(modname)) {
                        rsplugin.cs.println(String.format("[-] already enabled"));
                        rsplugin.setActiveProgram(rsplugin.program);
                        break;
                    }
                }

                // find program in list of open programs
                for (Program pgm : rsplugin.pm.getAllOpenPrograms()) {
                    if (pgm.getName().equalsIgnoreCase(modname)) {
                        rsplugin.setActiveProgram(pgm);
                        break;
                    }
                }

                if (!rsplugin.syncEnabled) {
                    rsplugin.cs.println(String.format("[x] program unavailable: %s", modname));
                }
                break;

                // sync mode tells if program switch is automatic or manual
            case "sync_mode":
                String auto = notice.getString("auto");
                rsplugin.cs.println(String.format("[<] sync mod auto: %s", auto));

                switch (auto) {
                case "on":
                    rsplugin.syncModAuto = true;
                    break;
                case "off":
                    rsplugin.syncModAuto = false;
                    break;
                default:
                    rsplugin.cs.println(String.format("[x] sync mod unknown: %s", auto));
                    break;
                }

                break;

                // send list of currently open programs
            case "idb_list":
                StringBuffer output = new StringBuffer();
                int idx = 0;

                output.append("open program(s):\n");

                for (Program pgm : rsplugin.pm.getAllOpenPrograms()) {
                    String isCurrent = rsplugin.pm.getCurrentProgram().equals(pgm) ? "(*)" : "";
                    output.append(String.format("  [%d] %s %s\n", idx++, pgm.getName(), isCurrent));
                }

                rsplugin.cs.println(String.format("[<] %s", output.toString()));
                curClient.out.println(output.toString());
                break;

                // manually set current active program to program 'n' from program list
            case "idb_n":
                int idbn;
                Program[] pgmList = rsplugin.pm.getAllOpenPrograms();

                try {
                    idbn = Integer.decode(notice.getString("idb"));
                } catch (NumberFormatException e) {
                    curClient.out.println(String.format("> idb_n error: n should be a decimal value"));
                    break;
                }

                if (Integer.compareUnsigned(idbn, pgmList.length) >= 0) {
                    curClient.out.println(String.format("> idb_n error: index %d is invalid (see idblist)", idbn));
                    break;
                }

                rsplugin.setActiveProgram(pgmList[idbn]);
                curClient.out.println(
                        String.format("> active program is now \"%s\" (%d)", rsplugin.program.getName(), idbn));
                break;

                // color trace request
            case "bc":
                String bc_action = notice.getString("msg");
                rsplugin.cs.println(String.format("[*] bc: bc_action (%s)", bc_action));

                switch (bc_action) {
                case "oneshot":
                    rsplugin.clrs.oneShotTrace();
                    break;

                case "on":
                    rsplugin.cs.println("[*] color trace enable");
                    rsplugin.clrs.enableTrace();
                    break;

                case "off":
                    rsplugin.cs.println("[*] color trace disable");
                    rsplugin.clrs.disableTrace();
                    break;

                case "set":
                    Long rgb = notice.getLong("rgb");
                    rsplugin.clrs.setTraceColor(rgb.intValue() & 0xffffff);
                    rsplugin.cs.println(String.format("[*] trace color set to 0x%x", rgb));
                    break;

                default:
                    rsplugin.cs.println(String.format("[x] bc: invalid request (%s)", bc_action));
                    break;
                }
                break;

            default:
                rsplugin.cs.println(String.format("[<] notice not implemented: %s", type));
                break;
            }

            return bExit;
        }
    }

    public class SyncHandler {
        private String type = "";
        private Long base = 0L;
        private Long offset = 0L;
        private Long raddr = 0L;
        private Long rbase = 0L;

        public SyncHandler() {

        }

        public boolean parse(JSONObject sync) {
            boolean bExit = false;
            type = sync.getString("type");
            base = sync.optLong("base");
            offset = sync.optLong("offset");

            switch (type) {
            // location request, update program's listing/graph view
            case "loc":
                if (rsplugin.program == null) {
                    break;
                }

                rsplugin.clrs.cbColorPre();

                // rsplugin.program (from mod request) is set as current program
                if (!rsplugin.program.equals(rsplugin.pm.getCurrentProgram())) {
                    rsplugin.pm.setCurrentProgram(rsplugin.program);
                }

                rsplugin.gotoLoc(base, offset);
                rsplugin.clrs.cbColorPost();
                break;

                // force remote address base for current program

            case "rbase":
                rbase = sync.getLong("rbase");
                rsplugin.setRemoteBase(rbase);
                break;

                // add comment request at addr
            case "cmt":
                String cmt = sync.getString("msg");
                rsplugin.addCmt(base, offset, cmt);
                break;

                // log command output request at addr
            case "cmd":
                String cmdb64 = sync.getString("msg");
                String cmd = new String(Base64.getDecoder().decode(cmdb64.getBytes()));
                rsplugin.addCmt(base, offset, cmd);
                break;

                // reset comment at addr
            case "rcmt":
                rsplugin.resetCmt(base, offset);
                break;

                // add a function comment at addr
            case "fcmt":
                String fcmt = sync.getString("msg");
                rsplugin.addFnCmt(base, offset, fcmt);
                break;

                // return program's symbol for a given addr
            case "rln":
                raddr = sync.getLong("raddr");
                Address reqAddr = rsplugin.rebaseLocal(raddr);
                String sym = rsplugin.getSymAt(reqAddr);
                if (sym != null) {
                    rsplugin.reqHandler.curClient.sendRaw(sym);
                }
                break;

                // return local address for a given program's symbol
            case "rrln":
                String symName = sync.getString("sym");
                List<Symbol> symIter = rsplugin.getSymAddr(symName);

                if (symIter.size() != 1) {
                    rsplugin.cs.println(String.format("[x] ambiguous symbol: %s", symName));
                } else {
                    Address symAddr = symIter.get(0).getAddress();
                    symAddr = rsplugin.rebaseRemote(symAddr);
                    if (symAddr != null) {
                        String symAddrReply = String.format("0x%x", symAddr.getOffset());
                        rsplugin.reqHandler.curClient.sendRaw(symAddrReply);
                    }
                }
                break;

                // add label request at address
            case "lbl":
                String lbl = sync.getString("msg");
                rsplugin.addLabel(base, offset, lbl);
                break;

                // add an address comment request at address
            case "raddr":
                rbase = sync.getLong("rbase");
                raddr = sync.getLong("raddr");

                if (rsplugin.cmpRemoteBase(rbase) == 0) {
                    Address target = rsplugin.rebase(rbase, raddr);
                    if (target != null) {
                        String raddr_cmt = String.format("0x%x (rebased from 0x%x)", target.getOffset(), raddr);
                        rsplugin.addCmt(base, offset, raddr_cmt);
                    }
                }
                break;

                // compare loaded module md5 with program's input file md5
            case "modcheck":
                String remote = null;
                String local = null;
                String output = null;

                if (sync.has("pdb")) {
                    rsplugin.cs.println("[sync] modcheck (pdb)");
                    local = rsplugin.program.getMetadata().get("PDB GUID").toUpperCase();
                    remote = parseWindbgInput(sync.getString("pdb"));

                } else if (sync.has("md5")) {
                    rsplugin.cs.println("[sync] modcheck (md5)");
                    local = rsplugin.program.getExecutableMD5().toUpperCase();
                    remote = sync.getString("md5").replaceAll("\\s", "").toUpperCase();
                }

                if (local != null && remote != null) {
                    rsplugin.cs.println(String.format("     local: %s", local));
                    rsplugin.cs.println(String.format("    remote: %s", remote));

                    if (local.equals(remote)) {
                        output = "[+] module successfully matched";
                    } else {
                        output = "[!] warning, modules mismatch";
                    }
                } else {
                    output = "[x] modcheck failed";
                }

                rsplugin.cs.println(output);
                rsplugin.reqHandler.curClient.sendRaw(output);
                break;

                // return current cursor position
            case "cursor":
                Address cursor = rsplugin.getCursor();
                if (cursor == null) {
                    rsplugin.cs.println("[x] failed to get cursor position");
                } else {
                    rsplugin.reqHandler.curClient.sendRaw(cursor.toString());
                }
                break;

            default:
                rsplugin.cs.println(String.format("[<] cmd not implemented: %s", type));
                break;
            }

            return bExit;
        }

        private String parseWindbgInput(String pdbInfo) {
            String output = null;
            String itoldyouso = new String(Base64.getDecoder().decode(pdbInfo.getBytes()));
            Scanner scanner = new Scanner(itoldyouso);

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();

                if (line.strip().startsWith("pdb sig")) {
                    output = line.split(":")[1].strip().toUpperCase();
                    break;
                }
            }

            scanner.close();
            return output;
        }
    }
}
