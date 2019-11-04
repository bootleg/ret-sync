/*

Copyright (C) 2019, Alexandre Gazet.

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

package main.java.retsync;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.io.FilenameUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class RequestHandler {
    private RetSyncPlugin rsplugin;
    private final Lock clientLock = new ReentrantLock(true);
    private final JSONParser jsonparser = new JSONParser();
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
        noticeHandler = new NoticeHandler(plugin);
        syncHandler = new SyncHandler(plugin);
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
        String tag = null;
        curClient = client;

        tag = RequestType.extract(request);

        if (tag == null) {
            rsplugin.cs.println(String.format("[sync] unknown request"));
            return bExit;
        }

        payload = RequestType.normalize(request, tag);
        try {
            Object obj = jsonparser.parse(payload);

            switch (tag) {
            case RequestType.NOTICE:
                bExit = noticeHandler.parse((JSONObject) obj);
                break;
            case RequestType.SYNC:
                if (rsplugin.syncEnabled) {
                    bExit = syncHandler.parse((JSONObject) obj);
                }
                break;
            }

        } catch (ParseException pe) {
            rsplugin.cs.println(String.format("[x] fail to parse json: %s", payload));
        }

        return bExit;
    }

    public class NoticeHandler {
        private RetSyncPlugin rsplugin;

        public NoticeHandler(RetSyncPlugin plugin) {
            rsplugin = plugin;
        }

        public boolean parse(JSONObject notice) {
            boolean bExit = false;
            String type;

            type = (String) notice.get("type");

            switch (type) {
            // a new debugger client connects
            case "new_dbg":
                String dialect = (String) notice.get("dialect");
                rsplugin.cs.println(String.format("[<] new_dbg: %s", (String) notice.get("msg")));

                if (DebuggerDialects.DIALECTS.containsKey(dialect)) {
                    curClient.dialect = DebuggerDialects.DIALECTS.get(dialect);

                    if (DebuggerDialects.WINDOWS_BASED_DBG.contains(dialect))
                        curClient.isWinOS = true;
                } else
                    dialect = "unknown";

                rsplugin.uiComponent.setConnected(dialect);
                rsplugin.cs.println(String.format("             dialect: %s", dialect));
                break;

                // debugger client disconnects
            case "dbg_quit":
                rsplugin.cs.println(String.format("[<] %s", (String) notice.get("msg")));
                rsplugin.clrs.cbColorFinal();
                rsplugin.uiComponent.resetClient();
                rsplugin.syncEnabled = false;
                rsplugin.program = null;
                curClient = null;
                break;

                // debugger notice that its current module has changed
            case "module":
                rsplugin.syncEnabled = false;
                rsplugin.clrs.cbColorFinal();

                Path modpath = Paths.get((String) notice.get("path"));

                // current OS is Linux/Mac while remote OS is Windows
                if (curClient.isWinOS && System.getProperty("file.separator").equals("/")) {
                    modpath = Paths.get(FilenameUtils.separatorsToUnix(modpath.toString()));
                }

                String modname = modpath.getFileName().toString();

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
                    idbn = Integer.decode((String) notice.get("idb"));
                } catch (NumberFormatException e) {
                    curClient.out.println("[x] idbn: failed to parse index");
                    break;
                }

                if (Integer.compareUnsigned(idbn, pgmList.length) >= 0) {
                    curClient.out.println("[x] idbn: invalid index");
                    break;
                }

                rsplugin.pm.setCurrentProgram(pgmList[idbn]);

                curClient.out.println(
                        String.format("> current program is now: %s", rsplugin.pm.getCurrentProgram().getName()));
                break;

                // color trace request
            case "bc":
                String bc_action = (String) notice.get("msg");
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
                    Long rgb = (Long) notice.get("rgb");
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
        private RetSyncPlugin rsplugin;

        public SyncHandler(RetSyncPlugin plugin) {
            rsplugin = plugin;
        }

        public boolean parse(JSONObject sync) {
            boolean bExit = false;
            String type = (String) sync.get("type");
            Long base = (Long) sync.get("base");
            Long offset = (Long) sync.get("offset");

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

                // add comment request at addr
            case "cmt":
                String cmt = (String) sync.get("msg");
                rsplugin.addCmt(base, offset, cmt);
                break;

                // log command output request at addr
            case "cmd":
                String cmdb64 = (String) sync.get("msg");
                String cmd = new String(Base64.getDecoder().decode(cmdb64.getBytes()));
                rsplugin.addCmt(base, offset, cmd);
                break;

                // reset comment at addr
            case "rcmt":
                rsplugin.resetCmt(base, offset);
                break;

                // add a function comment at addr
            case "fcmt":
                String fcmt = (String) sync.get("msg");
                rsplugin.addFnCmt(base, offset, fcmt);
                break;

                // return program's symbol for a given addr
            case "rln":
                Long ln_rbase = (Long) sync.get("rbase");
                Long ln_raddr = (Long) sync.get("raddr");

                String sym = rsplugin.getSymAt(ln_rbase, ln_raddr);
                if (sym != null) {
                    rsplugin.reqHandler.curClient.sendRaw(sym);
                }
                break;

                // return local address for a given program's symbol
            case "rrln":
                String symName = (String) sync.get("sym");
                List<Symbol> symIter = rsplugin.getSymAddr(symName);

                if (symIter.size() != 1) {
                    rsplugin.cs.println(String.format("[x] ambiguous symbol: %s", symName));
                } else {
                    String symAddrReply = String.format("0x%x", symIter.get(0).getAddress().getOffset());
                    rsplugin.reqHandler.curClient.sendRaw(symAddrReply);
                }
                break;

                // add label request at address
            case "lbl":
                String lbl = (String) sync.get("msg");
                rsplugin.addLabel(base, offset, lbl);
                break;

                // add an address comment request at address
            case "raddr":
                Long rbase = (Long) sync.get("rbase");
                Long raddr = (Long) sync.get("raddr");

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
                String pdb = (String) sync.get("pdb");
                String md5 = (String) sync.get("md5");
                String remote = null;
                String local = null;
                String output = null;

                if (pdb != null) {
                    rsplugin.cs.println("[sync] modcheck (pdb)");
                    local = rsplugin.program.getMetadata().get("PDB GUID").toUpperCase();
                    remote = parseWindbgInput(pdb);

                } else if (md5 != null) {
                    rsplugin.cs.println("[sync] modcheck (md5)");
                    local = rsplugin.program.getExecutableMD5().toUpperCase();
                    remote = md5.replaceAll("\\s", "").toUpperCase();
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
