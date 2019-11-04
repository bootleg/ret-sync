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

import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.comments.AppendCommentCmd;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.function.SetFunctionRepeatableCommentCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;;

// @formatter:off
@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = CorePluginPackage.NAME,
        category = PluginCategoryNames.NAVIGATION,
        shortDescription = "Reverse-Engineering Tools synchronization, ret-sync .",
        description = "Synchronize a debugging session with Ghidra.",
        servicesRequired = {
                ProgramManager.class,
                ConsoleService.class,
                CodeViewerService.class,
                GoToService.class },
        eventsConsumed = {
                ProgramActivatedPluginEvent.class,
                ProgramClosedPluginEvent.class }
        )
// @formatter:on

public class RetSyncPlugin extends ProgramPlugin {
    private static final boolean DEBUG_CALLBACK = false;
    public RetSyncComponent uiComponent;

    // services
    ConsoleService cs;
    GoToService gs;
    CodeViewerService cvs;
    ProgramManager pm;
    LocalColorizerService clrs;

    // client handling
    ListenerBackground server;
    RequestHandler reqHandler;

    // internal state
    Program program = null;
    Address imageBaseLocal = null;
    Address imageBaseRemote = null;
    Boolean syncEnabled = false;

    List<Socket> clients = new ArrayList<Socket>();

    // default configuration
    private static final String CONF_INI_FILE = ".sync";
    protected String SYNC_HOST = "localhost";
    protected int SYNC_PORT = 9100;

    public RetSyncPlugin(PluginTool tool) {
        super(tool, true, true);

        String pluginName = getName();
        uiComponent = new RetSyncComponent(this, pluginName);
    }

    @Override
    public void init() {
        super.init();

        cs = tool.getService(ConsoleService.class);
        cs.println("[*] retsync init");

        gs = tool.getService(GoToService.class);
        pm = tool.getService(ProgramManager.class);
        cvs = tool.getService(CodeViewerService.class);
        clrs = new LocalColorizerService(this);

        loadConfiguration();

        syncEnabled = false;
        reqHandler = new RequestHandler(this);
    }

    @Override
    protected void programActivated(Program activatedProgram) {
        imageBaseLocal = activatedProgram.getImageBase();
        if (DEBUG_CALLBACK) {
            cs.println(String.format("[>] programActivated: %s", activatedProgram.getName()));
        }
    }

    @Override
    protected void programDeactivated(Program deactivatedProgram) {
        if (DEBUG_CALLBACK) {
            cs.println(String.format("[>] programDeactivated: %s", deactivatedProgram.getName()));
        }
    }

    @Override
    protected void programOpened(Program openedProgram) {
        String pname = openedProgram.getName();
        cs.println(String.format("[>] programOpened: %s", pname));
        cs.println(String.format("    imageBase: 0x%x", openedProgram.getImageBase().getUnsignedOffset()));
    }

    @Override
    protected void programClosed(Program closedProgram) {
        cs.println(String.format("[>] programClosed: %s", closedProgram.getName()));

        if (program != null) {
            if (program.equals(closedProgram)) {
                // cleanup state
                clrs.cbColorFinal(program);
                program = null;
                syncEnabled = false;
            }
        }

        // stop the listener if current program is the last one open
        Program[] pgmList = pm.getAllOpenPrograms();
        if (pgmList.length == 0) {
            clrs.disableTrace();
            if (server != null) {
                server.stop();
            }
        }
    }

    void setActiveProgram(Program activeProgram) {
        program = activeProgram;
        pm.setCurrentProgram(program);
        cs.println(String.format("[>] set current program: %s", activeProgram.getName()));
        uiComponent.setProgram(activeProgram.getName());
        clrs.setProgram(activeProgram);
        syncEnabled = true;
    }

    void serverStart() {
        if (server == null) {
            server = new ListenerBackground(this);
            try {
                server.bind();
                new Thread(server).start();
                uiComponent.resetClient();
                cs.println("[>] server started");
            } catch (IOException e) {
                cs.println(String.format("[x] server startup failed (%s)", e.getMessage()));
                server.stop();
                server = null;
                uiComponent.resetStatus();
            }
        } else {
            cs.println("[!] server already started");
        }
    }

    void serverStop() {
        if (server == null) {
            cs.println("[!] server not started");
        } else {
            server.stop();
            cs.println("[>] server stopped");
            clrs.cbColorFinal();
            server = null;
            program = null;
            syncEnabled = false;
            uiComponent.resetStatus();
        }
    }

    // load configuration file as defined by CONF_INI_FILE
    // tested locations are : user home, Ghidra project directory
    void loadConfiguration() {
        List<String> locations = new ArrayList<String>();
        locations.add(Paths.get(System.getProperty("user.home")).toString());
        locations.add(tool.getProject().getProjectLocator().getLocation());

        for (String loc : locations) {
            if (loadConfigurationFrom(Paths.get(loc, CONF_INI_FILE).toString())) {
                cs.println(String.format("[>] configuration loaded from %s", loc));
                break;
            }
        }
    }

    // read .ini formatted file
    boolean loadConfigurationFrom(String filePath) {
        FileInputStream fd = null;
        boolean found = false;

        try {
            if (Files.exists(Paths.get(filePath))) {
                fd = new FileInputStream(filePath);
                found = parseIni(fd);
            }
        } catch (IOException e) {
            cs.println(String.format("[>] failed to read conf file: %s", e.getMessage()));
        } finally {
            try {
                if (fd != null)
                    fd.close();
            } catch (IOException ex) {
            }
        }

        return found;
    }

    boolean parseIni(FileInputStream fd) {
        boolean found = false;

        Properties props = new Properties();
        try {
            props.load(fd);

            String host = props.getProperty("host", SYNC_HOST);
            cs.println(String.format("[>] host: %s", host));
            String port = props.getProperty("port", Integer.toString(SYNC_PORT));
            cs.println(String.format("[>] port: %s", port));

            SYNC_HOST = host;
            SYNC_PORT = Integer.parseInt(port);
            found = true;
        } catch (IOException e) {
            cs.println(String.format("[>] failed to parse conf file: %s", e.getMessage()));
        }

        return found;
    }

    // rebase remote address with respect to
    // current program image base
    Address rebase(long base, long offset) {
        Address dest;

        if (program == null)
            return null;

        try {
            dest = imageBaseLocal.addNoWrap(offset - base);
        } catch (AddressOverflowException e) {
            cs.println(String.format("[x] unsafe rebase (wrap): 0x%x - 0x%x", base, offset));
            return null;
        }

        if (!dest.getAddressSpace().isLoadedMemorySpace()) {
            cs.println(String.format("[x] unsafe rebase: 0x%x - 0x%x", base, offset));
            return null;
        }

        if (imageBaseRemote == null) {
            imageBaseRemote = imageBaseLocal.getNewAddress(base);
        }

        return dest;
    }

    // compare remote image base with
    // offset from arg
    int cmpRemoteBase(long rbase) {
        return imageBaseRemote.compareTo(imageBaseRemote.getNewAddress(rbase));
    }

    // rebase local address with respect to
    // remote program image base
    Address rebase_remote(Address loc) {
        Address dest;

        if (program == null)
            return null;

        try {
            dest = imageBaseRemote.addNoWrap(loc.subtract(imageBaseLocal));
        } catch (AddressOverflowException e) {
            cs.println(String.format("[x] unsafe rebase remote (wrap): 0x%x - 0x%x", imageBaseRemote, loc));
            return null;
        }

        if (!dest.getAddressSpace().isLoadedMemorySpace()) {
            cs.println(String.format("[x] unsafe rebase remote: 0x%x", loc.getOffset()));
            return null;
        }

        return dest;
    }

    void gotoLoc(long base, long offset) {
        Address dest = null;

        if (!syncEnabled)
            return;

        dest = rebase(base, offset);

        if (dest != null) {
            gs.goTo(dest);
            clrs.setPrevAddr(dest);
        }
    }

    void addCmt(long base, long offset, String msg) {
        Address dest = null;
        boolean res = false;
        int transactionID;
        AppendCommentCmd cmd;

        dest = rebase(base, offset);

        if (dest != null) {
            transactionID = program.startTransaction("sync-add-cmt");
            try {
                cmd = new AppendCommentCmd(dest, CodeUnit.EOL_COMMENT, msg, ";");
                res = cmd.applyTo(program);
                cs.println(String.format("[x] cmd.applyTo %s", res));
            } catch (Exception e) {
                throw e;
            } finally {
                program.endTransaction(transactionID, true);
            }
        }

        if (!res) {
            cs.println("[sync] failed to add comment");
        }
    }

    void addFnCmt(long base, long offset, String msg) {
        Address dest = null;
        boolean res = false;
        int transactionID;
        SetFunctionRepeatableCommentCmd cmd;
        FunctionManager fm;
        Function func;

        dest = rebase(base, offset);

        if (dest != null) {
            fm = program.getFunctionManager();
            func = fm.getFunctionContaining(dest);

            if (func != null) {
                transactionID = program.startTransaction("sync-add-fcmt");
                try {
                    cmd = new SetFunctionRepeatableCommentCmd(func.getEntryPoint(), msg);
                    res = cmd.applyTo(program);
                } finally {
                    program.endTransaction(transactionID, true);
                }
            } else {
                cs.println(String.format("[x] no function associated with address 0x%x", dest.getOffset()));
            }
        }

        if (!res) {
            cs.println("[sync] failed to add function comment");
        }
    }

    void resetCmt(long base, long offset) {
        Address dest = null;
        boolean res = false;
        int transactionID;
        SetCommentCmd cmd;

        dest = rebase(base, offset);

        if (dest != null) {
            transactionID = program.startTransaction("sync-reset-cmt");
            try {
                cmd = new SetCommentCmd(dest, CodeUnit.EOL_COMMENT, "");
                res = cmd.applyTo(program);
            } finally {
                program.endTransaction(transactionID, true);
            }
        }

        if (!res) {
            cs.println("[sync] failed to reset comment");
        }
    }

    void addLabel(long base, long offset, String msg) {
        Address dest = null;
        boolean res = false;
        int transactionID;
        AddLabelCmd cmd;

        dest = rebase(base, offset);

        if (dest != null) {
            transactionID = program.startTransaction("sync-add-lbl");
            try {
                cmd = new AddLabelCmd(dest, msg, SourceType.USER_DEFINED);
                res = cmd.applyTo(program);
            } finally {
                program.endTransaction(transactionID, true);
            }
        }

        if (!res) {
            cs.println("[sync] failed to add label");
        }
    }

    String getSymAt(long base, long offset) {
        Address dest = null;
        String symName = null;
        SymbolTable symTable = program.getSymbolTable();

        dest = rebase(base, offset);
        if (dest != null) {
            // look for 'first-hand' symbol (function name, label, etc.)
            Symbol sym = symTable.getPrimarySymbol(dest);
            if (sym != null) {
                symName = sym.getName();
            }

            // return offset with respect to function's entry point
            if (symName == null) {
                FunctionManager fm = program.getFunctionManager();
                Function fn = fm.getFunctionContaining(dest);

                if (fn != null) {
                    Address ep = fn.getEntryPoint();
                    if (dest.compareTo(ep) > 0) {
                        symName = String.format("%s+0x%x", fn.getName(), dest.subtract(ep));
                    } else {
                        symName = String.format("%s-0x%x", fn.getName(), ep.subtract(dest));
                    }
                }
            }

            if (symName != null) {
                cs.println(String.format("[>] solved sym %s @ 0x%x", symName, dest.getOffset()));
            } else {
                cs.println(String.format("[sync] failed to get symbol at 0x%x", dest.getOffset()));
            }
        }
        return symName;
    }

    List<Symbol> getSymAddr(String symName) {
        SymbolTable symTable = program.getSymbolTable();

        List<Symbol> syms = symTable.getSymbols(symName, null);

        if (syms.isEmpty()) {
            cs.println(String.format("[sync] failed to find symbol %s", symName));
        }

        return syms;
    }
}
