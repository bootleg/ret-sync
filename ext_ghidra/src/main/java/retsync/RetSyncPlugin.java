/*

Copyright (C) 2019-2022, Alexandre Gazet.

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

import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.ini4j.Ini;
import org.ini4j.Profile.Section;

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
import ghidra.framework.cmd.Command;
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
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;

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
    List<Socket> clients = new ArrayList<Socket>();

    // internal state
    Program program = null;
    Address imageBaseLocal = null;
    Address imageBaseRemote = null;
    Map<String, Long> moduleBaseRemote = Collections.<String, Long>emptyMap();
    Boolean syncEnabled = false;
    Boolean syncModAuto = true;
    Boolean bUseRawAddr = false;
    
    // default configuration
    private static final boolean DEBUG_CALLBACK = false;
    protected static final boolean DEBUG_MODULES = false;
    private static final String CONF_INI_FILE = ".sync";
    protected final String SYNC_HOST_DEFAULT = "localhost";
    protected final int SYNC_PORT_DEFAULT = 9100;

    // dynamic configuration
    protected String SYNC_HOST = SYNC_HOST_DEFAULT;
    protected int SYNC_PORT = SYNC_PORT_DEFAULT;
    protected HashMap<String, String> aliases = new HashMap<String, String>();
    protected boolean bUseEnhancedHighlight = true;
    
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
        syncModAuto = true;
        reqHandler = new RequestHandler(this);
    }

    @Override
    protected void programActivated(Program activatedProgram) {
        imageBaseLocal = activatedProgram.getImageBase();
        String programName = activatedProgram.getName();

        cs.println(String.format("[>] programActivated: %s", programName));

        Long remoteBase = moduleBaseRemote.getOrDefault(programName, null);
        if (remoteBase != null) {
            imageBaseRemote = imageBaseLocal.getNewAddress(remoteBase);
            cs.println(String.format("    local addr: %s, remote: 0x%x", imageBaseLocal.toString(), remoteBase));
        } else {
            imageBaseRemote = null;
            cs.println(String.format("    local addr: %s, remote: unknown", imageBaseLocal.toString()));
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

    // restore default configuration values
    void defaultConfiguration() {
        SYNC_HOST = SYNC_HOST_DEFAULT;
        SYNC_PORT = SYNC_PORT_DEFAULT;
        aliases = new HashMap<String, String>();
    }

    // load configuration file as defined by CONF_INI_FILE
    // tested locations are : user home, Ghidra project directory
    void loadConfiguration() {
        List<String> locations = new ArrayList<String>();
        locations.add(tool.getProject().getProjectLocator().getProjectDir().toPath().toString());
        locations.add(Paths.get(System.getProperty("user.home")).toString());

        for (String loc : locations) {
            if (loadConfigurationFrom(Paths.get(loc, CONF_INI_FILE))) {
                break;
            }
        }
    }

    // look for .sync file
    boolean loadConfigurationFrom(Path filePath) {
        FileInputStream fd = null;
        boolean found = false;

        try {
            if (Files.exists(filePath)) {
                cs.println(String.format("[>] loading configuration file %s", filePath));
                fd = new FileInputStream(filePath.toString());
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

    // read .ini formatted file
    boolean parseIni(FileInputStream fd) {
        boolean found = false;

        try {
            Ini config = new Ini(fd);
            
            Section secGeneral = config.get("GENERAL");
            if (secGeneral != null) {
                Boolean use_raw_addr = Boolean.valueOf(secGeneral.getOrDefault("use_raw_addr", "false"));
                cs.println(String.format("  - using raw addresses: %s", use_raw_addr));
                bUseRawAddr = use_raw_addr;
            }          
            
            Section secNetwork = config.get("INTERFACE");
            if (secNetwork != null) {
                String host = secNetwork.getOrDefault("host", SYNC_HOST);
                cs.println(String.format("  - host: %s", host));

                String port = secNetwork.getOrDefault("port", Integer.toString(SYNC_PORT));
                cs.println(String.format("  - port: %s", port));

                SYNC_HOST = host;
                SYNC_PORT = Integer.parseInt(port);
            }

            Section secAlias = config.get("ALIASES");
            if (secAlias != null) {
                if (secAlias != null) {
                    Set<String> aliasSet = secAlias.keySet();
                    aliasSet.forEach((String fromName) -> {
                        String toName = secAlias.get(fromName);
                        if (!"".equals(toName)) {
                            aliases.put(toName, fromName);
                            cs.println(String.format("  - alias %s -> %s", fromName, toName));
                        }
                    });
                }
            }

            Section secGhidra = config.get("GHIDRA");
            if (secGhidra != null) {
                boolean enhanced_highlight = Boolean.valueOf(secGhidra.getOrDefault("enhanced_highlight", "true"));
                cs.println(String.format("  - enhanced highlight: %s", enhanced_highlight));
                bUseEnhancedHighlight = enhanced_highlight;
            }

            found = true;
        } catch (IOException e) {
            cs.println(String.format("[>] failed to parse conf file: %s", e.getMessage()));
        }

        return found;
    }

    void setRemoteModuleBases(Map<String, Long> bases) {
        moduleBaseRemote = bases;
    }

    void setRemoteBase(long rbase) {
        imageBaseRemote = imageBaseLocal.getNewAddress(rbase);
    }

    boolean isRemoteBaseKnown() {
        return imageBaseRemote != null;
    }

    // compare remote image base with offset
    int cmpRemoteBase(long rbase) {
        return imageBaseRemote.compareTo(imageBaseRemote.getNewAddress(rbase));
    }

    // rebase remote address with respect to
    // current program image base and update remote base address
    Address rebase(long base, long offset) {
        imageBaseRemote = imageBaseLocal.getNewAddress(base);
        return rebaseLocal(imageBaseLocal.getNewAddress(offset));
    }

    // rebase remote address with respect to
    // local program image base
    Address rebaseLocal(Address loc) {
        Address dest;
        
        if (bUseRawAddr)
        	return loc;
        
        if (program == null)
            return null;

        try {
            dest = imageBaseLocal.addNoWrap(loc.subtract(imageBaseRemote));
        } catch (AddressOverflowException e) {
            cs.println(String.format("[x] unsafe rebase local (wrap): %s - %s", imageBaseRemote, loc));
            return null;
        }

        if (!dest.getAddressSpace().isLoadedMemorySpace()) {
            cs.println(String.format("[x] unsafe rebase local: %s", loc));
            return null;
        }

        return dest;
    }

    // rebase remote address with respect to
    // local program image base
    // method overloading for long type
    Address rebaseLocal(long offset) {
        return rebaseLocal(imageBaseLocal.getNewAddress(offset));
    }

    // rebase local address with respect to
    // remote program image base
    Address rebaseRemote(Address loc) {
        Address dest;
        
        if (bUseRawAddr)
        	return loc;
        
        if (program == null)
            return null;
        
        try {
            dest = imageBaseRemote.addNoWrap(loc.subtract(imageBaseLocal));
        } catch (AddressOverflowException e) {
            cs.println(String.format("[x] unsafe rebase remote (wrap): %s - %s", imageBaseRemote, loc));
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
        AppendCommentCmd cmd;

        dest = rebase(base, offset);

        if (dest != null) {
            cmd = new AppendCommentCmd(dest, CodeUnit.EOL_COMMENT, msg, ";");
            res = doTransaction(cmd, "sync-add-cmt");
        }

        if (!res) {
            cs.println("[sync] failed to add comment");
        }
    }

    void addFnCmt(long base, long offset, String msg) {
        Address dest = null;
        boolean res = false;
        SetFunctionRepeatableCommentCmd cmd;
        FunctionManager fm;
        Function func;

        dest = rebase(base, offset);

        if (dest != null) {
            fm = program.getFunctionManager();
            func = fm.getFunctionContaining(dest);

            if (func != null) {
                cmd = new SetFunctionRepeatableCommentCmd(func.getEntryPoint(), msg);
                res = doTransaction(cmd, "sync-add-fcmt");
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
        SetCommentCmd cmd;

        dest = rebase(base, offset);

        if (dest != null) {
            cmd = new SetCommentCmd(dest, CodeUnit.EOL_COMMENT, "");
            res = doTransaction(cmd, "sync-reset-cmt");
        }

        if (!res) {
            cs.println("[sync] failed to reset comment");
        }
    }

    void addLabel(long base, long offset, String msg) {
        Address dest = null;
        boolean res = false;
        AddLabelCmd cmd;

        dest = rebase(base, offset);

        if (dest != null) {
            cmd = new AddLabelCmd(dest, msg, SourceType.USER_DEFINED);
            res = doTransaction(cmd, "sync-add-lbl");
        }

        if (!res) {
            cs.println("[sync] failed to add label");
        }
    }

    boolean doTransaction(Command cmd, String tName) {
        boolean res = false;
        int transactionID = program.startTransaction(tName);

        try {
            res = cmd.applyTo(program);
        } finally {
            program.endTransaction(transactionID, true);
        }

        return res;
    }

    String getSymAt(Address symAddr) {
        String symName = null;

        if (symAddr == null) {
            cs.println(String.format("[x] failed to get symbol at null address"));
            return null;
        }

        SymbolTable symTable = program.getSymbolTable();

        // look for 'first-hand' symbol (function name, label, etc.)
        Symbol sym = symTable.getPrimarySymbol(symAddr);
        if (sym != null) {
            symName = sym.getName();
            cs.println(String.format("[>] solved primary sym %s@%s", symName, symAddr));
        }

        // return offset with respect to function's entry point
        if (symName == null) {
            FunctionManager fm = program.getFunctionManager();
            Function fn = fm.getFunctionContaining(symAddr);

            if (fn != null) {
                Address ep = fn.getEntryPoint();
                if (symAddr.compareTo(ep) > 0) {
                    symName = String.format("%s+0x%x", fn.getName(), symAddr.subtract(ep));
                } else {
                    symName = String.format("%s-0x%x", fn.getName(), ep.subtract(symAddr));
                }
                cs.println(String.format("[>] solved sym %s@%s", symName, symAddr));
            }
        }

        if (symName == null) {
            cs.println(String.format("[sync] failed to get symbol at %s", symAddr));
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

    Address getCursor() {
        Address curAddr = null;
        ProgramLocation cLoc = cvs.getListingPanel().getCursorLocation();

        if (cLoc == null) {
            cs.println("[sync] failed to get cursor location");
        } else {
            curAddr = rebaseRemote(cLoc.getAddress());
        }

        return curAddr;
    }

}
