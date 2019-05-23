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

package retsync;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.comments.AppendCommentCmd;
import ghidra.app.events.ProgramActivatedPluginEvent;
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
import ghidra.program.model.listing.Program;

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
		eventsConsumed = { ProgramActivatedPluginEvent.class })
// @formatter:on

public class RetSyncPlugin extends ProgramPlugin {
	public RetSyncComponent provider;
	// services
	ConsoleService cs;
	GoToService gs;
	CodeViewerService cvs;
	ProgramManager pm;
	// client handling
	ListenerBackground server;
	RequestHandler reqHandler;
	// internal state
	Program program = null;
	Address imageBase = null;
	Address imageBaseRemote = null;
	Boolean syncEnabled;
	List<Socket> clients = new ArrayList<Socket>();

	// default configuration
	private static final String CONF_INI_FILE = ".sync";
	protected String SYNC_HOST = "localhost";
	protected int SYNC_PORT = 9100;

	public RetSyncPlugin(PluginTool tool) {
		super(tool, true, true);

		String pluginName = getName();
		provider = new RetSyncComponent(this, pluginName);
	}

	@Override
	public void init() {
		super.init();

		cs = tool.getService(ConsoleService.class);
		if (cs == null) {
			cs.printlnError("[x] failed acquired ConsoleService");
		}

		cs.println("[+] ConsoleService acquired with success");

		gs = tool.getService(GoToService.class);
		if (cs == null) {
			cs.printlnError("[x] failed acquired GoToService");
		}

		cs.println("[+] GoToService acquired with success");

		pm = tool.getService(ProgramManager.class);
		if (pm == null) {
			cs.printlnError("[x] failed acquired ProgramManager");
		}

		cs.println("[+] ProgramManager acquired with success");

		cvs = tool.getService(CodeViewerService.class);
		if (pm == null) {
			cs.printlnError("[x] failed acquired CodeViewerService");
		}

		cs.println("[+] CodeViewerService acquired with success");

		loadConfiguration();

		syncEnabled = false;
		reqHandler = new RequestHandler(this);
	}

	@Override
	protected void programActivated(Program activatedProgram) {
		cs.println(String.format("[>] programActivated: %s", activatedProgram.getName()));
		this.imageBase = activatedProgram.getImageBase();
		cs.println(String.format("    imageBase: 0x%x", imageBase.getUnsignedOffset()));
	}

	@Override
	protected void programOpened(Program openedProgram) {
		String pname = openedProgram.getName();
		cs.println(String.format("[>] programOpened: %s", pname));
	}

	@Override
	protected void programClosed(Program closedProgram) {
		if (this.program != null) {
			if (this.program.equals(closedProgram)) {
				String pname = closedProgram.getName();
				cs.println(String.format("[>] programClosed: %s", pname));
				this.program = null;
				this.syncEnabled = false;
			}
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
			fd = new FileInputStream(filePath);
			found = parseIni(fd);
		} catch (IOException e) {
			cs.println(String.format("[>] failed to read conf file: %s", e.getMessage()));
		} finally {
			try {
				if (fd != null)
					fd.close();
			} catch (IOException ex) {
			}
		}
		System.out.println(filePath.toString());

		return found;
	}

	boolean parseIni(FileInputStream fd) {
		boolean found = false;

		Properties props = new Properties();
		try {
			props.load(fd);

			String host = props.getProperty("host");
			cs.println(String.format("[>] host: %s", host));
			String port = props.getProperty("port");
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
			dest = imageBase.addNoWrap(offset - base);
		} catch (AddressOverflowException e) {
			cs.println(String.format("[x] unsafe rebase (wrap): 0x%x - 0x%x", base, offset));
			return null;
		}

		if (!dest.getAddressSpace().isLoadedMemorySpace()) {
			cs.println(String.format("[x] unsafe rebase: 0x%x - 0x%x", base, offset));
			return null;
		}

		if (imageBaseRemote == null) {
			imageBaseRemote = imageBase.getNewAddress(base);
		}

		return dest;
	}

	// rebase local address with respect to
	// remote program image base
	Address rebase_remote(Address loc) {
		Address dest;

		if (this.program == null)
			return null;

		try {
			dest = imageBaseRemote.addNoWrap(loc.subtractNoWrap(imageBase.getUnsignedOffset()).getUnsignedOffset());
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
			} finally {
				program.endTransaction(transactionID, true);
			}
		}

		if (!res) {
			cs.println("[sync] failed to add comment");
		}
	}

	public class Status {
		public static final String IDLE = "idle";
		public static final String ENABLED = "listening";
		public static final String RUNNING = "connected";
	}
}
