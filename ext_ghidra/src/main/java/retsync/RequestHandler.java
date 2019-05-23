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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import ghidra.program.model.listing.Program;
import retsync.RetSyncPlugin.Status;

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
				bExit = syncHandler.parse((JSONObject) obj);
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
				rsplugin.provider.setClient(dialect);
				rsplugin.provider.setStatus(Status.RUNNING);

				if (DebuggerDialects.DIALECTS.containsKey(dialect))
					curClient.dialect = DebuggerDialects.DIALECTS.get(dialect);
				else
					dialect = "unknown";

				rsplugin.cs.println(String.format("   dialect: %s", dialect));
				break;

			// debugger client disconnects
			case "dbg_quit":
				rsplugin.cs.println(String.format("[<] %s", (String) notice.get("msg")));
				rsplugin.provider.setClient("-");
				rsplugin.program = null;
				curClient = null;
				break;

			// debugger notice that its current module has changed
			case "module":
				rsplugin.syncEnabled = false;
				Path modpath = Paths.get((String) notice.get("path"));
				String modname = modpath.getFileName().toString();

				if (rsplugin.program != null) {
					if (rsplugin.program.getName().equalsIgnoreCase(modname)) {
						rsplugin.cs.println(String.format("[-] already enabled"));
						rsplugin.syncEnabled = true;
						break;
					}
				}

				// find program in list of open programs
				for (Program pgm : rsplugin.pm.getAllOpenPrograms()) {
					if (pgm.getName().equalsIgnoreCase(modname)) {
						rsplugin.pm.setCurrentProgram(pgm);
						rsplugin.syncEnabled = true;
						rsplugin.program = pgm;
						rsplugin.cs.println(String.format("[>] set current program: %s", pgm.getName()));
						rsplugin.provider.setProgram(pgm.getName());
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
			case "loc":
				if (rsplugin.program == null) {
					break;
				}

				if (!rsplugin.program.equals(rsplugin.pm.getCurrentProgram())) {
					rsplugin.pm.setCurrentProgram(rsplugin.program);
				}

				rsplugin.gotoLoc(base, offset);
				break;

			case "cmt":
				String cmt = (String) sync.get("msg");
				rsplugin.addCmt(base, offset, cmt);
				break;

			case "cmd":
				String cmdb64 = (String) sync.get("msg");
				String cmd = new String(Base64.getDecoder().decode(cmdb64.getBytes()));
				rsplugin.addCmt(base, offset, cmd);
				break;

			default:
				rsplugin.cs.println(String.format("[<] cmd not implemented: %s", type));
				break;
			}

			return bExit;
		}
	}
}
