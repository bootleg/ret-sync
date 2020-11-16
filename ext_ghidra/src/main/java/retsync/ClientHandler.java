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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.HashMap;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private RetSyncPlugin plugin;
    PrintWriter out;
    BufferedReader in;
    HashMap<String, String> dialect = null;
    Boolean isWinOS = false;

    public ClientHandler(RetSyncPlugin plugin, Socket socket) {
        clientSocket = socket;
        this.plugin = plugin;
    }

    @Override
    public void run() {
        boolean bExit = false;
        String inputLine;

        try {
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            while ((inputLine = in.readLine()) != null && !Thread.currentThread().isInterrupted()) {
                plugin.reqHandler.lock();
                bExit = plugin.reqHandler.parse(this, inputLine);
                plugin.reqHandler.unlock();

                if (bExit)
                    break;
            }

            in.close();
            out.close();
            plugin.cs.println("[>] handler exit");
            cleanup();
        } catch (IOException e) {
            plugin.cs.println(String.format("[!] handler error: %s", e.getMessage()));

            // debugger quit abruptly
            if (e.getMessage().equals("Connection reset")) {
                plugin.clrs.cbColorFinal();
            }
        } finally {
            plugin.clrs.stopEnhancedDecompHighlight();
            plugin.uiComponent.resetClient();
        }
    }

    public void cleanup() {
        plugin.clients.remove(clientSocket);
        plugin.program = null;
    }

    public void sendSimpleCmd(String cmd) {
        sendCmd(cmd, "");
    }

    public void sendCmd(String cmd, String args) {
        sendCmd(cmd, args, false);
    }

    public void sendCmd(String cmd, String args, boolean oneshot) {
        String cmd_op;

        if (dialect == null) {
            plugin.cs.println("[x] unknown dialect");
            return;
        }

        if (dialect.containsKey(cmd)) {
            cmd_op = dialect.get(cmd);

            if (!args.isEmpty())
                cmd_op = String.format("%s %s", cmd_op, args);

            if (oneshot && dialect.containsKey("oneshot_post"))
                cmd_op = String.format("%s%s", cmd_op, dialect.get("oneshot_post"));

            out.println(cmd_op);
        } else {
            plugin.cs.println("[x] unknown command");
        }
    }

    public void sendRawCmd(String cmd, String args) {
        String cmd_pre;

        if (dialect == null) {
            plugin.cs.println("[x] unknown dialect");
            return;
        }

        if (dialect.containsKey("prefix")) {
            cmd_pre = dialect.get("prefix");

            out.println(String.format("%s%s %s", cmd_pre, cmd, args));
        } else {
            plugin.cs.println("[x] raw command not supported");
        }
    }

    public void sendRaw(String msg) {
        out.println(msg);
    }

}
