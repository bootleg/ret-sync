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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ListenerBackground implements Runnable {
    private RetSyncPlugin plugin;
    private ServerSocket serverSocket;
    private ExecutorService pool;

    public ListenerBackground(RetSyncPlugin plugin) {
        this.plugin = plugin;
        pool = Executors.newFixedThreadPool(1);
    }

    public void bind() throws IOException {
        InetAddress byAddress = InetAddress.getByName(plugin.SYNC_HOST);
        serverSocket = new ServerSocket(plugin.SYNC_PORT, 0, byAddress);
        plugin.cs.println("[>] server listening ");
    }

    @Override
    public void run() {
        try {
            while (true) {
                Socket client = serverSocket.accept();
                plugin.clients.add(client);
                pool.execute(new ClientHandler(plugin, client));
            }
        } catch (IOException e) {
            plugin.cs.println(String.format("[!] server exception: %s", e.getMessage()));
        }
    }

    public void stop() {
        for (Socket client : plugin.clients) {
            try {
                client.close();
            } catch (IOException e) {
                plugin.cs.println(String.format("[!] close client socket: %s", e.getMessage()));
            }
        }

        pool.shutdown();

        try {
            if (!pool.awaitTermination(100, TimeUnit.MILLISECONDS)) {
                pool.shutdownNow();
                if (!pool.awaitTermination(100, TimeUnit.MILLISECONDS)) {
                    plugin.cs.println("[>] pool did not terminate");
                }
            }
        } catch (InterruptedException ie) {
            pool.shutdownNow();
            Thread.currentThread().interrupt();
        }

        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                plugin.cs.println(String.format("[>] server shutdown: %s", e.getMessage()));
            }
        }

    }
}
