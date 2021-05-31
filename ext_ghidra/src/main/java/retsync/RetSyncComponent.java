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

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

import org.apache.commons.io.FilenameUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import resources.Icons;
import resources.ResourceManager;

public class RetSyncComponent extends ComponentProvider {
    private static final Boolean bDebugAction = false;
    private RetSyncPlugin rsplugin;

    private JPanel panel;
    private JLabel statusArea;
    private JLabel clientArea;
    private JLabel programArea;

    private DockingAction action_enable;
    private DockingAction action_disable;
    private DockingAction action_refresh;

    private NavigatableContextAction action_trace;
    private NavigatableContextAction action_step;
    private NavigatableContextAction action_go;
    private NavigatableContextAction action_run;
    private NavigatableContextAction action_bp;
    private NavigatableContextAction action_bp1;
    private NavigatableContextAction action_hbp;
    private NavigatableContextAction action_hbp1;
    private NavigatableContextAction action_translate;
    private NavigatableContextAction action_reload_conf;

    private static final Color COLOR_CONNECTED = new Color(0, 153, 0);

    private class Status {
        public static final String IDLE = "idle";
        public static final String ENABLED = "listening";
        public static final String RUNNING = "connected";
    }

    public RetSyncComponent(Plugin plugin, String owner) {
        super(plugin.getTool(), owner, owner);
        rsplugin = (RetSyncPlugin) plugin;
        createActions();
        buildPanel();
        resetStatus();
        setVisible(true);
        setIcon(ResourceManager.loadImage("images/face-monkey.png"));
    }

    private void buildPanel() {
        GridBagLayout grid = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        panel = new JPanel(grid);

        gbc.insets = new Insets(2, 8, 2, 8);
        gbc.gridx = 0;
        gbc.anchor = GridBagConstraints.SOUTHEAST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;

        Icon BROWSER_ICON = ResourceManager.loadImage("images/browser.png");
        statusArea = new JLabel(BROWSER_ICON, SwingConstants.LEFT);
        panel.add(statusArea, gbc);

        Icon MEMORY_ICON = ResourceManager.loadImage("images/memory16.gif");
        clientArea = new JLabel(MEMORY_ICON, SwingConstants.LEFT);
        panel.add(clientArea, gbc);

        Icon CODE_ICON = ResourceManager.loadImage("images/viewedCode.gif");
        programArea = new JLabel(CODE_ICON, SwingConstants.LEFT);
        panel.add(programArea, gbc);
    }

    private NavigatableContextAction codeViewerActionFactory(String name, String cmd, KeyBindingData keyBinding) {
        NavigatableContextAction action;

        action = new NavigatableContextAction(name, getName()) {
            @Override
            public void actionPerformed(NavigatableActionContext context) {
                if (bDebugAction) {
                    rsplugin.cs.println(String.format("[>] %s", this.getFullName()));
                }

                if (!rsplugin.syncEnabled) {
                    rsplugin.cs.println(String.format("[sync] %s, sync not enabled", this.getName()));
                    return;
                }

                rsplugin.reqHandler.curClient.sendSimpleCmd(cmd);
            }
        };

        action.setEnabled(true);
        action.setKeyBindingData(keyBinding);
        action.setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, action.getName()));
        return action;
    }

    private NavigatableContextAction codeViewerActionFactory(String name, String cmd, int key) {
        return codeViewerActionFactory(name, cmd, new KeyBindingData(key, 0));
    }

    private NavigatableContextAction breakPointActionFactory(String name, String cmd, boolean oneshot,
            KeyBindingData keyBinding) {
        NavigatableContextAction breakpoint_action;
        breakpoint_action = new NavigatableContextAction(name, getName()) {
            @Override
            public void actionPerformed(NavigatableActionContext context) {
                rsplugin.cs.println(String.format("[>] %s", this.getName()));

                if (rsplugin.syncEnabled) {
                    ProgramLocation loc = rsplugin.cvs.getCurrentLocation();
                    Program pgm = loc.getProgram();

                    if (rsplugin.isRemoteBaseKnown()) {
                        Address dest = rsplugin.rebaseRemote(loc.getAddress());
                        rsplugin.reqHandler.curClient.sendCmd(cmd, String.format("0x%x", dest.getOffset()), oneshot);
                        rsplugin.cs.println(String.format("    local addr: %s, remote: 0x%x",
                                loc.getAddress().toString(), dest.getOffset()));
                    } else {
                        rsplugin.cs.println(
                                String.format("[x] %s failed, remote base of %s program unknown", cmd, pgm.getName()));
                    }
                }
            }
        };

        breakpoint_action.setEnabled(true);
        breakpoint_action.setKeyBindingData(keyBinding);
        breakpoint_action.setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, breakpoint_action.getName()));
        return breakpoint_action;
    }

    private void createActions() {
        action_enable = new DockingAction("ret-sync enable", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                rsplugin.cs.println(String.format("[>] %s", this.getName()));

                if (rsplugin.server == null) {
                    rsplugin.serverStart();
                } else {
                    rsplugin.cs.println("[>] server already started");
                }
            }
        };

        action_disable = new DockingAction("ret-sync disable", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                rsplugin.cs.println(String.format("[>] %s", this.getName()));
                rsplugin.serverStop();
            }
        };

        action_refresh = new DockingAction("ret-sync restart", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                rsplugin.cs.println(String.format("[>] %s", this.getName()));
                rsplugin.serverStop();
                rsplugin.serverStart();
            }
        };

        action_enable.setEnabled(true);
        action_enable.setDescription("Start listener");
        action_enable.setKeyBindingData(new KeyBindingData(KeyEvent.VK_S, InputEvent.ALT_DOWN_MASK));
        action_enable.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
        dockingTool.addAction(action_enable);

        action_disable.setEnabled(true);
        action_disable.setDescription("Stop listener");
        action_disable.setKeyBindingData(
                new KeyBindingData(KeyEvent.VK_S, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK));
        action_disable.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
        dockingTool.addAction(action_disable);

        action_refresh.setEnabled(true);
        action_refresh.setDescription("Restart listener");
        action_refresh.setKeyBindingData(new KeyBindingData(KeyEvent.VK_R, InputEvent.ALT_DOWN_MASK));
        action_refresh.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        dockingTool.addAction(action_refresh);

        action_translate = new NavigatableContextAction("ret-sync translate", getName()) {
            @Override
            public void actionPerformed(NavigatableActionContext context) {
                rsplugin.cs.println(String.format("[>] %s", this.getName()));

                if (rsplugin.syncEnabled) {
                    ProgramLocation loc = rsplugin.cvs.getCurrentLocation();
                    Program pgm = loc.getProgram();
                    String args = String.format("%s %s %s", pgm.getImageBase(), loc.getAddress(),
                            FilenameUtils.removeExtension(pgm.getName()));

                    rsplugin.cs.println(String.format("    local addr: %s@%s", pgm.getName(), loc.getAddress()));
                    rsplugin.reqHandler.curClient.sendRawCmd("translate ", args);
                } else {
                    rsplugin.cs.println("[x] translate failed, syncing not enabled");
                }
            }
        };

        action_reload_conf = new NavigatableContextAction("ret-sync reload conf", getName()) {
            @Override
            public void actionPerformed(NavigatableActionContext context) {
                rsplugin.cs.println(String.format("[>] %s", this.getName()));
                rsplugin.defaultConfiguration();
                rsplugin.loadConfiguration();
            }
        };

        action_step = codeViewerActionFactory("ret-sync-step", "so", KeyEvent.VK_F10);
        action_step.setDescription("Single-step program");
        dockingTool.addAction(action_step);

        action_trace = codeViewerActionFactory("ret-sync-trace", "si", KeyEvent.VK_F11);
        action_trace.setDescription("Single-trace program");
        dockingTool.addAction(action_trace);

        action_go = codeViewerActionFactory("ret-sync-go", "go", KeyEvent.VK_F5);
        action_go.setDescription("Run program");
        dockingTool.addAction(action_go);

        action_run = codeViewerActionFactory("ret-sync-run", "run", new KeyBindingData(KeyEvent.VK_F5, InputEvent.ALT_DOWN_MASK));
        action_run.setDescription("Run program (gdb run)");
        dockingTool.addAction(action_run);

        action_bp = breakPointActionFactory("ret-sync-bp", "bp", false, new KeyBindingData(KeyEvent.VK_F2, 0));
        action_bp.setDescription("Set breakpoint");
        dockingTool.addAction(action_bp);

        action_hbp = breakPointActionFactory("ret-sync-hbp", "hbp", false,
                new KeyBindingData(KeyEvent.VK_F2, InputEvent.CTRL_DOWN_MASK));
        action_hbp.setDescription("Set hardware breakpoint");
        dockingTool.addAction(action_hbp);

        action_bp1 = breakPointActionFactory("ret-sync-bp1", "bp1", true,
                new KeyBindingData(KeyEvent.VK_F3, InputEvent.ALT_DOWN_MASK));
        action_bp1.setDescription("Set one-shot hardware breakpoint");
        dockingTool.addAction(action_bp1);

        action_hbp1 = breakPointActionFactory("ret-sync-hbp1", "hbp1", true,
                new KeyBindingData(KeyEvent.VK_F3, InputEvent.CTRL_DOWN_MASK));
        action_hbp1.setDescription("Set one-shot hardware breakpoint");
        dockingTool.addAction(action_hbp1);

        action_translate.setEnabled(true);
        action_translate.markHelpUnnecessary();
        action_translate.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F2, InputEvent.ALT_DOWN_MASK));
        dockingTool.addAction(action_translate);

        action_reload_conf.setEnabled(true);
        action_reload_conf.markHelpUnnecessary();
        action_reload_conf.setKeyBindingData(
                new KeyBindingData(KeyEvent.VK_R, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK));
        dockingTool.addAction(action_reload_conf);

    }

    public void resetStatus() {
        setStatus(Status.IDLE);
        setProgram("n/a");
        setClient("n/a");
    }

    public void resetClient() {
        setStatus(Status.ENABLED);
        setProgram("n/a");
        setClient("n/a");
    }

    public void setConnected(String dialect) {
        setStatus(Status.RUNNING);
        setClient(dialect);
    }

    public void setClient(String client) {
        clientArea.setText(String.format("Client debugger: %s", client));
    }

    public void setProgram(String pgm) {
        programArea.setText(String.format("Client program: %s", pgm));
    }

    public void setStatus(String status) {
        statusArea.setText(String.format("Status: %s", status));
        switch (status) {
        case Status.IDLE:
            statusArea.setForeground(Color.BLACK);
            break;
        case Status.ENABLED:
            statusArea.setForeground(Color.BLUE);
            break;
        case Status.RUNNING:
            statusArea.setForeground(COLOR_CONNECTED);
            break;
        }
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
