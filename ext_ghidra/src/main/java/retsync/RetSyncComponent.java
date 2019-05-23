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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import org.apache.commons.io.FilenameUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.app.plugin.core.codebrowser.actions.CodeViewerContextAction;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import resources.Icons;
import retsync.RetSyncPlugin.Status;

public class RetSyncComponent extends ComponentProvider {
	private RetSyncPlugin rsplugin;
	private JPanel panel;
	private JTextArea statusArea;
	private JTextArea clientArea;
	private JTextArea programArea;
	private DockingAction action_enable;
	private DockingAction action_disable;
	private DockingAction action_refresh;
	private CodeViewerContextAction action_trace;
	private CodeViewerContextAction action_step;
	private CodeViewerContextAction action_go;
	private CodeViewerContextAction action_breakpoint;
	private CodeViewerContextAction action_translate;

	public RetSyncComponent(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.rsplugin = (RetSyncPlugin) plugin;
		buildPanel();
		createActions();
	}

	private void buildPanel() {
		GridBagLayout grid = new GridBagLayout();
		GridBagConstraints gbc = new GridBagConstraints();
		panel = new JPanel(grid);

		gbc.gridx = 0;
		gbc.anchor = GridBagConstraints.SOUTHEAST;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.weightx = 1.0;
		gbc.gridwidth = 1;
		gbc.gridheight = 1;

		statusArea = new JTextArea();
		statusArea.setEditable(false);
		setStatus(Status.IDLE);
		panel.add(statusArea, gbc);

		clientArea = new JTextArea();
		clientArea.setEditable(false);
		setClient("-");
		panel.add(clientArea, gbc);

		programArea = new JTextArea();
		programArea.setEditable(false);
		setProgram("-");
		panel.add(programArea, gbc);

		setVisible(true);
	}

	private CodeViewerContextAction codeViewerActionFactory(String name, String cmd, int key) {
		CodeViewerContextAction action;

		action = new CodeViewerContextAction(name, getName(), true) {
			@Override
			public void actionPerformed(CodeViewerActionContext context) {
				rsplugin.cs.println(String.format("[>] %s", this.getFullName()));

				if (!rsplugin.syncEnabled) {
					rsplugin.cs.println("[sync] program not enabled");
					return;
				}

				rsplugin.reqHandler.curClient.sendSimpleCmd(cmd);
			}
		};

		action.setEnabled(true);
		action.setKeyBindingData(new KeyBindingData(key, 0));
		action.setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, action.getName()));
		return action;
	}

	private void createActions() {
		action_enable = new DockingAction("ret-sync enable", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				rsplugin.cs.println(String.format("[>] %s", this.getFullName()));

				if (rsplugin.server == null) {
					rsplugin.server = new ListenerBackground(rsplugin);
					new Thread(rsplugin.server).start();
					rsplugin.cs.println("[>] server started");
					setStatus(Status.ENABLED);
				} else {
					rsplugin.cs.println("[>] server already started");
				}
			}
		};

		action_disable = new DockingAction("ret-sync disable", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				rsplugin.cs.println(String.format("[>] %s", this.getFullName()));

				if (rsplugin.server == null) {
					rsplugin.cs.println("[>] server not started");
				} else {
					rsplugin.server.stop();
					rsplugin.cs.println("[>] server stopped");
					rsplugin.server = null;
					resetStatus();
				}
			}
		};

		action_refresh = new DockingAction("ret-sync restart", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				rsplugin.cs.println(String.format("[>] %s", this.getFullName()));

				if (rsplugin.server == null) {
					rsplugin.cs.println("[>] server not started");
				} else {
					rsplugin.server.stop();
					resetStatus();

					rsplugin.server = new ListenerBackground(rsplugin);
					new Thread(rsplugin.server).start();
					rsplugin.cs.println("[>] server started");
				}
			}
		};

		action_enable.setEnabled(true);
		action_enable.setDescription("Start listener");
		action_enable.setKeyBindingData(new KeyBindingData(KeyEvent.VK_S, InputEvent.ALT_DOWN_MASK));
		action_enable.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		dockingTool.addAction(action_enable);

		action_disable.setEnabled(true);
		action_disable.setDescription("Stop listener");
		action_disable.setKeyBindingData(new KeyBindingData(KeyEvent.VK_U, InputEvent.ALT_DOWN_MASK));
		action_disable.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
		dockingTool.addAction(action_disable);

		action_refresh.setEnabled(true);
		action_refresh.setDescription("Restart listener");
		action_refresh.setKeyBindingData(new KeyBindingData(KeyEvent.VK_R, InputEvent.ALT_DOWN_MASK));
		action_refresh.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		dockingTool.addAction(action_refresh);

		action_breakpoint = new CodeViewerContextAction("ret-sync bp", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				rsplugin.cs.println(String.format("[>] %s", this.getFullName()));

				if (rsplugin.syncEnabled) {
					ProgramLocation loc = rsplugin.cvs.getCurrentLocation();
					Address dest = rsplugin.rebase_remote(loc.getAddress());
					rsplugin.reqHandler.curClient.sendCmd("bp", dest.toString());
					rsplugin.cs.println(String.format("    local addr: %s, remote %s", loc.getAddress().toString(),
							dest.toString()));
				}
			}
		};

		action_translate = new CodeViewerContextAction("ret-sync translate", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				rsplugin.cs.println(String.format("[>] %s", this.getFullName()));

				if (rsplugin.syncEnabled) {
					ProgramLocation loc = rsplugin.cvs.getCurrentLocation();
					Address dest = rsplugin.rebase_remote(loc.getAddress());

					String args = String.format("%s %s %s", rsplugin.imageBase.toString(), dest.toString(),
							FilenameUtils.removeExtension(rsplugin.program.getName()));
					rsplugin.reqHandler.curClient.sendRawCmd("translate ", args);
				}
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

		action_breakpoint.setEnabled(true);
		action_breakpoint.markHelpUnnecessary();
		action_breakpoint.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F2, 0));
		dockingTool.addAction(action_breakpoint);

		action_translate.setEnabled(true);
		action_translate.markHelpUnnecessary();
		action_translate.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F2, InputEvent.ALT_DOWN_MASK));
		dockingTool.addAction(action_translate);
	}

	public void resetStatus() {
		setStatus(Status.IDLE);
		setProgram("-");
		setClient("-");
	}

	public void resetClient() {
		setStatus(Status.ENABLED);
		setProgram("-");
		setClient("-");
	}

	public void setStatus(String status) {
		statusArea.setText(String.format("status: %s", status));
	}

	public void setClient(String client) {
		clientArea.setText(String.format("client debugger: %s", client));
	}

	public void setProgram(String pgm) {
		programArea.setText(String.format("client program: %s", pgm));
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
