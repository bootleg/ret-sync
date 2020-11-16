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



Part of the code from package ColorizingPlugin / ghidra.app.plugin.core.colorizer;

 * ### IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package retsync;

import java.awt.Color;
import java.io.IOException;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.LocationClangHighlightController;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.util.viewer.listingpanel.PropertyBasedBackgroundColorModel;
import ghidra.program.database.IntRangeMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class LocalColorizerService {
    private RetSyncPlugin rsplugin;
    private static Color SYNC_CURLINE = Color.YELLOW;
    private static Color SYNC_CBTRACE = Color.GREEN;
    private Boolean cbTraceEnabled = false;
    private Address cbPrevAddr = null;
    private Color cbrevColor = null;
    private DecompilerPanel dpanel = null;
    private Program program;

    LocalColorizerService(RetSyncPlugin plugin) {
        rsplugin = plugin;
    }

    void setPrevAddr(Address prev) {
        cbPrevAddr = prev;
    }

    void enableTrace() {
        cbTraceEnabled = true;
    }

    void disableTrace() {
        cbTraceEnabled = false;
    }

    void oneShotTrace() {
        cbrevColor = SYNC_CBTRACE;
    }

    void setTraceColor(int rgb) {
        Color new_col = new Color(rgb);
        SYNC_CBTRACE = new_col;
    }

    void setProgram(Program program) {
        this.program = program;
    }

    void cbColorPost() {
        cbrevColor = getBackgroundColor(cbPrevAddr);
        setColorTransaction(cbPrevAddr, SYNC_CURLINE);
    }

    void cbColorPre() {
        if (cbPrevAddr != null) {
            Color currentColor = getBackgroundColor(cbPrevAddr);

            // race condition: block/instruction's color may have been modified
            // by the user/other script after it was saved
            if (currentColor != null) {
                if (!currentColor.equals(cbrevColor) && !currentColor.equals(SYNC_CURLINE)) {
                    cbrevColor = currentColor;
                }
            }

            // if tracing is enable, force color
            if (cbTraceEnabled) {
                cbrevColor = SYNC_CBTRACE;
            }

            setColorTransaction(cbPrevAddr, cbrevColor);
        }
    }

    void cbColorFinal() {
        cbColorFinal(rsplugin.program);
    }

    void cbColorFinal(Program pgm) {
        setProgram(pgm);
        cbTraceEnabled = false;

        if (program != null) {
            program.flushEvents();
            cbColorPre();

            try {
                program.save("commit-cb-final", TaskMonitor.DUMMY);
            } catch (CancelledException | IOException e) {
                rsplugin.cs.println(String.format("[x] program.save exception: %s", e.getMessage()));
            }

            program.flushEvents();
            program = null;
        }
    }

    private void setColorTransaction(Address target, Color color) {
        if (program != null) {
            int transactionID = program.startTransaction("sync-bckgrnd-color");
            try {
                if (color != null) {
                    setBackgroundColor(target, target, color);
                } else {
                    clearBackgroundColor(target, target);
                }

            } finally {
                program.endTransaction(transactionID, true);
            }
        }
    }

    /*
     ***************************************************************************
     *
     * Code below from package ColorizingPlugin / ghidra.app.plugin.core.colorizer;
     *
     * ColorizingService relies upon PluginEvents to manage its internal target
     * program. If call from another's plugin PluginEvent handler, the value of
     * target program may be null and methods like clearBackgroundColor ineffective.
     *
     ***************************************************************************
     */

    private Color getBackgroundColor(Address address) {
        IntRangeMap map = getColorRangeMap(false);
        if (map != null) {
            Integer value = map.getValue(address);
            if (value != null) {
                return new Color(value, true);
            }
        }
        return null;
    }

    private void setBackgroundColor(Address min, Address max, Color c) {
        IntRangeMap map = getColorRangeMap(true);
        if (map != null) {
            map.setValue(min, max, c.getRGB());
        }
    }

    private void clearBackgroundColor(Address min, Address max) {
        IntRangeMap map = getColorRangeMap(false);
        if (map != null) {
            map.clearValue(min, max);
        }
    }

    private IntRangeMap getColorRangeMap(boolean create) {
        if (program == null) {
            return null;
        }

        IntRangeMap map = program.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
        if (map == null && create) {
            try {
                map = program.createIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
            } catch (DuplicateNameException e) {
                // can't happen since we just checked for it!
            }
        }
        return map;
    }

    /*
     ***************************************************************************
     *
     * Decompiler highlight enhancement option: full line instead of token based
     * highlighting can be disable in configuration file: enhanced_highlight option
     * of the GHIDRA section
     *
     ***************************************************************************
     */

    private void getDecompilerPanel() {
        DecompilerProvider dprov = null;
        DecompilerActionContext context = null;

        dprov = (DecompilerProvider) rsplugin.getTool().getComponentProvider("Decompiler");
        if (dprov != null) {
            context = (DecompilerActionContext) dprov.getActionContext(null);
            if (context != null) {
                dpanel = context.getDecompilerPanel();
            }
        }
    }

    // set up FullLineLocationClangHighlightController (full line highlight)
    protected void startEnhancedDecompHighlight() {
        if (!rsplugin.bUseEnhancedHighlight)
            return;

        if (dpanel == null) {
            getDecompilerPanel();

            if (dpanel != null) {
                FullLineLocationClangHighlightController highlightController;
                highlightController = new FullLineLocationClangHighlightController();
                dpanel.setHighlightController(highlightController);
            }
        }
    }

    // restore LocationClangHighlightController (token highlight)
    protected void stopEnhancedDecompHighlight() {
        if (!rsplugin.bUseEnhancedHighlight)
            return;

        if (dpanel != null) {
            LocationClangHighlightController highlightController = new LocationClangHighlightController();
            dpanel.setHighlightController(highlightController);
            dpanel = null;
        }
    }

    private class FullLineLocationClangHighlightController extends LocationClangHighlightController {

        @Override
        public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {

            clearPrimaryHighlights();

            if (!(field instanceof ClangTextField)) {
                return;
            }

            ClangToken loctok = ((ClangTextField) field).getToken(location);
            if (loctok == null) {
                return;
            }

            if (trigger == EventTrigger.GUI_ACTION) {
                addTokenPrimaryHighlight(loctok);
            } else {
                ClangLine cline = loctok.getLineParent();
                if (cline != null) {
                    cline.getAllTokens().forEach((tok) -> {
                        addTokenPrimaryHighlight(tok);
                    });
                }
            }
        }

        private void addTokenPrimaryHighlight(ClangToken token) {
            addPrimaryHighlight(token, defaultHighlightColor);
            if (token instanceof ClangSyntaxToken) {
                addPrimaryHighlightToTokensForParenthesis((ClangSyntaxToken) token, defaultParenColor);
                addHighlightBrace((ClangSyntaxToken) token, defaultParenColor);
            }
        }
    }

}
