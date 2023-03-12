package ghidra.apollo;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = MiscellaneousPluginPackage.NAME,
    category = PluginCategoryNames.MISC,
    shortDescription = "Apollo Support",
    description = "Apollo Domain/OS binary support",
    servicesRequired = { GoToService.class, ProgramManager.class},
    eventsProduced = { ProgramLocationPluginEvent.class },
    eventsConsumed = { ProgramClosedPluginEvent.class}
    )
//@formatter:on

public class ApolloPlugin extends ProgramPlugin {
	public ApolloPlugin(PluginTool plugintool) {
		super(plugintool);
		// TODO Auto-generated constructor stub
	}
}
